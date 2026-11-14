import copy
import unittest
from unittest.mock import patch
from check import assert_sbom, atlas_result, semantic_hash, wait_for_processing


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.expected = {"repository": "pgm-testing/sbom-demo-python", "probes": [
            {"name": "probe", "purl": "pkg:pypi/stellar-sdk", "version": "17.0.1",
             "repo": "pkg:github/StellarCN/py-stellar-base"}]}
        self.doc = {"packages": [
            {"SPDXID": "root", "externalRefs": [{"referenceType": "purl",
              "referenceLocator": "pkg:github/pgm-testing/sbom-demo-python"}]},
            {"SPDXID": "dep", "versionInfo": "17.0.1", "externalRefs": [
             {"referenceType": "purl", "referenceLocator": "pkg:pypi/stellar-sdk@17.0.1"}]}],
            "relationships": [{"spdxElementId": "root", "relationshipType": "DEPENDS_ON",
                               "relatedSpdxElement": "dep"}]}

    def test_complete_document_passes(self):
        self.assertTrue(assert_sbom({"sbom": self.doc}, self.expected)["pass"])

    def test_root_only_fails(self):
        self.doc["packages"] = self.doc["packages"][:1]
        self.assertFalse(assert_sbom(self.doc, self.expected)["pass"])

    def test_wrong_version_fails(self):
        self.doc["packages"][1]["externalRefs"][0]["referenceLocator"] = "pkg:pypi/stellar-sdk@16.0.0"
        self.doc["packages"][1]["versionInfo"] = "16.0.0"
        self.assertFalse(assert_sbom(self.doc, self.expected)["pass"])

    def test_unconnected_package_fails(self):
        self.doc["relationships"] = []
        self.assertFalse(assert_sbom(self.doc, self.expected)["pass"])

    def test_transitive_path_passes(self):
        self.doc["relationships"] = [
            {"spdxElementId": "root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "middle"},
            {"spdxElementId": "middle", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "dep"}]
        self.assertTrue(assert_sbom(self.doc, self.expected)["pass"])

    def test_pending_is_not_coverage_failure(self):
        result, code = atlas_result({"id": 1, "repository_claim": "pgm-testing/sbom-demo-python",
                                     "status": "pending"}, self.expected)
        self.assertEqual(code, 3)
        self.assertEqual(result["status"], "pending")

    def test_wrong_repository_rejected(self):
        with self.assertRaises(ValueError):
            atlas_result({"id": 1, "repository_claim": "other/repo", "status": "processed"}, self.expected)

    @patch("check.get")
    def test_processed_missing_edge_fails(self, fetch):
        fetch.side_effect = [{"project_id": None}, []]
        self.assertEqual(atlas_result({"id": 1, "repository_claim": "pgm-testing/sbom-demo-python",
                         "status": "processed"}, self.expected)[1], 1)

    @patch("check.get")
    def test_processed_expected_edge_passes(self, fetch):
        fetch.side_effect = [{"project_id": None},
            [{"canonical_id": "pkg:github/StellarCN/py-stellar-base"}]]
        self.assertEqual(atlas_result({"id": 1, "repository_claim": "pgm-testing/sbom-demo-python",
                         "status": "processed"}, self.expected)[1], 0)


    def test_flattened_transitive_relationship_fails(self):
        self.expected["relationship_checks"] = [{"parent_purl": "pkg:pypi/requests",
            "child_purl": "pkg:pypi/stellar-sdk", "direct_from_root": False}]
        self.doc["packages"].append({"SPDXID": "parent", "externalRefs": [
            {"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.0"}]})
        self.assertFalse(assert_sbom(self.doc, self.expected)["pass"])

    def test_preserved_transitive_relationship_passes(self):
        self.expected["relationship_checks"] = [{"parent_purl": "pkg:pypi/requests",
            "child_purl": "pkg:pypi/stellar-sdk", "direct_from_root": False}]
        self.doc["packages"].append({"SPDXID": "parent", "externalRefs": [
            {"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.0"}]})
        self.doc["relationships"] = [
            {"spdxElementId": "root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "parent"},
            {"spdxElementId": "parent", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "dep"}]
        self.assertTrue(assert_sbom(self.doc, self.expected)["pass"])


    def test_semantic_hash_ignores_export_metadata_and_order(self):
        other = copy.deepcopy(self.doc)
        other["creationInfo"] = {"created": "2099-01-01T00:00:00Z"}
        other["documentNamespace"] = "different-export"
        other["packages"].reverse()
        self.assertEqual(semantic_hash(self.doc), semantic_hash(other))

    def test_semantic_hash_preserves_relationship_changes(self):
        other = copy.deepcopy(self.doc)
        other["relationships"] = []
        self.assertNotEqual(semantic_hash(self.doc), semantic_hash(other))


    def test_processing_polls_until_processed(self):
        clock = [0]
        states = iter([{"id": 9, "repository_claim": self.expected["repository"], "status": "pending"},
                       {"id": 9, "repository_claim": self.expected["repository"], "status": "processed"}])
        def fetch(_): return next(states)
        def sleep(seconds): clock[0] += seconds
        with patch("check.get", side_effect=[{"project_id": None}, [{"canonical_id": self.expected["probes"][0]["repo"]}]]):
            result, code = wait_for_processing(9, self.expected, 30, 15,
                fetch=fetch, clock=lambda: clock[0], sleep=sleep)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["poll_attempts"], 2)
        self.assertTrue(result["verification_complete"])

    def test_processing_timeout_is_pending_not_pass_or_failure(self):
        clock = [0]
        submission = {"id": 9, "repository_claim": self.expected["repository"], "status": "pending"}
        def sleep(seconds): clock[0] += seconds
        result, code = wait_for_processing(9, self.expected, 30, 15,
            fetch=lambda _: submission, clock=lambda: clock[0], sleep=sleep)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "pending-timeout")
        self.assertFalse(result["verification_complete"])
        self.assertEqual(result["waited_seconds"], 30)

    def test_failed_processing_remains_error(self):
        submission = {"id": 9, "repository_claim": self.expected["repository"], "status": "failed", "error_detail": "bad payload"}
        result, code = wait_for_processing(9, self.expected, 30, 15, fetch=lambda _: submission)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "failed")

    def test_processed_missing_relationship_remains_failure(self):
        submission = {"id": 9, "repository_claim": self.expected["repository"], "status": "processed"}
        with patch("check.get", side_effect=[{"project_id": None}, []]):
            result, code = wait_for_processing(9, self.expected, 30, 15, fetch=lambda _: submission)
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "coverage-failure")


class GoRetestAssertions(unittest.TestCase):
    """Check the real Go expectations against representative API responses."""

    def setUp(self):
        from pathlib import Path
        import json
        self.expected = json.loads(Path("expected.json").read_text())
        self.submission = {"id": 2424, "repository_claim": self.expected["repository"], "status": "processed"}
        self.edges = [dict(item) for item in self.expected["atlas_checks"]]

    def result(self):
        with patch("check.get", side_effect=[{"project_id": None}, self.edges]):
            return atlas_result(self.submission, self.expected)

    def test_correct_repo_versions_and_external_control_pass(self):
        self.assertEqual(self.result()[1], 0)

    def test_nebu_still_external_fails(self):
        self.edges[0].update(canonical_id="pkg:golang/github.com/withobsrvr/nebu", vertex_type="external-repo")
        self.assertEqual(self.result()[1], 1)

    def test_wrong_version_fails(self):
        self.edges[0]["version_range"] = "v0.7.1"
        self.assertEqual(self.result()[1], 1)

    def test_missing_control_fails(self):
        self.edges.pop()
        self.assertEqual(self.result()[1], 1)

    def test_control_promoted_to_repo_fails(self):
        self.edges[1]["vertex_type"] = "repo"
        self.assertEqual(self.result()[1], 1)

    def test_duplicate_edge_fails(self):
        self.edges.append(dict(self.edges[0]))
        self.assertEqual(self.result()[1], 1)

    def test_exact_repo_casing_required(self):
        self.edges[0]["canonical_id"] = self.edges[0]["canonical_id"].lower()
        self.assertEqual(self.result()[1], 1)


if __name__ == "__main__":
    unittest.main()
