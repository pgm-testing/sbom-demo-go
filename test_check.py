import copy
import unittest
from unittest.mock import patch
from check import assert_sbom, atlas_result, semantic_hash


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


if __name__ == "__main__":
    unittest.main()
