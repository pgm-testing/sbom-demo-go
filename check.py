"""Read-only coverage checks. Exit: 0 pass, 1 coverage failure, 2 error, 3 pending."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://api.pgatlas.xyz"


def document(raw):
    return raw.get("sbom", raw)


def package_identity(locator):
    value = urllib.parse.unquote(locator).split("?", 1)[0].split("#", 1)[0]
    if "@" in value:
        return value.rsplit("@", 1)
    return value, None


def assert_sbom(raw, expected):
    doc = document(raw)
    packages = doc.get("packages", [])
    roots = set()
    graph = {}
    for rel in doc.get("relationships", []):
        if rel.get("relationshipType") == "DESCRIBES":
            roots.add(rel["relatedSpdxElement"])
        if rel.get("relationshipType") == "DEPENDS_ON":
            graph.setdefault(rel["spdxElementId"], set()).add(rel["relatedSpdxElement"])
    for pkg in packages:
        for ref in pkg.get("externalRefs", []):
            identity, _ = package_identity(ref.get("referenceLocator", ""))
            if identity.lower() == ("pkg:github/" + expected["repository"]).lower():
                roots.add(pkg["SPDXID"])
    reachable = set(roots)
    frontier = list(roots)
    while frontier:
        for target in graph.get(frontier.pop(), set()) - reachable:
            reachable.add(target)
            frontier.append(target)
    results = []
    for probe in expected["probes"]:
        matches = []
        for pkg in packages:
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType", "").lower() != "purl":
                    continue
                identity, purl_version = package_identity(ref.get("referenceLocator", ""))
                if identity.lower() == urllib.parse.unquote(probe["purl"]).lower():
                    matches.append({
                        "id": pkg.get("SPDXID"),
                        "version": purl_version or pkg.get("versionInfo"),
                    })
        correct = [m for m in matches if m["version"] == probe["version"]]
        linked = any(m["id"] in reachable - roots for m in correct)
        results.append({
            **probe, "observed": matches, "reachable_from_root": linked,
            "pass": bool(correct) and linked,
        })
    by_purl = {}
    for pkg in packages:
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType", "").lower() == "purl":
                identity, _ = package_identity(ref.get("referenceLocator", ""))
                by_purl.setdefault(identity.lower(), set()).add(pkg["SPDXID"])
    structure = []
    for check in expected.get("relationship_checks", []):
        parents = by_purl.get(check["parent_purl"].lower(), set())
        children = by_purl.get(check["child_purl"].lower(), set())
        parent_edge = any(child in graph.get(parent, set()) for parent in parents for child in children)
        root_edge = any(child in graph.get(root, set()) for root in roots for child in children)
        structure.append({**check, "parent_edge_present": parent_edge,
                          "root_edge_present": root_edge,
                          "pass": bool(children) and parent_edge and root_edge == check["direct_from_root"]})
    return {"stage": "sbom", "pass": bool(roots) and all(r["pass"] for r in results) and all(r["pass"] for r in structure),
            "root_ids": sorted(roots), "probes": results, "relationship_checks": structure}


def get(path):
    request = urllib.request.Request(BASE + path, headers={"User-Agent": "PG-Atlas-D1-ecosystem-demo"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def semantic_hash(raw):
    # Match Atlas's documented canonical fields; ignore export timestamps/namespace.
    doc = document(raw)
    canonical = {"name": doc.get("name"),
        "packages": sorted(doc["packages"], key=lambda p: p["SPDXID"]),
        "relationships": sorted(doc.get("relationships", []),
            key=lambda r: (r["spdxElementId"], r["relatedSpdxElement"], r["relationshipType"]))}
    return hashlib.sha256(json.dumps(canonical, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode()).hexdigest()


def find_submission(raw, expected):
    # Match Atlas semantic content hash, including dependencies and relationships.
    expected_hash = semantic_hash(raw)
    query = urllib.parse.urlencode({"repository": expected["repository"], "limit": 50})
    listing = get("/ingest/sbom?" + query)
    for item in sorted(listing["items"], key=lambda x: x["id"], reverse=True):
        if item.get("sbom_content_hash") == expected_hash:
            detail = get("/ingest/sbom/" + str(item["id"]))
            if detail["repository_claim"].lower() == expected["repository"].lower():
                return detail
    return None


def atlas_result(submission, expected):
    if submission["repository_claim"].lower() != expected["repository"].lower():
        raise ValueError("Submission belongs to a different repository")
    if submission["status"] != "processed":
        return {"stage": "atlas", "status": submission["status"],
                "submission_id": submission["id"], "error": submission.get("error_detail")}, (
                    2 if submission["status"] == "failed" else 3)
    canonical = "pkg:github/" + expected["repository"]
    detail = get("/repos/" + urllib.parse.quote(canonical, safe=""))
    if detail.get("project_id") is not None:
        raise ValueError("Demo unexpectedly belongs to an Atlas project")
    edges = get("/repos/" + urllib.parse.quote(canonical, safe="") + "/depends-on")
    observed = {edge["canonical_id"].lower() for edge in edges}
    probes = [{"name": p["name"], "expected_repo": p["repo"],
               "pass": p["repo"].lower() in observed}
              for p in expected["probes"] if p["repo"]]
    success = all(p["pass"] for p in probes)
    return {"stage": "atlas", "status": "pass" if success else "coverage-failure",
            "submission_id": submission["id"], "submission": submission,
            "edges": edges, "probes": probes}, 0 if success else 1


def save(name, value):
    path = Path("evidence")
    path.mkdir(exist_ok=True)
    (path / name).write_text(json.dumps(value, indent=2) + "\n")
    print(json.dumps(value, indent=2))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as output:
            output.write("### " + name + "\n\n")
            output.write("```json\n" + json.dumps(value, indent=2) + "\n```\n\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=["sbom", "submission", "atlas"])
    parser.add_argument("--sbom", default="sbom.spdx.json")
    parser.add_argument("--submission-id", type=int)
    parser.add_argument("--wait-seconds", type=int, default=90)
    args = parser.parse_args()
    expected = json.loads(Path("expected.json").read_text())
    try:
        if args.stage == "sbom":
            result = assert_sbom(json.loads(Path(args.sbom).read_text()), expected)
            code = 0 if result["pass"] else 1
        elif args.stage == "submission":
            raw = json.loads(Path(args.sbom).read_text())
            deadline = time.monotonic() + args.wait_seconds
            while True:
                submission = find_submission(raw, expected)
                if submission is not None:
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(min(10, max(0, deadline - time.monotonic())))
            if submission is None:
                result, code = {"stage": "submission", "status": "not-visible-before-timeout"}, 3
            else:
                Path("evidence").mkdir(exist_ok=True)
                Path("evidence/submission.json").write_text(json.dumps(submission, indent=2))
                result = {"stage": "submission", "status": submission["status"],
                          "submission_id": submission["id"]}
                code = 2 if submission["status"] == "failed" else 0
                if os.environ.get("GITHUB_OUTPUT"):
                    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
                        out.write("submission_id=" + str(submission["id"]) + "\n")
        else:
            if not args.submission_id or args.submission_id < 1:
                raise ValueError("A positive --submission-id is required")
            result, code = atlas_result(get("/ingest/sbom/" + str(args.submission_id)), expected)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result, code = {"stage": args.stage, "status": "error", "error": str(error)}, 2
    save(args.stage + "-result.json", result)
    return code


if __name__ == "__main__":
    sys.exit(main())
