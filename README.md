# PG Atlas SBOM demo: go

Phase 1 baseline for [D1](https://github.com/SCF-Public-Goods-Maintenance/pg-atlas-sbom-action/issues/10).
This is an unpublished test repository and must stay unattached to an Atlas project.

## Expected dependencies

- nebu: `pkg:golang/github.com/withObsrvr/nebu@v0.7.2` → `pkg:github/withObsrvr/nebu`
- UUID control: `pkg:golang/github.com/google/uuid@v1.6.0` → control (SBOM assertion only)

## Baseline procedure

Enable GitHub Dependency graph; leave Automatic dependency submission disabled.
The workflow resolves/builds the fixture, then runs the pinned, unchanged PG Atlas Action with read access and OIDC. No precursor submission action is installed.
The checker verifies package identities, versions, and paths from the root.
The workflow captures SBOM/submission evidence correlated by Atlas semantic hash and distinguishes missing coverage (exit 1), errors (exit 2), and pending processing after bounded polling (exit 0 with `status: pending-timeout` and `verification_complete: false`). Exit 3 is reserved for submission-record lookup timing out.

Some toolchains are only installed on CI. Initial fixture setup runs export generated lockfiles as `fixture-locks` artifacts. Commit those files and rerun before classifying the definitive baseline: GitHub exports the committed tree, not the runner filesystem. A pre-lock setup run cannot establish a package-manager coverage failure.

Atlas processing may take hours. Run `verify-atlas.yml` manually with the recorded submission ID at the same fixture revision after processing. It only reads production API data. Preserve artifact/run links in the Phase 1 report. Artifacts expire after 30 days.

## Local check commands

```sh
python3 -m unittest -v
python3 check.py sbom --sbom /path/to/export.spdx.json
python3 check.py atlas --submission-id SUBMISSION_ID
```

The resolver/build commands are in `.github/workflows/baseline.yml`. An export or build error is reported separately from an omitted expected package. Successful package presence does not establish full transitive graph fidelity; only explicitly configured relationship assertions test that.

## Waiting for Atlas processing

The checker now polls the submission status every 15 seconds for up to five minutes before checking dependency relationships. A processed submission is checked immediately; a processing error or missing relationship still fails.

If the budget expires while the submission is pending, the result is `pending-timeout` with `verification_complete: false`. This keeps the workflow from failing solely because a worker has not run, but it is **not** a verified coverage pass. Run `verify-atlas.yml` with the recorded submission ID later. Its result and the baseline together form the evidence.

Override the polling budget with `--processing-wait-seconds` and `--poll-interval`. Submission-record lookup has its own 90-second budget. API errors remain errors rather than being reported as pending.

Repository settings should stay at their defaults unless a baseline demonstrates a necessary change. Gradle needs automatic dependency submission, enabled by Alex. Do not enable it in the other demos just to match Gradle. Alex owns backend dependency-link corrections; these demos provide evidence and verification.
