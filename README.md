# te-runner

The one Docker image TE 2.0 labs reference (`te-labkit-v2/PRD.md` rock 2).
Carries `wizlab` (`/usr/local/bin/wizlab`), the measured-facts catalog
(`/opt/te/measurements.yaml`), AWS CLI v2, Terraform 1.9.8, python 3.12, jq.

Build: CI only — push a `v*` tag to the **`personal`** remote (`eh24905-wiz`),
whose Actions publish the **public** `ghcr.io/eh24905-wiz/te-runner:<tag>` that
labs pin (Instruqt pulls anonymously). A tag on `origin` (wiz-training) builds a
**private** org package labs can't pull — `manifest unknown`/401. Never `latest`.

`wizlab` exit codes: 0 satisfied · 1 not satisfied · 2 invocation · 3
environment. In learner checks, remap 2/3 to 1 (out-of-list codes brick the
session — probe finding 2026-08-28); consume them raw in CI.

Next actions: measure the post-role connector `healthy` enum on a live lease
(TODO in `wizlab/wizlab`); add gcloud/az when pilot 2 needs them.
