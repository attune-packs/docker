# Source Verification

- Upstream: https://github.com/StackStorm-Exchange/stackstorm-docker
- Default branch: `master`
- Verified revision: `50cebd7f7d59272d09cd34261257327bff17f97e`
- Revision date: `2021-12-19T01:26:37-06:00`
- Revision description: `Use Github Actions instead of CirclecI`
- Latest tag: `v1.0.0`
- Tag revision: `46e507034e19164f83e7336993cca9ded9ea8de3`
- Upstream pack version: `1.0.0`
- License: Apache-2.0, verified from the upstream `LICENSE` and GitHub metadata

The source offered build, pull, and push actions through legacy `docker-py`,
pinned Engine API `1.13`, and included a local-container polling sensor. This
pack is a rewrite using Docker SDK 7 with `version="auto"`; no upstream Python
file is copied. The sensor is intentionally omitted because polling a local
privileged socket is not an appropriate initial Attune sensor design.
