# Docker Engine Attune Pack

Guarded Docker image and container operations using Docker SDK for Python 7
and negotiated Engine API versions.

Action resources are flat JSON documents stored with Attune's required
`.yaml` discovery suffix; parameters and outputs use JSON over stdin/stdout.

## Security Boundary

Access to a Docker daemon is root-equivalent on the daemon host. Anyone who
can execute these actions can usually influence host-level workloads even
though this pack excludes the most direct escape primitives. Grant execution
only to a dedicated privileged Attune role, isolate its workers, and audit all
uses. Never expose the Docker TCP API without mutually trusted network policy
and verified TLS.

Container creation deliberately does not expose bind mounts, named volumes,
devices, host networking, published ports, added Linux capabilities,
privileged mode, host PID/IPC/UTS namespaces, custom seccomp profiles, or the
Docker socket. It always drops all capabilities, enables `no-new-privileges`,
uses an init process, applies memory/CPU/PID limits, and defaults to a read-only
root filesystem with no network. Images declaring `VOLUME` are rejected to
prevent implicit anonymous mounts. These restrictions are not a sandbox
against a malicious daemon or a vulnerable kernel.

Created containers receive an `io.attune.safety-profile=docker-restricted-v1`
label. Start, restart, and exec revalidate that label, dropped capabilities,
`no-new-privileges`, mounts, devices, privilege, and host namespaces before
acting. Logs use the same check to avoid exposing output from arbitrary daemon
workloads. These actions refuse containers outside this restricted profile.

`container_exec` accepts an argv array and never invokes a shell. It requires
an exact container-name/ID confirmation and disables stdin, TTY, and privileged
exec. Docker has no API to cancel an exec process: a client timeout or bounded
output disconnect can leave the process running in the container. Do not use
the action where that residual behavior is unacceptable.

## Keys

Credentials are read only from encrypted, pack-owned Attune Keys whose refs
begin with `docker.`. Create the default local daemon Key:

```sh
attune key create --ref docker.daemon --name "Docker local daemon" \
  --value '{"endpoint":"unix:///var/run/docker.sock","timeout_seconds":60}' \
  --owner-type pack --owner-pack-ref docker --encrypt
```

The endpoint defaults to `unix:///var/run/docker.sock` when omitted from this
Key. Supported endpoint schemes are `unix` and `tcp`. TCP always requires
certificate verification. Docker CLI named contexts are not resolved; select
the daemon by putting its endpoint and credentials explicitly in the Key:

```json
{
  "endpoint": "tcp://docker.example.com:2376",
  "timeout_seconds": 60,
  "tls": {
    "verify": true,
    "ca_pem": "-----BEGIN CERTIFICATE-----\n...",
    "client_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
    "client_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
  }
}
```

The client certificate and key are optional as a pair; the CA and verification
are mandatory. Temporary PEM files are mode `0600` and removed when the action
finishes. Passwords in endpoint URLs, unverified TCP, SSH contexts, and ambient
`DOCKER_HOST`, proxy settings, and Docker config are rejected or ignored. The
SDK is constructed with a private empty Docker config and cannot reload ambient
registry credentials for a build.

For authenticated pull or push, create a separate pack-owned Key:

```sh
attune key create --ref docker.registry --name "Docker registry" \
  --value '{"registry":"registry.example.com","username":"robot","password":"REPLACE"}' \
  --owner-type pack --owner-pack-ref docker --encrypt
```

Use `identity_token` instead of `username` and `password` when appropriate.
The Key registry must exactly match the registry in the image reference, which
prevents forwarding credentials to an unintended registry. Public operations
omit `registry_key`. Registry and daemon errors are intentionally opaque.

## Build Artifacts

`image_build.context` is resolved beneath `ATTUNE_ARTIFACTS_DIR`; the
Dockerfile must resolve inside that context. Absolute inputs are accepted only
when still confined. Symbolic links, special files, more than 20,000 entries,
and contexts over 2 GiB are rejected. Build networking defaults to `none` and
requires both `network_mode: "default"` and `confirm_network_access: true` to
enable it for Dockerfile `RUN` instructions. `pull` is disabled, but the daemon
can still resolve a missing base image from a registry; enforce daemon egress
policy and preload base images when that is unacceptable. Build arguments are
omitted to avoid implicit credentials and secret-bearing image history.

Artifact directories should be immutable to action callers for the duration
of a build. Filesystem validation and SDK archive creation cannot make a
concurrently writable directory race-free.

## Actions

| Action | Purpose | Guard |
| --- | --- | --- |
| `docker.image_build` | Build and tag from a confined context | no network by default; bounded context/log/time |
| `docker.image_pull` | Pull an image | explicit optional registry Key |
| `docker.image_push` | Push an image | explicit optional registry Key; bounded events |
| `docker.image_inspect` | Return selected non-secret image fields | omits environment values and labels |
| `docker.image_list` | List selected image fields | limit 1-500 |
| `docker.image_remove` | Remove an unforced image | exact `confirm`; no force |
| `docker.container_create` | Create a restricted container | no mounts/privilege/host namespaces |
| `docker.container_start` | Start an existing container | no implicit create or pull |
| `docker.container_stop` | Stop an existing container | exact `confirm`; bounded grace |
| `docker.container_restart` | Restart an existing container | exact `confirm`; bounded grace |
| `docker.container_remove` | Remove a stopped container | exact `confirm`; no force/volume removal |
| `docker.container_inspect` | Return selected non-secret fields | omits environment and label values/mounts |
| `docker.container_logs` | Read non-following logs | bounded tail and bytes |
| `docker.container_exec` | Run an argv command | exact `confirm`; no shell/stdin/TTY/privilege |

Start, restart, logs, and exec additionally require the pack-managed restricted
safety profile. Stop and non-forced remove remain available for incident
response against other containers.

Mutating operations execute once and are never retried by pack code. A caller
must inspect the resulting daemon state before deciding whether a failed
mutation is safe to repeat. Daemon requests and streams use the Key's bounded
timeout; build and exec can select stricter action-specific bounds.

## Testing

Tests use deterministic fake SDK objects and Attune API modules. They do not
contact a live daemon, registry, or Attune server and import no undeclared test
dependency:

```sh
python3 -m unittest -v tests/test_pack.py
attune pack check /absolute/path/to/docker
attune pack test /absolute/path/to/docker
```

No sensor is included in this release. See `SOURCE.md` and `NOTICE` for source
verification and attribution.
