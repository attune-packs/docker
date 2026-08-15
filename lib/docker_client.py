"""Guarded Docker SDK operations for the Docker Attune pack."""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit


class DockerPackError(ValueError):
    """An action validation or safe-to-report execution error."""


_KEY_REF = re.compile(r"^docker\.[a-z][a-z0-9_.-]{0,127}$")
_REGISTRY = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::[0-9]{1,5})?$")
_MAX_OUTPUT_BYTES = 1_000_000
_MAX_CONTEXT_ENTRIES = 20_000
_MAX_CONTEXT_BYTES = 2 * 1024 * 1024 * 1024
_MAX_STRING = 32_768
_PROFILE_LABEL = "io.attune.safety-profile"
_PROFILE_VALUE = "docker-restricted-v1"


class _ExplicitAuthOnly:
    """Prevent Docker SDK build from reloading ambient registry credentials."""

    is_empty = False

    def __bool__(self) -> bool:
        return True

    def get_all_credentials(self) -> dict[str, Any]:
        return {}


def _string(
    params: dict[str, Any], name: str, default: str | None = None, *, maximum: int = _MAX_STRING
) -> str:
    value = params.get(name, default)
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > maximum:
        raise DockerPackError(f"'{name}' must be a non-empty string of at most {maximum} characters")
    return value


def _boolean(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise DockerPackError(f"'{name}' must be a boolean")
    return value


def _integer(params: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DockerPackError(f"'{name}' must be an integer from {minimum} to {maximum}")
    return value


def _optional_string(params: dict[str, Any], name: str, maximum: int = _MAX_STRING) -> str | None:
    if params.get(name) is None:
        return None
    return _string(params, name, maximum=maximum)


def _argv(params: dict[str, Any], name: str = "command", *, required: bool = False) -> list[str] | None:
    value = params.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, list) or (required and not value) or len(value) > 256:
        raise DockerPackError(f"'{name}' must be an array of 1 to 256 arguments")
    if any(not isinstance(item, str) or not item or "\x00" in item for item in value):
        raise DockerPackError(f"'{name}' arguments must be non-empty strings without null bytes")
    if sum(len(item) for item in value) > _MAX_STRING:
        raise DockerPackError(f"'{name}' is too large")
    return value


def _mapping(params: dict[str, Any], name: str, *, secret: bool = False) -> dict[str, str]:
    value = params.get(name, {})
    if not isinstance(value, dict) or len(value) > 128:
        raise DockerPackError(f"'{name}' must be an object with at most 128 entries")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or "\x00" in key or len(key) > 256:
            raise DockerPackError(f"'{name}' keys must be non-empty strings")
        if not isinstance(item, str) or "\x00" in item or len(item) > _MAX_STRING:
            raise DockerPackError(f"'{name}' values must be strings without null bytes")
        result[key] = item
    return result


def _key_ref(params: dict[str, Any], name: str, default: str | None = None) -> str | None:
    value = params.get(name, default)
    if value is None:
        return None
    if not isinstance(value, str) or not _KEY_REF.fullmatch(value):
        raise DockerPackError(f"'{name}' must reference a pack-owned docker.* Attune Key")
    return value


def fetch_key(ref: str) -> dict[str, Any]:
    """Fetch and decrypt a pack-owned Attune Key without exposing response details."""
    if not _KEY_REF.fullmatch(ref):
        raise DockerPackError("credential Key must use the docker.* namespace")
    try:
        from attune import context
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(ref, client=context.client, decrypt=True)
        if int(response.status_code) != 200 or response.parsed is None:
            raise DockerPackError(f"Attune Key '{ref}' is unavailable")
        value = response.parsed.data.value
    except DockerPackError:
        raise
    except Exception as exc:
        raise DockerPackError(f"Attune Key '{ref}' is unavailable") from exc
    if not isinstance(value, dict):
        raise DockerPackError(f"Attune Key '{ref}' must contain a JSON object")
    return value


def _daemon_config(params: dict[str, Any]) -> tuple[str, dict[str, Any], int]:
    ref = _key_ref(params, "daemon_key", "docker.daemon")
    assert ref is not None
    config = fetch_key(ref)
    endpoint = config.get("endpoint", "unix:///var/run/docker.sock")
    if not isinstance(endpoint, str) or len(endpoint) > 2048 or "\x00" in endpoint:
        raise DockerPackError("daemon endpoint is invalid")
    parsed = urlsplit(endpoint)
    if parsed.scheme == "unix":
        if parsed.netloc or not parsed.path.startswith("/") or parsed.query or parsed.fragment:
            raise DockerPackError("Unix daemon endpoint must be an absolute unix:/// path")
        if config.get("tls") not in (None, {}):
            raise DockerPackError("TLS configuration is not valid for a Unix daemon endpoint")
    elif parsed.scheme == "tcp":
        if parsed.username or parsed.password or not parsed.hostname or parsed.path not in ("", "/"):
            raise DockerPackError("TCP daemon endpoint must be tcp://host:port without credentials or a path")
        try:
            port = parsed.port
        except ValueError as exc:
            raise DockerPackError("TCP daemon endpoint port is invalid") from exc
        if port is None or not 1 <= port <= 65535 or parsed.query or parsed.fragment:
            raise DockerPackError("TCP daemon endpoint must include a valid port")
        tls = config.get("tls")
        if not isinstance(tls, dict) or tls.get("verify") is not True:
            raise DockerPackError("TCP daemon endpoints require TLS certificate verification")
        if not isinstance(tls.get("ca_pem"), str) or not tls["ca_pem"].strip():
            raise DockerPackError("TCP daemon endpoints require a CA certificate in the daemon Key")
        cert_present = tls.get("client_cert_pem") is not None
        key_present = tls.get("client_key_pem") is not None
        if cert_present != key_present:
            raise DockerPackError("TLS client certificate and key must be provided together")
    else:
        raise DockerPackError("daemon endpoint scheme must be unix or tcp")
    timeout = config.get("timeout_seconds", 60)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        raise DockerPackError("daemon timeout_seconds must be an integer from 1 to 300")
    return endpoint, config, timeout


def _write_secret(directory: str, name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 262_144:
        raise DockerPackError(f"TLS {name} is invalid")
    path = Path(directory) / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value.encode("utf-8"))
    finally:
        os.close(descriptor)
    return str(path)


@contextlib.contextmanager
def docker_session(params: dict[str, Any]) -> Iterator[tuple[Any, str, str]]:
    endpoint, config, timeout = _daemon_config(params)
    temporary = tempfile.TemporaryDirectory(prefix="attune-docker-session-")
    client: Any = None
    try:
        try:
            import docker
        except ImportError as exc:
            raise DockerPackError("the declared Docker SDK dependency is unavailable") from exc
        tls_config = None
        if endpoint.startswith("tcp://"):
            tls = config["tls"]
            ca = _write_secret(temporary.name, "ca.pem", tls["ca_pem"])
            client_cert = None
            if tls.get("client_cert_pem") is not None:
                cert = _write_secret(temporary.name, "cert.pem", tls["client_cert_pem"])
                key = _write_secret(temporary.name, "key.pem", tls["client_key_pem"])
                client_cert = (cert, key)
            tls_config = docker.tls.TLSConfig(client_cert=client_cert, ca_cert=ca, verify=True)
        previous_config = os.environ.get("DOCKER_CONFIG")
        os.environ["DOCKER_CONFIG"] = temporary.name
        try:
            try:
                client = docker.DockerClient(
                    base_url=endpoint,
                    version="auto",
                    timeout=timeout,
                    tls=tls_config,
                )
            finally:
                if previous_config is None:
                    os.environ.pop("DOCKER_CONFIG", None)
                else:
                    os.environ["DOCKER_CONFIG"] = previous_config
            if (
                not hasattr(client.api, "_auth_configs")
                or not hasattr(client.api, "trust_env")
                or not hasattr(client.api, "_set_request_timeout")
            ):
                raise DockerPackError("installed Docker SDK cannot enforce explicit credential isolation")
            client.api._auth_configs = _ExplicitAuthOnly()
            client.api.trust_env = False
            original_timeout = client.api._set_request_timeout

            def bounded_request_timeout(kwargs: dict[str, Any]) -> dict[str, Any]:
                values = dict(kwargs)
                if values.get("timeout") is None:
                    values["timeout"] = client.api.timeout
                return original_timeout(values)

            client.api._set_request_timeout = bounded_request_timeout
            api_version = str(client.api.api_version)
        except Exception as exc:
            if isinstance(exc, DockerPackError):
                raise
            raise DockerPackError(f"Docker daemon connection failed ({type(exc).__name__})") from exc
        yield client, endpoint, api_version
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        temporary.cleanup()


def _registry_for_image(image: str) -> str:
    first = image.split("/", 1)[0].lower()
    registry = first if "." in first or ":" in first or first == "localhost" else "docker.io"
    return "docker.io" if registry in {"index.docker.io", "registry-1.docker.io"} else registry


def _registry_auth(params: dict[str, Any], image: str) -> tuple[dict[str, str], list[str]]:
    ref = _key_ref(params, "registry_key")
    if ref is None:
        return {}, []
    config = fetch_key(ref)
    registry = config.get("registry")
    if not isinstance(registry, str) or not _REGISTRY.fullmatch(registry):
        raise DockerPackError("registry Key must contain a valid registry host[:port]")
    if registry.lower() != _registry_for_image(image):
        raise DockerPackError("registry Key host does not match the image reference")
    username = config.get("username")
    password = config.get("password")
    token = config.get("identity_token")
    if token is not None and (username is not None or password is not None):
        raise DockerPackError("registry Key must use either identity_token or username/password")
    auth: dict[str, str] = {"serveraddress": registry}
    secrets: list[str] = []
    if token is not None:
        if not isinstance(token, str) or not token or len(token) > _MAX_STRING:
            raise DockerPackError("registry identity_token is invalid")
        auth["identitytoken"] = token
        secrets.append(token)
    else:
        if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
            raise DockerPackError("registry Key must contain username and password")
        if len(username) > 1024 or len(password) > _MAX_STRING:
            raise DockerPackError("registry credentials are too large")
        auth.update(username=username, password=password)
        secrets.extend([username, password])
    return auth, secrets


def _image_ref(params: dict[str, Any], name: str = "image") -> str:
    value = _string(params, name, maximum=512)
    if any(character.isspace() for character in value):
        raise DockerPackError(f"'{name}' must not contain whitespace")
    return value


def _artifact_root() -> Path:
    raw = os.environ.get("ATTUNE_ARTIFACTS_DIR")
    if not raw:
        raise DockerPackError("ATTUNE_ARTIFACTS_DIR is required for image builds")
    path = Path(raw)
    if not path.is_absolute():
        raise DockerPackError("ATTUNE_ARTIFACTS_DIR must be absolute")
    try:
        root = path.resolve(strict=True)
    except OSError as exc:
        raise DockerPackError("ATTUNE_ARTIFACTS_DIR is unavailable") from exc
    if not root.is_dir():
        raise DockerPackError("ATTUNE_ARTIFACTS_DIR must be a directory")
    return root


def _confined_context(params: dict[str, Any]) -> tuple[Path, str]:
    root = _artifact_root()
    raw_context = Path(_string(params, "context"))
    candidate = raw_context if raw_context.is_absolute() else root / raw_context
    try:
        context = candidate.resolve(strict=True)
    except OSError as exc:
        raise DockerPackError("build context does not exist") from exc
    if not context.is_dir() or not context.is_relative_to(root):
        raise DockerPackError("build context must be a directory within ATTUNE_ARTIFACTS_DIR")
    raw_dockerfile = Path(_string(params, "dockerfile", "Dockerfile"))
    dockerfile_candidate = raw_dockerfile if raw_dockerfile.is_absolute() else context / raw_dockerfile
    try:
        dockerfile = dockerfile_candidate.resolve(strict=True)
    except OSError as exc:
        raise DockerPackError("Dockerfile does not exist") from exc
    if not dockerfile.is_file() or not dockerfile.is_relative_to(context):
        raise DockerPackError("Dockerfile must be a file within the build context")
    entries = 0
    total = 0
    for directory, names, files in os.walk(context, followlinks=False):
        for name in [*names, *files]:
            path = Path(directory) / name
            entries += 1
            if entries > _MAX_CONTEXT_ENTRIES:
                raise DockerPackError("build context contains too many entries")
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise DockerPackError("build context changed while being validated") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise DockerPackError("build context must not contain symbolic links")
            if stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
            elif not stat.S_ISDIR(metadata.st_mode):
                raise DockerPackError("build context must contain only directories and regular files")
            if total > _MAX_CONTEXT_BYTES:
                raise DockerPackError("build context exceeds the 2 GiB safety limit")
    return context, str(dockerfile.relative_to(context))


def _redact(text: str, secrets: list[str]) -> str:
    for secret in sorted({item for item in secrets if len(item) >= 4}, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


def _append_bounded(chunks: list[bytes], chunk: Any, current: int) -> tuple[int, bool]:
    if chunk is None:
        return current, False
    data = chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8", "replace")
    remaining = _MAX_OUTPUT_BYTES - current
    if remaining > 0:
        chunks.append(data[:remaining])
    return current + min(len(data), max(remaining, 0)), len(data) > max(remaining, 0)


def _close_stream(stream: Any) -> None:
    close = getattr(stream, "close", None)
    if callable(close):
        close()


def _image_summary(image: Any) -> dict[str, Any]:
    attrs = image.attrs if isinstance(getattr(image, "attrs", None), dict) else {}
    return {
        "id": str(getattr(image, "id", attrs.get("Id", ""))),
        "tags": list(attrs.get("RepoTags") or getattr(image, "tags", []) or [])[:100],
        "digests": list(attrs.get("RepoDigests") or [])[:100],
        "created": attrs.get("Created"),
        "size": attrs.get("Size"),
        "os": attrs.get("Os"),
        "architecture": attrs.get("Architecture"),
    }


def _container_summary(container: Any) -> dict[str, Any]:
    attrs = container.attrs if isinstance(getattr(container, "attrs", None), dict) else {}
    config = attrs.get("Config") if isinstance(attrs.get("Config"), dict) else {}
    host = attrs.get("HostConfig") if isinstance(attrs.get("HostConfig"), dict) else {}
    state = attrs.get("State") if isinstance(attrs.get("State"), dict) else {}
    network_settings = attrs.get("NetworkSettings") if isinstance(attrs.get("NetworkSettings"), dict) else {}
    networks = network_settings.get("Networks") if isinstance(network_settings.get("Networks"), dict) else {}
    env_names = []
    for item in config.get("Env") or []:
        if isinstance(item, str):
            env_names.append(item.split("=", 1)[0])
    return {
        "id": str(getattr(container, "id", attrs.get("Id", ""))),
        "name": str(getattr(container, "name", attrs.get("Name", ""))).lstrip("/"),
        "image": config.get("Image"),
        "created": attrs.get("Created"),
        "status": getattr(container, "status", state.get("Status")),
        "state": {
            key: state.get(key)
            for key in ("Status", "Running", "Paused", "Restarting", "Dead", "Pid", "ExitCode", "StartedAt", "FinishedAt")
        },
        "config": {
            "user": config.get("User"),
            "working_dir": config.get("WorkingDir"),
            "entrypoint": config.get("Entrypoint"),
            "command": config.get("Cmd"),
            "env_names": sorted(set(env_names))[:256],
            "label_names": sorted((config.get("Labels") or {}).keys())[:256],
        },
        "isolation": {
            "read_only": host.get("ReadonlyRootfs"),
            "cap_drop": host.get("CapDrop"),
            "security_opt": host.get("SecurityOpt"),
            "network_mode": host.get("NetworkMode"),
            "memory": host.get("Memory"),
            "nano_cpus": host.get("NanoCpus"),
            "pids_limit": host.get("PidsLimit"),
        },
        "networks": {
            name: {"ip_address": value.get("IPAddress"), "gateway": value.get("Gateway")}
            for name, value in list(networks.items())[:32]
            if isinstance(value, dict)
        },
    }


def _confirmed(params: dict[str, Any], resource: str, *, name: str = "confirm") -> None:
    if params.get(name) != resource:
        raise DockerPackError(f"'{name}' must exactly match '{resource}'")


def _sdk_error(operation: str, exc: Exception) -> DockerPackError:
    return DockerPackError(f"{operation} failed ({type(exc).__name__}); remote details were redacted")


def _check_deadline(started: float, timeout: int, operation: str) -> None:
    if time.monotonic() - started > timeout:
        raise DockerPackError(f"{operation} exceeded its {timeout}-second timeout")


def _build(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    context, dockerfile = _confined_context(params)
    tag = _image_ref(params, "tag")
    network = params.get("network_mode", "none")
    if network not in {"none", "default"}:
        raise DockerPackError("'network_mode' must be 'none' or 'default'")
    if network == "default" and not _boolean(params, "confirm_network_access"):
        raise DockerPackError("'confirm_network_access' must be true for networked builds")
    timeout = _integer(params, "timeout_seconds", 900, 1, 1800)
    previous_timeout = client.api.timeout
    client.api.timeout = timeout
    events: list[dict[str, Any]] = []
    log_chunks: list[bytes] = []
    used = 0
    truncated = False
    stream = None
    started = time.monotonic()
    try:
        stream = client.api.build(
            path=str(context),
            dockerfile=dockerfile,
            tag=tag,
            rm=True,
            forcerm=True,
            nocache=_boolean(params, "no_cache"),
            pull=False,
            network_mode=network,
            decode=True,
            timeout=timeout,
            use_config_proxy=False,
        )
        for event in stream:
            _check_deadline(started, timeout, "image build")
            if not isinstance(event, dict):
                continue
            if event.get("error") or event.get("errorDetail"):
                raise DockerPackError("image build failed; daemon error details were redacted")
            text = event.get("stream") or event.get("status")
            if text:
                used, overflow = _append_bounded(log_chunks, text, used)
                truncated = truncated or overflow
            if len(events) < 1_000:
                events.append({key: event[key] for key in ("id", "status", "progress") if key in event})
            else:
                truncated = True
        image = client.images.get(tag)
    except DockerPackError:
        raise
    except Exception as exc:
        raise _sdk_error("image build", exc) from exc
    finally:
        client.api.timeout = previous_timeout
        if stream is not None:
            _close_stream(stream)
    return {
        "image": _image_summary(image),
        "log": b"".join(log_chunks).decode("utf-8", "replace"),
        "events": events,
        "truncated": truncated,
        "network_mode": network,
    }


def _pull(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    image_ref = _image_ref(params)
    auth, secrets = _registry_auth(params, image_ref)
    stream = None
    events: list[dict[str, str]] = []
    truncated = False
    timeout = client.api.timeout
    started = time.monotonic()
    try:
        stream = client.api.pull(image_ref, stream=True, decode=True, auth_config=auth)
        for event in stream:
            _check_deadline(started, timeout, "image pull")
            if not isinstance(event, dict):
                continue
            if event.get("error") or event.get("errorDetail"):
                raise DockerPackError("image pull failed; registry error details were redacted")
            if len(events) < 1_000:
                events.append(
                    {
                        key: _redact(str(event[key]), secrets)
                        for key in ("id", "status", "progress")
                        if key in event
                    }
                )
            else:
                truncated = True
        image = client.images.get(image_ref)
    except DockerPackError:
        raise
    except Exception as exc:
        raise _sdk_error("image pull", exc) from exc
    finally:
        if stream is not None:
            _close_stream(stream)
    return {"image": _image_summary(image), "events": events, "truncated": truncated}


def _push(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    image_ref = _image_ref(params)
    auth, secrets = _registry_auth(params, image_ref)
    stream = None
    events: list[dict[str, Any]] = []
    truncated = False
    digest = None
    timeout = client.api.timeout
    started = time.monotonic()
    try:
        stream = client.api.push(image_ref, stream=True, decode=True, auth_config=auth)
        for event in stream:
            _check_deadline(started, timeout, "image push")
            if not isinstance(event, dict):
                continue
            if event.get("error") or event.get("errorDetail"):
                raise DockerPackError("image push failed; registry error details were redacted")
            auxiliary = event.get("aux")
            if isinstance(auxiliary, dict) and auxiliary.get("Digest"):
                digest = _redact(str(auxiliary["Digest"]), secrets)
            if len(events) < 1_000:
                events.append(
                    {
                        key: _redact(str(event[key]), secrets)
                        for key in ("id", "status", "progress")
                        if key in event
                    }
                )
            else:
                truncated = True
    except DockerPackError:
        raise
    except Exception as exc:
        raise _sdk_error("image push", exc) from exc
    finally:
        if stream is not None:
            _close_stream(stream)
    return {"image": image_ref, "digest": digest, "events": events, "truncated": truncated}


def _image_inspect(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    image_ref = _image_ref(params)
    try:
        return {"image": _image_summary(client.images.get(image_ref))}
    except Exception as exc:
        raise _sdk_error("image inspect", exc) from exc


def _image_list(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    limit = _integer(params, "limit", 100, 1, 500)
    name = _optional_string(params, "name", 512)
    try:
        images = client.images.list(name=name, all=_boolean(params, "all"))
    except Exception as exc:
        raise _sdk_error("image list", exc) from exc
    return {
        "images": [_image_summary(image) for image in images[:limit]],
        "count": min(len(images), limit),
        "truncated": len(images) > limit,
    }


def _image_remove(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    image_ref = _image_ref(params)
    _confirmed(params, image_ref)
    try:
        records = client.images.remove(image_ref, force=False, noprune=_boolean(params, "no_prune"))
    except Exception as exc:
        raise _sdk_error("image remove", exc) from exc
    return {"image": image_ref, "removed": records or []}


def _container(client: Any, name: str) -> Any:
    try:
        return client.containers.get(name)
    except Exception as exc:
        raise _sdk_error("container lookup", exc) from exc


def _assert_restricted_container(container: Any) -> None:
    attrs = container.attrs if isinstance(getattr(container, "attrs", None), dict) else {}
    config = attrs.get("Config") if isinstance(attrs.get("Config"), dict) else {}
    host = attrs.get("HostConfig") if isinstance(attrs.get("HostConfig"), dict) else {}
    labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
    dangerous = any(
        (
            host.get("Privileged"),
            host.get("Binds"),
            attrs.get("Mounts"),
            host.get("Devices"),
            host.get("CapAdd"),
            host.get("NetworkMode") == "host",
            host.get("PidMode") == "host",
            host.get("IpcMode") == "host",
            host.get("UTSMode") == "host",
        )
    )
    if (
        labels.get(_PROFILE_LABEL) != _PROFILE_VALUE
        or dangerous
        or "ALL" not in (host.get("CapDrop") or [])
        or "no-new-privileges" not in (host.get("SecurityOpt") or [])
    ):
        raise DockerPackError(
            "container does not satisfy the pack-managed restricted safety profile"
        )


def _container_create(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    image = _image_ref(params)
    name = _optional_string(params, "name", 255)
    command = _argv(params)
    environment = _mapping(params, "environment", secret=True)
    labels = _mapping(params, "labels")
    if any(key.startswith("io.attune.") for key in labels):
        raise DockerPackError("'labels' must not use the reserved io.attune.* namespace")
    labels[_PROFILE_LABEL] = _PROFILE_VALUE
    allow_network = _boolean(params, "allow_network")
    if allow_network and not _boolean(params, "confirm_network_access"):
        raise DockerPackError("'confirm_network_access' must be true when network access is enabled")
    user = _optional_string(params, "user", 256)
    working_dir = _optional_string(params, "working_directory", 4096)
    container = None
    try:
        image_object = client.images.get(image)
        image_attrs = image_object.attrs if isinstance(getattr(image_object, "attrs", None), dict) else {}
        image_config = image_attrs.get("Config") if isinstance(image_attrs.get("Config"), dict) else {}
        if image_config.get("Volumes"):
            raise DockerPackError("container image declares volumes and is not allowed by the restricted profile")
        container = client.containers.create(
            image=image,
            name=name,
            command=command,
            environment=environment,
            labels=labels,
            user=user or "",
            working_dir=working_dir or "",
            detach=True,
            stdin_open=False,
            tty=False,
            auto_remove=False,
            network_disabled=not allow_network,
            network_mode="bridge" if allow_network else "none",
            privileged=False,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            read_only=_boolean(params, "read_only", True),
            mem_limit=_integer(params, "memory_bytes", 536_870_912, 16_777_216, 68_719_476_736),
            nano_cpus=_integer(params, "nano_cpus", 1_000_000_000, 10_000_000, 64_000_000_000),
            pids_limit=_integer(params, "pids_limit", 256, 16, 4096),
            init=True,
            use_config_proxy=False,
        )
        container.reload()
        _assert_restricted_container(container)
    except DockerPackError:
        if container is not None:
            try:
                container.remove(force=False, v=True)
            except Exception:
                pass
        raise
    except Exception as exc:
        if container is not None:
            try:
                container.remove(force=False, v=True)
            except Exception:
                pass
        raise _sdk_error("container create", exc) from exc
    return {"container": _container_summary(container)}


def _container_start(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = _string(params, "container", maximum=512)
    container = _container(client, name)
    _assert_restricted_container(container)
    try:
        container.start()
        container.reload()
    except Exception as exc:
        raise _sdk_error("container start", exc) from exc
    return {"container": _container_summary(container)}


def _container_stop(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = _string(params, "container", maximum=512)
    _confirmed(params, name)
    grace = _integer(params, "grace_seconds", 10, 0, 300)
    container = _container(client, name)
    try:
        container.stop(timeout=grace)
        container.reload()
    except Exception as exc:
        raise _sdk_error("container stop", exc) from exc
    return {"container": _container_summary(container), "grace_seconds": grace}


def _container_restart(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = _string(params, "container", maximum=512)
    _confirmed(params, name)
    grace = _integer(params, "grace_seconds", 10, 0, 300)
    container = _container(client, name)
    _assert_restricted_container(container)
    try:
        container.restart(timeout=grace)
        container.reload()
    except Exception as exc:
        raise _sdk_error("container restart", exc) from exc
    return {"container": _container_summary(container), "grace_seconds": grace}


def _container_remove(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = _string(params, "container", maximum=512)
    _confirmed(params, name)
    container = _container(client, name)
    identifier = str(getattr(container, "id", name))
    try:
        container.remove(force=False, v=False)
    except Exception as exc:
        raise _sdk_error("container remove", exc) from exc
    return {"container": name, "id": identifier, "removed": True, "volumes_removed": False}


def _container_inspect(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = _string(params, "container", maximum=512)
    container = _container(client, name)
    try:
        container.reload()
    except Exception as exc:
        raise _sdk_error("container inspect", exc) from exc
    return {"container": _container_summary(container)}


def _container_logs(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = _string(params, "container", maximum=512)
    container = _container(client, name)
    _assert_restricted_container(container)
    tail = _integer(params, "tail", 200, 1, 10_000)
    max_bytes = _integer(params, "max_bytes", 262_144, 1, _MAX_OUTPUT_BYTES)
    stream = None
    chunks: list[bytes] = []
    used = 0
    truncated = False
    timeout = client.api.timeout
    started = time.monotonic()
    try:
        stream = container.logs(
            stdout=True,
            stderr=True,
            stream=True,
            follow=False,
            timestamps=_boolean(params, "timestamps"),
            tail=tail,
        )
        for chunk in stream:
            _check_deadline(started, timeout, "container logs")
            data = chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8", "replace")
            remaining = max_bytes - used
            if remaining > 0:
                chunks.append(data[:remaining])
                used += min(len(data), remaining)
            if len(data) > max(remaining, 0):
                truncated = True
                break
    except Exception as exc:
        raise _sdk_error("container logs", exc) from exc
    finally:
        if stream is not None:
            _close_stream(stream)
    return {
        "container": name,
        "logs": b"".join(chunks).decode("utf-8", "replace"),
        "bytes": used,
        "truncated": truncated,
    }


def _container_exec(client: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = _string(params, "container", maximum=512)
    _confirmed(params, name)
    command = _argv(params, required=True)
    assert command is not None
    environment = _mapping(params, "environment", secret=True)
    secrets = list(environment.values())
    timeout = _integer(params, "timeout_seconds", 60, 1, 300)
    max_bytes = _integer(params, "max_bytes", 262_144, 1, _MAX_OUTPUT_BYTES)
    container = _container(client, name)
    _assert_restricted_container(container)
    previous_timeout = client.api.timeout
    client.api.timeout = timeout
    stream = None
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_used = 0
    stderr_used = 0
    truncated = False
    started = time.monotonic()
    try:
        created = client.api.exec_create(
            container.id,
            command,
            stdout=True,
            stderr=True,
            stdin=False,
            tty=False,
            privileged=False,
            environment=environment,
        )
        exec_id = created.get("Id") if isinstance(created, dict) else None
        if not isinstance(exec_id, str) or not exec_id:
            raise DockerPackError("container exec failed to return an execution ID")
        stream = client.api.exec_start(exec_id, detach=False, tty=False, stream=True, demux=True)
        for item in stream:
            _check_deadline(started, timeout, "container exec")
            stdout, stderr = item if isinstance(item, tuple) else (item, None)
            if stdout is not None:
                data = stdout if isinstance(stdout, bytes) else str(stdout).encode("utf-8", "replace")
                remaining = max_bytes - stdout_used - stderr_used
                if remaining > 0:
                    stdout_chunks.append(data[:remaining])
                    stdout_used += min(len(data), remaining)
                if len(data) > max(remaining, 0):
                    truncated = True
                    break
            if stderr is not None:
                data = stderr if isinstance(stderr, bytes) else str(stderr).encode("utf-8", "replace")
                remaining = max_bytes - stdout_used - stderr_used
                if remaining > 0:
                    stderr_chunks.append(data[:remaining])
                    stderr_used += min(len(data), remaining)
                if len(data) > max(remaining, 0):
                    truncated = True
                    break
        inspection = client.api.exec_inspect(exec_id)
        exit_code = inspection.get("ExitCode") if isinstance(inspection, dict) else None
        running = bool(inspection.get("Running")) if isinstance(inspection, dict) else False
    except DockerPackError:
        raise
    except Exception as exc:
        raise _sdk_error("container exec", exc) from exc
    finally:
        client.api.timeout = previous_timeout
        if stream is not None:
            _close_stream(stream)
    stdout_text = _redact(b"".join(stdout_chunks).decode("utf-8", "replace"), secrets)
    stderr_text = _redact(b"".join(stderr_chunks).decode("utf-8", "replace"), secrets)
    return {
        "container": name,
        "exec_id": exec_id,
        "exit_code": exit_code,
        "running": running,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "truncated": truncated,
    }


_OPERATIONS = {
    "image_build": _build,
    "image_pull": _pull,
    "image_push": _push,
    "image_inspect": _image_inspect,
    "image_list": _image_list,
    "image_remove": _image_remove,
    "container_create": _container_create,
    "container_start": _container_start,
    "container_stop": _container_stop,
    "container_restart": _container_restart,
    "container_remove": _container_remove,
    "container_inspect": _container_inspect,
    "container_logs": _container_logs,
    "container_exec": _container_exec,
}


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    handler = _OPERATIONS.get(operation)
    if handler is None:
        raise DockerPackError("unsupported Docker action")
    with docker_session(params) as (client, endpoint, api_version):
        result = handler(client, params)
    return {
        "operation": operation,
        "endpoint": endpoint,
        "api_version": api_version,
        "result": result,
    }
