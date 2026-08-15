from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

PACK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACK_ROOT))

from lib import docker_client


class Stream:
    def __init__(self, values):
        self.values = values
        self.closed = False

    def __iter__(self):
        return iter(self.values)

    def close(self):
        self.closed = True


class FakeImage:
    def __init__(self, identifier="sha256:image", tags=None):
        self.id = identifier
        self.tags = tags or ["example:latest"]
        self.attrs = {
            "Id": identifier,
            "RepoTags": self.tags,
            "RepoDigests": ["example@sha256:digest"],
            "Created": "2026-01-01T00:00:00Z",
            "Size": 123,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"Env": ["IMAGE_SECRET=do-not-return"]},
        }


class FakeContainer:
    def __init__(self, identifier="container-id", name="example"):
        self.id = identifier
        self.name = name
        self.status = "created"
        self.calls = []
        self.attrs = {
            "Id": identifier,
            "Name": f"/{name}",
            "Created": "2026-01-01T00:00:00Z",
            "Config": {
                "Image": "example:latest",
                "User": "1000",
                "WorkingDir": "/work",
                "Entrypoint": None,
                "Cmd": ["sleep", "10"],
                "Env": ["TOKEN=container-secret", "MODE=test"],
                "Labels": {
                    "secret-label": "label-secret",
                    "io.attune.safety-profile": "docker-restricted-v1",
                },
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "NetworkMode": "none",
                "Memory": 536870912,
                "NanoCpus": 1000000000,
                "PidsLimit": 256,
                "Binds": [],
            },
            "State": {
                "Status": "created",
                "Running": False,
                "Paused": False,
                "Restarting": False,
                "Dead": False,
                "Pid": 0,
                "ExitCode": 0,
                "StartedAt": "",
                "FinishedAt": "",
                "Error": "secret state error",
            },
            "NetworkSettings": {"Networks": {"none": {"IPAddress": "", "Gateway": ""}}},
            "Mounts": [],
        }

    def reload(self):
        self.calls.append(("reload", {}))

    def start(self):
        self.status = "running"
        self.calls.append(("start", {}))

    def stop(self, **kwargs):
        self.status = "exited"
        self.calls.append(("stop", kwargs))

    def restart(self, **kwargs):
        self.status = "running"
        self.calls.append(("restart", kwargs))

    def remove(self, **kwargs):
        self.calls.append(("remove", kwargs))

    def logs(self, **kwargs):
        self.calls.append(("logs", kwargs))
        return Stream([b"first\n", b"x" * 100])


class FakeImages:
    def __init__(self):
        self.image = FakeImage()
        self.calls = []
        self.fail_pull = None

    def get(self, image):
        self.calls.append(("get", image))
        return self.image

    def pull(self, image, **kwargs):
        self.calls.append(("pull", image, kwargs))
        if self.fail_pull is not None:
            raise self.fail_pull
        return self.image

    def list(self, **kwargs):
        self.calls.append(("list", kwargs))
        return [self.image, FakeImage("sha256:second", ["second:latest"])]

    def remove(self, image, **kwargs):
        self.calls.append(("remove", image, kwargs))
        return [{"Deleted": image}]


class FakeContainers:
    def __init__(self):
        self.container = FakeContainer()
        self.calls = []

    def get(self, name):
        self.calls.append(("get", name))
        return self.container

    def create(self, **kwargs):
        self.calls.append(("create", kwargs))
        return self.container


class FakeAPI:
    def __init__(self):
        self.api_version = "1.47"
        self.timeout = 60
        self.trust_env = True
        self._auth_configs = object()
        self.calls = []
        self.fail_pull = None

    def _set_request_timeout(self, kwargs):
        kwargs.setdefault("timeout", self.timeout)
        return kwargs

    def build(self, **kwargs):
        self.calls.append(("build", kwargs))
        return Stream([{"stream": "Step 1/1\n"}, {"status": "done", "id": "layer"}])

    def push(self, image, **kwargs):
        self.calls.append(("push", image, kwargs))
        return Stream([{"status": "pushed", "id": "layer"}, {"aux": {"Digest": "sha256:digest"}}])

    def pull(self, image, **kwargs):
        self.calls.append(("pull", image, kwargs))
        if self.fail_pull is not None:
            raise self.fail_pull
        self.last_pull_stream = Stream([{"status": "pulled", "id": "layer"}])
        return self.last_pull_stream

    def exec_create(self, container, command, **kwargs):
        self.calls.append(("exec_create", container, command, kwargs))
        return {"Id": "exec-id"}

    def exec_start(self, exec_id, **kwargs):
        self.calls.append(("exec_start", exec_id, kwargs, self.timeout))
        return Stream([(b"token=exec-secret\n", None), (None, b"stderr\n")])

    def exec_inspect(self, exec_id):
        self.calls.append(("exec_inspect", exec_id))
        return {"ExitCode": 0, "Running": False}


class FakeClient:
    def __init__(self):
        self.api = FakeAPI()
        self.images = FakeImages()
        self.containers = FakeContainers()
        self.closed = False

    def close(self):
        self.closed = True


def fake_docker_module(client, capture):
    module = ModuleType("docker")

    class TLSConfig:
        def __init__(self, **kwargs):
            capture["tls"] = kwargs

    def DockerClient(**kwargs):
        capture["client"] = kwargs
        return client

    module.tls = SimpleNamespace(TLSConfig=TLSConfig)
    module.DockerClient = DockerClient
    return module


def load_entrypoint():
    path = PACK_ROOT / "actions" / "docker_action.py"
    spec = importlib.util.spec_from_file_location("docker_action_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Docker action entry point")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DockerPackTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.capture = {}
        self.docker = fake_docker_module(self.client, self.capture)
        self.daemon = {"endpoint": "unix:///var/run/docker.sock", "timeout_seconds": 60}

    def execute(self, operation, params=None, key_values=None):
        values = dict(params or {})
        keys = {"docker.daemon": self.daemon}
        keys.update(key_values or {})
        with patch.dict(sys.modules, {"docker": self.docker}), patch.object(
            docker_client, "fetch_key", side_effect=lambda ref: keys[ref]
        ):
            return docker_client.execute_action(operation, values)

    def test_yaml_action_contracts_are_all_discovered_resources(self):
        paths = sorted((PACK_ROOT / "actions").glob("*.yaml"))
        expected = {
            "image_build", "image_pull", "image_push", "image_inspect", "image_list", "image_remove",
            "container_create", "container_start", "container_stop", "container_restart",
            "container_remove", "container_inspect", "container_logs", "container_exec",
        }
        self.assertEqual({path.stem for path in paths}, expected)
        for path in paths:
            action = path.read_text(encoding="utf-8")
            self.assertFalse(action.lstrip().startswith(("{", "[")))
            self.assertIn(f'ref: "docker.{path.stem}"', action)
            self.assertIn('runner_type: "python"', action)
            self.assertIn('entry_point: "docker_action.py"', action)
            self.assertIn('parameter_delivery: "stdin"', action)
            self.assertIn('parameter_format: "json"', action)
            self.assertIn('output_format: "json"', action)
            self.assertIn('default: "docker.daemon"', action)
            for field in ("operation", "endpoint", "api_version", "result"):
                self.assertIn(f"\n  {field}:\n", action)
        create = (PACK_ROOT / "actions" / "container_create.yaml").read_text()
        parameters = create.split("parameters:\n", 1)[1].split("output:\n", 1)[0]
        forbidden = {"volumes", "mounts", "devices", "privileged", "ports", "network_mode", "cap_add"}
        self.assertTrue(all(f"\n  {name}:" not in parameters for name in forbidden))
        self.assertFalse((PACK_ROOT / "sensors").exists())

    def test_source_license_and_notice_pin_verified_upstream(self):
        pack = (PACK_ROOT / "pack.yaml").read_text(encoding="utf-8")
        notice = (PACK_ROOT / "NOTICE").read_text(encoding="utf-8")
        license_text = (PACK_ROOT / "LICENSE").read_text(encoding="utf-8")
        revision = "50cebd7f7d59272d09cd34261257327bff17f97e"
        self.assertIn(f'source_revision: "{revision}"', pack)
        self.assertIn('source_version: "1.0.0"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn(revision, notice)
        self.assertIn("Apache License", license_text)

    def test_key_lookup_requests_decryption(self):
        calls = {}
        get_key = ModuleType("attune.api_client.api.secrets.get_key")
        get_key.sync_detailed = lambda ref, *, client, decrypt: calls.update(
            ref=ref, client=client, decrypt=decrypt
        ) or SimpleNamespace(status_code=200, parsed=SimpleNamespace(data=SimpleNamespace(value={"endpoint": "unix:///sock"})))
        secrets = ModuleType("attune.api_client.api.secrets")
        secrets.get_key = get_key
        modules = {
            "attune": SimpleNamespace(context=SimpleNamespace(client="execution-client")),
            "attune.api_client": ModuleType("attune.api_client"),
            "attune.api_client.api": ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": secrets,
        }
        with patch.dict(sys.modules, modules):
            value = docker_client.fetch_key("docker.daemon")
        self.assertEqual(value["endpoint"], "unix:///sock")
        self.assertEqual(calls, {"ref": "docker.daemon", "client": "execution-client", "decrypt": True})
        with self.assertRaisesRegex(docker_client.DockerPackError, "docker.\\*"):
            docker_client.fetch_key("other.credentials")

    def test_local_session_negotiates_api_and_ignores_environment(self):
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://attacker:2375"}, clear=True):
            result = self.execute("image_inspect", {"image": "example:latest"})
        self.assertEqual(self.capture["client"]["base_url"], "unix:///var/run/docker.sock")
        self.assertEqual(self.capture["client"]["version"], "auto")
        self.assertFalse(self.client.api.trust_env)
        self.assertIsInstance(self.client.api._auth_configs, docker_client._ExplicitAuthOnly)
        self.assertEqual(self.client.api._set_request_timeout({"timeout": None})["timeout"], 60)
        self.assertEqual(result["api_version"], "1.47")
        self.assertEqual(result["endpoint"], "unix:///var/run/docker.sock")
        self.assertTrue(self.client.closed)

    def test_tcp_requires_verified_tls_and_cleans_private_pem_files(self):
        insecure = {"endpoint": "tcp://docker.example:2376"}
        with patch.object(docker_client, "fetch_key", return_value=insecure), self.assertRaisesRegex(
            docker_client.DockerPackError, "require TLS"
        ):
            with docker_client.docker_session({}):
                pass

        secure = {
            "endpoint": "tcp://docker.example:2376",
            "tls": {
                "verify": True,
                "ca_pem": "CA DATA",
                "client_cert_pem": "CERT DATA",
                "client_key_pem": "KEY DATA",
            },
        }
        with patch.object(docker_client, "fetch_key", return_value=secure), patch.dict(
            sys.modules, {"docker": self.docker}
        ):
            with docker_client.docker_session({}):
                tls_paths = [self.capture["tls"]["ca_cert"], *self.capture["tls"]["client_cert"]]
                self.assertTrue(all(stat.S_IMODE(Path(path).stat().st_mode) == 0o600 for path in tls_paths))
        self.assertTrue(all(not Path(path).exists() for path in tls_paths))
        self.assertTrue(self.capture["tls"]["verify"])

    def test_registry_credentials_are_scoped_and_never_enter_results(self):
        registry = {"registry": "registry.example.com", "username": "robot", "password": "registry-secret"}
        result = self.execute(
            "image_pull",
            {"image": "registry.example.com/team/app:1", "registry_key": "docker.registry"},
            {"docker.registry": registry},
        )
        call = next(call for call in self.client.api.calls if call[0] == "pull")
        self.assertEqual(call[2]["auth_config"]["password"], "registry-secret")
        self.assertNotIn("registry-secret", json.dumps(result))
        with self.assertRaisesRegex(docker_client.DockerPackError, "does not match"):
            self.execute(
                "image_pull",
                {"image": "other.example/team/app:1", "registry_key": "docker.registry"},
                {"docker.registry": registry},
            )

    def test_build_context_is_confined_rejects_symlinks_and_uses_structured_sdk_arguments(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory).resolve()
            context = root / "context;not-a-shell"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            environment = {"ATTUNE_ARTIFACTS_DIR": str(root)}
            with patch.dict(os.environ, environment, clear=True):
                result = self.execute(
                    "image_build",
                    {"context": context.name, "tag": "safe:latest", "timeout_seconds": 12},
                )
            call = self.client.api.calls[0]
            self.assertEqual(call[0], "build")
            self.assertEqual(call[1]["path"], str(context))
            self.assertEqual(call[1]["dockerfile"], "Dockerfile")
            self.assertEqual(call[1]["network_mode"], "none")
            self.assertFalse(call[1]["use_config_proxy"])
            self.assertEqual(call[1]["timeout"], 12)
            self.assertEqual(result["result"]["image"]["id"], "sha256:image")
            self.assertEqual(self.client.api.timeout, 60)

            link = context / "escape"
            link.symlink_to(Path(outside) / "outside")
            with patch.dict(os.environ, environment, clear=True), self.assertRaisesRegex(
                docker_client.DockerPackError, "symbolic links"
            ):
                self.execute("image_build", {"context": context.name, "tag": "safe:latest"})
            link.unlink()
            with patch.dict(os.environ, environment, clear=True), self.assertRaisesRegex(
                docker_client.DockerPackError, "within ATTUNE_ARTIFACTS_DIR"
            ):
                self.execute("image_build", {"context": outside, "tag": "safe:latest"})

    def test_networked_build_and_container_require_explicit_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            with patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": str(root)}, clear=True), self.assertRaisesRegex(
                docker_client.DockerPackError, "confirm_network_access"
            ):
                self.execute("image_build", {"context": ".", "tag": "safe:latest", "network_mode": "default"})
        with self.assertRaisesRegex(docker_client.DockerPackError, "confirm_network_access"):
            self.execute("container_create", {"image": "safe:latest", "allow_network": True})

    def test_container_create_enforces_restrictions_and_preserves_argv(self):
        hostile = ["printf", "%s", "$(touch /tmp/injected); rm -rf /"]
        result = self.execute(
            "container_create",
            {"image": "safe:latest", "command": hostile, "environment": {"TOKEN": "container-secret"}},
        )
        kwargs = self.client.containers.calls[-1][1]
        self.assertEqual(kwargs["command"], hostile)
        self.assertFalse(kwargs["privileged"])
        self.assertEqual(kwargs["cap_drop"], ["ALL"])
        self.assertEqual(kwargs["security_opt"], ["no-new-privileges"])
        self.assertEqual(kwargs["labels"]["io.attune.safety-profile"], "docker-restricted-v1")
        self.assertEqual(kwargs["network_mode"], "none")
        self.assertTrue(kwargs["network_disabled"])
        self.assertTrue(kwargs["read_only"])
        self.assertFalse(kwargs["stdin_open"])
        self.assertFalse(kwargs["tty"])
        self.assertFalse(kwargs["auto_remove"])
        self.assertFalse(kwargs["use_config_proxy"])
        for unsafe in ("volumes", "mounts", "devices", "ports", "pid_mode", "ipc_mode"):
            self.assertNotIn(unsafe, kwargs)
        self.assertNotIn("container-secret", json.dumps(result))
        with self.assertRaisesRegex(docker_client.DockerPackError, "reserved"):
            self.execute(
                "container_create",
                {"image": "safe:latest", "labels": {"io.attune.safety-profile": "fake"}},
            )
        self.client.containers.container.attrs["Mounts"] = [{"Source": "/unexpected"}]
        with self.assertRaisesRegex(docker_client.DockerPackError, "restricted safety profile"):
            self.execute("container_create", {"image": "safe:latest"})
        self.assertEqual(
            self.client.containers.container.calls[-1],
            ("remove", {"force": False, "v": True}),
        )
        self.client.containers.container.attrs["Mounts"] = []
        self.client.images.image.attrs["Config"]["Volumes"] = {"/data": {}}
        with self.assertRaisesRegex(docker_client.DockerPackError, "declares volumes"):
            self.execute("container_create", {"image": "safe:latest"})

    def test_start_restart_and_exec_refuse_unmanaged_or_dangerous_containers(self):
        labels = self.client.containers.container.attrs["Config"]["Labels"]
        labels.pop("io.attune.safety-profile")
        with self.assertRaisesRegex(docker_client.DockerPackError, "restricted safety profile"):
            self.execute("container_start", {"container": "example"})
        labels["io.attune.safety-profile"] = "docker-restricted-v1"
        self.client.containers.container.attrs["HostConfig"]["Binds"] = ["/:/host"]
        for operation, params in (
            ("container_start", {"container": "example"}),
            ("container_restart", {"container": "example", "confirm": "example"}),
            ("container_logs", {"container": "example"}),
            (
                "container_exec",
                {"container": "example", "confirm": "example", "command": ["id"]},
            ),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                docker_client.DockerPackError, "restricted safety profile"
            ):
                self.execute(operation, params)

    def test_destructive_actions_require_exact_confirmation_and_never_force(self):
        with self.assertRaisesRegex(docker_client.DockerPackError, "exactly match"):
            self.execute("image_remove", {"image": "safe:latest", "confirm": "REMOVE"})
        self.execute("image_remove", {"image": "safe:latest", "confirm": "safe:latest"})
        self.assertEqual(self.client.images.calls[-1][2], {"force": False, "noprune": False})

        for operation in ("container_stop", "container_restart", "container_remove"):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                docker_client.DockerPackError, "exactly match"
            ):
                self.execute(operation, {"container": "example", "confirm": "wrong"})
        self.execute("container_remove", {"container": "example", "confirm": "example"})
        self.assertEqual(self.client.containers.container.calls[-1], ("remove", {"force": False, "v": False}))

    def test_mutations_are_not_retried_and_sdk_errors_are_opaque(self):
        self.client.api.fail_pull = RuntimeError("registry-secret response body")
        with self.assertRaises(docker_client.DockerPackError) as raised:
            self.execute("image_pull", {"image": "example:latest"})
        self.assertEqual(len([call for call in self.client.api.calls if call[0] == "pull"]), 1)
        self.assertNotIn("registry-secret", str(raised.exception))
        self.assertIn("details were redacted", str(raised.exception))

    def test_stream_deadline_is_bounded_and_closes_pull_stream(self):
        with patch.object(docker_client.time, "monotonic", side_effect=[0.0, 61.0]), self.assertRaisesRegex(
            docker_client.DockerPackError, "exceeded its 60-second timeout"
        ):
            self.execute("image_pull", {"image": "example:latest"})
        self.assertTrue(self.client.api.last_pull_stream.closed)

    def test_inspection_omits_environment_label_values_mounts_and_errors(self):
        self.client.containers.container.attrs["HostConfig"]["Binds"] = [
            "/host/secret:/container/secret"
        ]
        self.client.containers.container.attrs["Mounts"] = [{"Source": "/host/secret"}]
        result = self.execute("container_inspect", {"container": "example"})
        encoded = json.dumps(result)
        self.assertIn("TOKEN", encoded)
        self.assertIn("secret-label", encoded)
        for secret in ("container-secret", "label-secret", "/host/secret", "secret state error"):
            self.assertNotIn(secret, encoded)
        image = self.execute("image_inspect", {"image": "example:latest"})
        self.assertNotIn("do-not-return", json.dumps(image))

    def test_logs_are_non_following_and_byte_bounded(self):
        result = self.execute("container_logs", {"container": "example", "max_bytes": 10, "tail": 5})
        payload = result["result"]
        self.assertEqual(payload["bytes"], 10)
        self.assertTrue(payload["truncated"])
        kwargs = self.client.containers.container.calls[-1][1]
        self.assertFalse(kwargs["follow"])
        self.assertTrue(kwargs["stream"])
        self.assertEqual(kwargs["tail"], 5)

    def test_exec_is_argv_only_non_privileged_bounded_and_redacted(self):
        command = ["sh", "-c", "this string remains one explicit argv item"]
        result = self.execute(
            "container_exec",
            {
                "container": "example",
                "confirm": "example",
                "command": command,
                "environment": {"TOKEN": "exec-secret"},
                "timeout_seconds": 9,
            },
        )
        create_call = next(call for call in self.client.api.calls if call[0] == "exec_create")
        self.assertEqual(create_call[2], command)
        self.assertFalse(create_call[3]["privileged"])
        self.assertFalse(create_call[3]["stdin"])
        self.assertFalse(create_call[3]["tty"])
        start_call = next(call for call in self.client.api.calls if call[0] == "exec_start")
        self.assertEqual(start_call[3], 9)
        self.assertEqual(self.client.api.timeout, 60)
        self.assertNotIn("exec-secret", json.dumps(result))
        self.assertIn("[REDACTED]", result["result"]["stdout"])

    def test_entrypoint_rejects_malformed_json_without_echoing_secret(self):
        module = load_entrypoint()
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "stdin", io.StringIO('{"password":"DO_NOT_PRINT"')), redirect_stdout(
            stdout
        ), redirect_stderr(stderr):
            self.assertEqual(module.main(), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("DO_NOT_PRINT", stderr.getvalue())

    def test_no_shell_or_unsafe_deserialization_calls(self):
        forbidden = ["subprocess", "os.system", "shell=True", "pickle.loads", "yaml.load"]
        for path in [PACK_ROOT / "actions" / "docker_action.py", PACK_ROOT / "lib" / "docker_client.py"]:
            text = path.read_text(encoding="utf-8")
            self.assertFalse(any(item in text for item in forbidden), str(path))


if __name__ == "__main__":
    unittest.main()
