from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from swebench.harness.constants import (
    DOCKER_WORKDIR,
    KEY_INSTANCE_ID,
    MAP_REPO_VERSION_TO_SPECS,
    SWEbenchInstance,
)
from swebench.harness.test_spec.test_spec import TestSpec, make_test_spec


BUILD_STRATEGY = "swebench-harness"
CONDA_ENV_NAME = "testbed"
DEFAULT_OPENSHELL_BASE_IMAGE = (
    "ghcr.io/pittampalliorg/openshell-sandbox"
    "@sha256:dae398c014aeb4553844c79922d5c76c99dde04d0a6a7a9db5dd5307584a9a3b"
)


@dataclass(frozen=True)
class SwebenchEnvironmentSpecRequest:
    dataset: str | None
    instance_id: str
    repo: str
    version: str
    base_commit: str
    test_patch: str
    fail_to_pass: list[str]
    pass_to_pass: list[str]
    patch: str = ""
    problem_statement: str = ""
    hints_text: str = ""
    environment_setup_commit: str | None = None

    @classmethod
    def from_mapping(
        cls, payload: Mapping[str, Any]
    ) -> "SwebenchEnvironmentSpecRequest":
        test_metadata = _record(payload.get("testMetadata")) or _record(
            payload.get("test_metadata")
        )
        instance_id = _required_string(
            payload, "instance_id", "instanceId", "id"
        )
        repo = _required_string(payload, "repo")
        version = _metadata_string(payload, test_metadata, "version")
        base_commit = _required_string(payload, "base_commit", "baseCommit")
        test_patch = _metadata_string(
            payload, test_metadata, "test_patch", "testPatch"
        )
        return cls(
            dataset=_optional_string(payload, "dataset", "datasetName"),
            instance_id=instance_id,
            repo=repo,
            version=version,
            base_commit=base_commit,
            test_patch=test_patch,
            fail_to_pass=_metadata_list(
                payload, test_metadata, "FAIL_TO_PASS", "fail_to_pass"
            ),
            pass_to_pass=_metadata_list(
                payload, test_metadata, "PASS_TO_PASS", "pass_to_pass"
            ),
            patch=_optional_string(payload, "patch", "goldPatch") or "",
            problem_statement=_optional_string(
                payload, "problem_statement", "problemStatement"
            )
            or "",
            hints_text=_optional_string(payload, "hints_text", "hintsText", "hints")
            or "",
            environment_setup_commit=_optional_string(
                payload, "environment_setup_commit", "environmentSetupCommit"
            )
            or (
                _optional_string(
                    test_metadata or {},
                    "environment_setup_commit",
                    "environmentSetupCommit",
                )
                if test_metadata
                else None
            ),
        )

    def to_instance(self) -> SWEbenchInstance:
        instance: dict[str, Any] = {
            KEY_INSTANCE_ID: self.instance_id,
            "repo": self.repo,
            "version": self.version,
            "base_commit": self.base_commit,
            "test_patch": self.test_patch,
            "patch": self.patch,
            "problem_statement": self.problem_statement,
            "hints_text": self.hints_text,
            "FAIL_TO_PASS": self.fail_to_pass,
            "PASS_TO_PASS": self.pass_to_pass,
        }
        if self.environment_setup_commit:
            instance["environment_setup_commit"] = self.environment_setup_commit
        return instance  # type: ignore[return-value]


def is_supported_harness_spec(repo: str, version: str | None) -> bool:
    return bool(version and version in MAP_REPO_VERSION_TO_SPECS.get(repo, {}))


def generate_swebench_environment_spec(
    request: SwebenchEnvironmentSpecRequest | Mapping[str, Any],
    *,
    namespace: str | None = None,
    base_image_tag: str = "latest",
    env_image_tag: str = "latest",
    instance_image_tag: str = "latest",
    arch: str = "x86_64",
    openshell_base_image: str = DEFAULT_OPENSHELL_BASE_IMAGE,
) -> dict[str, Any]:
    if not isinstance(request, SwebenchEnvironmentSpecRequest):
        request = SwebenchEnvironmentSpecRequest.from_mapping(request)
    if not is_supported_harness_spec(request.repo, request.version):
        raise ValueError(
            f"SWE-bench harness specs do not support {request.repo}@{request.version}"
        )

    test_spec = make_test_spec(
        request.to_instance(),
        namespace=namespace,
        base_image_tag=base_image_tag,
        env_image_tag=env_image_tag,
        instance_image_tag=instance_image_tag,
        arch=arch,
    )
    specs = MAP_REPO_VERSION_TO_SPECS[request.repo][request.version]
    setup_repo_script = _adapt_setup_repo_script(test_spec.install_repo_script)
    script_hashes = {
        "setupEnvScript": _sha256(test_spec.setup_env_script),
        "setupRepoScript": _sha256(setup_repo_script),
        "evalScript": _sha256(test_spec.eval_script),
    }
    dockerfile_hashes = {
        "baseDockerfile": _sha256(test_spec.base_dockerfile),
        "envDockerfile": _sha256(test_spec.env_dockerfile),
        "instanceDockerfile": _sha256(test_spec.instance_dockerfile),
    }
    openshell_dockerfile = make_openshell_dockerfile(
        test_spec,
        openshell_base_image=openshell_base_image,
    )
    dockerfile_hashes["openshellDockerfile"] = _sha256(openshell_dockerfile)
    spec_core = {
        "buildStrategy": BUILD_STRATEGY,
        "dataset": request.dataset,
        "instanceId": request.instance_id,
        "repo": request.repo,
        "version": request.version,
        "baseCommit": request.base_commit,
        "environmentSetupCommit": request.environment_setup_commit,
        "baseImageKey": test_spec.base_image_key,
        "envImageKey": test_spec.env_image_key,
        "instanceImageKey": test_spec.instance_image_key,
        "language": test_spec.language,
        "platform": test_spec.platform,
        "pythonVersion": specs.get("python"),
        "workspaceRoot": DOCKER_WORKDIR,
        "condaEnvironment": CONDA_ENV_NAME,
        "scriptHashes": script_hashes,
        "dockerfileHashes": dockerfile_hashes,
    }
    env_spec_hash = _sha256(_stable_json(spec_core))
    return {
        **spec_core,
        "envSpecHash": env_spec_hash,
        "baseDockerfile": test_spec.base_dockerfile,
        "envDockerfile": test_spec.env_dockerfile,
        "instanceDockerfile": test_spec.instance_dockerfile,
        "openshellDockerfile": openshell_dockerfile,
        "setupEnvScript": test_spec.setup_env_script,
        "setupRepoScript": setup_repo_script,
        "evalScript": test_spec.eval_script,
        "FAIL_TO_PASS": request.fail_to_pass,
        "PASS_TO_PASS": request.pass_to_pass,
        "testPatchHash": _sha256(request.test_patch),
    }


def make_openshell_dockerfile(
    test_spec: TestSpec,
    *,
    openshell_base_image: str = DEFAULT_OPENSHELL_BASE_IMAGE,
) -> str:
    """Build a final sandbox image from SWE-bench recipes on an OpenShell base.

    Official SWE-bench images are split into base/env/instance layers. The
    OpenShell runtime needs its own base image and sandbox user, so this
    Dockerfile reuses the SWE-bench setup scripts as the dependency and repo
    source of truth while keeping the final runtime OpenShell-compatible.
    """

    upstream_base_body = _adapt_base_dockerfile_body(
        _strip_first_from(test_spec.base_dockerfile)
    ).strip()
    return "\n".join(
        [
            "# syntax=docker/dockerfile:1.7",
            "",
            f"ARG OPENSHELL_BASE_IMAGE={openshell_base_image}",
            "FROM ${OPENSHELL_BASE_IMAGE}",
            "",
            "SHELL [\"/bin/bash\", \"-lc\"]",
            "USER root",
            "",
            "# Upstream SWE-bench base image recipe, with the FROM replaced by",
            "# the OpenShell base so workspace tools and sandbox policy remain valid.",
            upstream_base_body,
            "",
            "COPY ./setup_env.sh /root/setup_env.sh",
            "COPY ./setup_repo.sh /root/setup_repo.sh",
            "RUN sed -i -e 's/\\r$//' /root/setup_env.sh /root/setup_repo.sh \\",
            " && chmod +x /root/setup_env.sh /root/setup_repo.sh",
            "RUN source ~/.bashrc && /root/setup_env.sh",
            "RUN /root/setup_repo.sh",
            "",
            "ENV CONDA_DEFAULT_ENV=testbed",
            "ENV CONDA_PREFIX=/opt/miniconda3/envs/testbed",
            "ENV CONDA_EXE=/opt/miniconda3/bin/conda",
            "ENV CONDA_PYTHON_EXE=/opt/miniconda3/bin/python",
            (
                "ENV PATH=/opt/miniconda3/envs/testbed/bin:"
                "/opt/miniconda3/condabin:/opt/miniconda3/bin:"
                "/sandbox/.venv/bin:/usr/local/sbin:/usr/local/bin:"
                "/usr/sbin:/usr/bin:/sbin:/bin"
            ),
            "RUN printf '%s\\n' \\",
            "  'if [ -f /opt/miniconda3/etc/profile.d/conda.sh ]; then' \\",
            "  '  . /opt/miniconda3/etc/profile.d/conda.sh' \\",
            "  '  conda activate testbed >/dev/null 2>&1 || true' \\",
            "  'fi' > /root/.bashrc \\",
            " && if id sandbox >/dev/null 2>&1; then \\",
            "      sandbox_home=\"$(getent passwd sandbox | cut -d: -f6)\"; \\",
            "      if [ -z \"$sandbox_home\" ]; then sandbox_home=/sandbox; fi; \\",
            "      mkdir -p \"$sandbox_home\"; \\",
            "      printf '%s\\n' \\",
            "        'export CONDA_DEFAULT_ENV=testbed' \\",
            "        'export CONDA_PREFIX=/opt/miniconda3/envs/testbed' \\",
            "        'export CONDA_EXE=/opt/miniconda3/bin/conda' \\",
            "        'export CONDA_PYTHON_EXE=/opt/miniconda3/bin/python' \\",
            "        'export PATH=/opt/miniconda3/envs/testbed/bin:/opt/miniconda3/condabin:/opt/miniconda3/bin:/sandbox/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \\",
            "        > \"$sandbox_home/.bashrc\"; \\",
            "      chown sandbox:sandbox \"$sandbox_home\" \"$sandbox_home/.bashrc\"; \\",
            "      chown -R sandbox:sandbox /testbed /opt/miniconda3/envs/testbed; \\",
            "    fi",
            "",
            "WORKDIR /testbed",
            "ENV HOME=/sandbox",
            "ENV PWD=/testbed",
            "USER sandbox",
            "WORKDIR /testbed",
            "",
        ]
    )


def write_build_context(spec: Mapping[str, Any], output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "Dockerfile": spec["openshellDockerfile"],
        "Dockerfile.base": spec["baseDockerfile"],
        "Dockerfile.env": spec["envDockerfile"],
        "Dockerfile.instance": spec["instanceDockerfile"],
        "setup_env.sh": spec["setupEnvScript"],
        "setup_repo.sh": spec["setupRepoScript"],
        "eval.sh": spec["evalScript"],
        "swebench-spec.json": json.dumps(spec, indent=2, sort_keys=True) + "\n",
    }
    for name, content in files.items():
        (out / name).write_text(str(content), encoding="utf-8")
    return out


def _strip_first_from(dockerfile: str) -> str:
    lines = dockerfile.splitlines()
    for index, line in enumerate(lines):
        if line.lstrip().upper().startswith("FROM "):
            return "\n".join(lines[:index] + lines[index + 1 :])
    return dockerfile


def _adapt_base_dockerfile_body(dockerfile_body: str) -> str:
    return dockerfile_body.replace(
        "RUN adduser --disabled-password --gecos 'dog' nonroot",
        "RUN true  # OpenShell provides the sandbox runtime user.",
    )


def _adapt_setup_repo_script(script: str) -> str:
    clone_line = re.compile(
        r"^git clone -o origin\s+(?:--branch (?P<branch>\S+)\s+)?"
        r"--single-branch\s+(?P<url>\S+)\s+(?P<dest>\S+)$"
    )
    lines: list[str] = []
    for line in script.splitlines():
        match = clone_line.match(line)
        if not match:
            lines.append(line)
            continue
        lines.extend(
            [
                f"if ! {line}; then",
                f"  rm -rf {match.group('dest')}",
                f"  git clone -o origin {match.group('url')} {match.group('dest')}",
                "fi",
            ]
        )
    return "\n".join(lines) + ("\n" if script.endswith("\n") else "")


def _required_string(payload: Mapping[str, Any], *keys: str) -> str:
    value = _optional_string(payload, *keys)
    if value:
        return value
    raise ValueError(f"Missing required field: {'/'.join(keys)}")


def _optional_string(payload: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _metadata_string(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any] | None,
    *keys: str,
) -> str:
    value = _optional_string(payload, *keys)
    if value:
        return value
    if metadata:
        value = _optional_string(metadata, *keys)
        if value:
            return value
    raise ValueError(f"Missing required SWE-bench metadata field: {'/'.join(keys)}")


def _metadata_list(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any] | None,
    *keys: str,
) -> list[str]:
    for source in (payload, metadata or {}):
        for key in keys:
            if key in source:
                return _coerce_string_list(source[key])
    return []


def _coerce_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return [item.strip() for item in raw.splitlines() if item.strip()]
        return _coerce_string_list(parsed)
    if isinstance(value, list | tuple):
        return [str(item) for item in value]
    return [str(value)]


def _record(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    return None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate SWE-bench harness/OpenShell environment specs."
    )
    parser.add_argument(
        "--input",
        "-i",
        default="-",
        help="JSON request file. Defaults to stdin.",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optional JSON output file. Defaults to stdout.",
    )
    parser.add_argument(
        "--write-build-context",
        help="Optional directory to write Dockerfile/scripts/spec artifacts.",
    )
    parser.add_argument(
        "--openshell-base-image",
        default=DEFAULT_OPENSHELL_BASE_IMAGE,
        help="OpenShell-compatible base image for the generated final Dockerfile.",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    args = parser.parse_args(argv)

    raw = sys.stdin.read() if args.input == "-" else Path(args.input).read_text()
    request = json.loads(raw)
    spec = generate_swebench_environment_spec(
        request,
        openshell_base_image=args.openshell_base_image,
    )
    if args.write_build_context:
        write_build_context(spec, args.write_build_context)
    text = json.dumps(spec, indent=2 if args.pretty else None, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
