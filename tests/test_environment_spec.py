import json

from swebench.harness.constants import DOCKER_WORKDIR
from swebench.harness.environment_spec import (
    BUILD_STRATEGY,
    generate_swebench_environment_spec,
    is_supported_harness_spec,
    write_build_context,
)


def make_request(instance_id: str, repo: str, version: str) -> dict:
    return {
        "dataset": "SWE-bench/SWE-bench_Lite",
        "instance_id": instance_id,
        "repo": repo,
        "version": version,
        "base_commit": "abc123",
        "test_patch": "\n".join(
            [
                "diff --git a/tests/test_dummy.py b/tests/test_dummy.py",
                "--- a/tests/test_dummy.py",
                "+++ b/tests/test_dummy.py",
                "@@ -1 +1 @@",
                "-old",
                "+new",
            ]
        ),
        "FAIL_TO_PASS": ["tests/test_dummy.py::test_fix"],
        "PASS_TO_PASS": ["tests/test_dummy.py::test_existing"],
    }


def test_generates_harness_specs_for_representative_python_repos():
    cases = [
        ("django__django-13012", "django/django", "3.2"),
        ("pydata__xarray-3993", "pydata/xarray", "2024.05"),
        ("sphinx-doc__sphinx-9602", "sphinx-doc/sphinx", "7.2"),
        ("sympy__sympy-13091", "sympy/sympy", "1.7"),
    ]

    for instance_id, repo, version in cases:
        spec = generate_swebench_environment_spec(
            make_request(instance_id, repo, version)
        )

        assert spec["buildStrategy"] == BUILD_STRATEGY
        assert spec["workspaceRoot"] == DOCKER_WORKDIR == "/testbed"
        assert spec["condaEnvironment"] == "testbed"
        assert spec["language"] == "py"
        assert spec["platform"] == "linux/x86_64"
        assert spec["baseImageKey"].startswith("sweb.base.py.x86_64")
        assert spec["envImageKey"].startswith("sweb.env.py.x86_64")
        assert spec["instanceImageKey"].startswith("sweb.eval.x86_64.")
        assert spec["envSpecHash"]
        assert spec["scriptHashes"]["setupEnvScript"]
        assert spec["dockerfileHashes"]["openshellDockerfile"]
        assert "WORKDIR /testbed" in spec["openshellDockerfile"]
        assert "conda activate testbed" in spec["openshellDockerfile"]
        assert (
            "ENV PATH=/opt/miniconda3/envs/testbed/bin:/opt/miniconda3/condabin:"
            "/opt/miniconda3/bin:/sandbox/.venv/bin:/usr/local/sbin:/usr/local/bin:"
            "/usr/sbin:/usr/bin:/sbin:/bin"
        ) in spec["openshellDockerfile"]
        assert 'sandbox_home="$(getent passwd sandbox | cut -d: -f6)"' in spec[
            "openshellDockerfile"
        ]
        assert "ENV HOME=/sandbox" in spec["openshellDockerfile"]
        assert "ENV PWD=/testbed" in spec["openshellDockerfile"]
        assert "USER sandbox" in spec["openshellDockerfile"]
        assert "${PATH}" not in spec["openshellDockerfile"]


def test_xarray_uses_swebench_pinned_dependencies_not_latest_packages():
    spec = generate_swebench_environment_spec(
        make_request("pydata__xarray-3993", "pydata/xarray", "2024.05")
    )

    assert "numpy==1.23.0" in spec["setupEnvScript"]
    assert "pandas==1.5.3" in spec["setupEnvScript"]
    assert "pytest==7.4.0" in spec["setupEnvScript"]


def test_setup_repo_falls_back_when_version_ref_is_missing():
    spec = generate_swebench_environment_spec(
        make_request("sympy__sympy-13091", "sympy/sympy", "1.7")
    )

    assert "if ! git clone -o origin" in spec["setupRepoScript"]
    assert "git clone -o origin https://github.com/sympy/sympy /testbed" in spec[
        "setupRepoScript"
    ]


def test_unsupported_repo_version_is_not_a_harness_spec():
    assert is_supported_harness_spec("unknown/repo", "1.0") is False
    assert is_supported_harness_spec("sympy/sympy", None) is False


def test_write_build_context_outputs_dockerfiles_scripts_and_spec(tmp_path):
    spec = generate_swebench_environment_spec(
        make_request("sympy__sympy-13091", "sympy/sympy", "1.7")
    )

    write_build_context(spec, tmp_path)

    assert (tmp_path / "Dockerfile").read_text().startswith(
        "# syntax=docker/dockerfile:1.7"
    )
    assert (tmp_path / "setup_env.sh").read_text().startswith("#!/bin/bash")
    assert (tmp_path / "setup_repo.sh").read_text().startswith("#!/bin/bash")
    written = json.loads((tmp_path / "swebench-spec.json").read_text())
    assert written["envSpecHash"] == spec["envSpecHash"]
