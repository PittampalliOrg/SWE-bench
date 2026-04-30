import json
import subprocess
from pathlib import Path

import pytest

from swebench.harness.constants import KEY_INSTANCE_ID, KEY_MODEL, KEY_PREDICTION
from swebench.harness.dapr_native import (
    BenchmarkRunProvenance,
    InstanceResult,
    InstanceStatus,
    PredictionValidationError,
    StartRunRequest,
    build_golden_canary_run_manifest,
    build_agent_prompt,
    build_harness_result_summary,
    build_evaluator_command,
    merge_run_provenance,
    extract_git_diff,
    filter_instances,
    is_valid_status_transition,
    parse_report_statuses,
    parse_pytest_summary_counts,
    patch_sha256,
    prediction_record,
    prepare_evaluator_launch,
    require_valid_predictions_jsonl,
    summarize_raw_harness_notes,
    validate_predictions_jsonl,
    suite_dataset,
    validate_status_transition,
    write_predictions_jsonl,
)
from swebench.harness.reporting import make_run_report


def run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def test_start_run_request_accepts_camel_case_contract():
    request = StartRunRequest.from_mapping(
        {
            "suite": "verified",
            "instanceIds": ["django__django-11099"],
            "agentRef": {"id": "coding-assistant", "version": "v1"},
            "concurrency": 3,
            "timeoutSeconds": 900,
            "maxTurns": 8,
            "keepSandbox": True,
            "evaluatorResourceClass": "large",
        }
    )

    assert request.dataset_name == "SWE-bench/SWE-bench_Verified"
    assert request.split == "test"
    assert request.to_dict()["instanceIds"] == ["django__django-11099"]
    assert suite_dataset("lite") == ("SWE-bench/SWE-bench_Lite", "test")


def test_filter_instances_preserves_requested_order_and_validates_ids():
    dataset = [
        {KEY_INSTANCE_ID: "first"},
        {KEY_INSTANCE_ID: "second"},
        {KEY_INSTANCE_ID: "third"},
    ]

    assert filter_instances(dataset, ["third", "first"]) == [
        {KEY_INSTANCE_ID: "third"},
        {KEY_INSTANCE_ID: "first"},
    ]
    with pytest.raises(ValueError, match="missing"):
        filter_instances(dataset, ["missing"])


def test_build_agent_prompt_contains_sandbox_contract():
    prompt = build_agent_prompt(
        {
            KEY_INSTANCE_ID: "sympy__sympy-20590",
            "repo": "sympy/sympy",
            "base_commit": "abc123",
            "problem_statement": "Fix assumptions.",
            "hints_text": "Look at simplify.",
        },
        max_turns=5,
    )

    assert "Work only in /testbed" in prompt
    assert "conda testbed environment" in prompt
    assert "Do not reinstall project dependencies" in prompt
    assert "Do not commit" in prompt
    assert "Leave final changes in the working tree" in prompt
    assert "sympy__sympy-20590" in prompt
    assert "Max turns: 5" in prompt


def test_extract_git_diff_includes_tracked_and_untracked_files(tmp_path):
    run(["git", "init"], tmp_path)
    run(["git", "config", "user.email", "test@example.com"], tmp_path)
    run(["git", "config", "user.name", "Test User"], tmp_path)
    (tmp_path / "existing.py").write_text("value = 1\n")
    run(["git", "add", "existing.py"], tmp_path)
    run(["git", "commit", "-m", "base"], tmp_path)
    base_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        text=True,
    ).strip()

    (tmp_path / "existing.py").write_text("value = 2\n")
    (tmp_path / "new_file.py").write_text("created = True\n")

    diff = extract_git_diff(tmp_path, base_commit)

    assert "diff --git a/existing.py b/existing.py" in diff
    assert "-value = 1" in diff
    assert "+value = 2" in diff
    assert "diff --git a/new_file.py b/new_file.py" in diff
    assert "+created = True" in diff


def test_prediction_jsonl_and_patch_metadata(tmp_path):
    patch = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
    result = InstanceResult.from_patch("repo__repo-1", patch)
    predictions = [
        prediction_record("repo__repo-1", patch, "agent-v1"),
        result.to_prediction("agent-v1"),
    ]

    path = write_predictions_jsonl(predictions, tmp_path / "predictions.jsonl")
    rows = [json.loads(line) for line in path.read_text().splitlines()]

    assert rows[0][KEY_INSTANCE_ID] == "repo__repo-1"
    assert rows[0][KEY_MODEL] == "agent-v1"
    assert rows[0][KEY_PREDICTION] == patch
    assert result.patch_sha256 == patch_sha256(patch)
    assert result.patch_bytes == len(patch.encode("utf-8"))


def test_prediction_validation_accepts_empty_patch_and_valid_diff(tmp_path):
    valid_patch = "\n".join(
        [
            "diff --git a/a.py b/a.py",
            "--- a/a.py",
            "+++ b/a.py",
            "@@ -1 +1 @@",
            "-old",
            "+new",
            "",
        ]
    )
    path = write_predictions_jsonl(
        [
            prediction_record("repo__repo-1", valid_patch, "agent-v1"),
            prediction_record("repo__repo-2", "", "agent-v1"),
            prediction_record("repo__repo-3", None, "agent-v1"),
        ],
        tmp_path / "predictions.jsonl",
    )

    result = validate_predictions_jsonl(
        path,
        ["repo__repo-1", "repo__repo-2", "repo__repo-3"],
    )

    assert result.valid
    assert result.empty_patch_ids == ["repo__repo-2", "repo__repo-3"]
    assert result.predictions_sha256


def test_prediction_validation_rejects_bad_jsonl_shapes(tmp_path):
    path = tmp_path / "predictions.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        KEY_INSTANCE_ID: "repo__repo-1",
                        KEY_MODEL: "agent",
                        KEY_PREDICTION: "```diff\n--- a/a.py\n+++ b/a.py\n```",
                    }
                ),
                json.dumps(
                    {
                        KEY_INSTANCE_ID: "repo__repo-1",
                        KEY_MODEL: "agent",
                        KEY_PREDICTION: "",
                    }
                ),
                json.dumps(
                    {
                        KEY_INSTANCE_ID: "repo__repo-2",
                        KEY_PREDICTION: "not a diff",
                    }
                ),
                "{bad json",
            ]
        )
        + "\n"
    )

    result = validate_predictions_jsonl(
        path,
        ["repo__repo-1", "repo__repo-2", "repo__repo-3"],
    )

    assert not result.valid
    codes = {issue.code.value for issue in result.issues}
    assert "markdown_wrapped_diff" in codes
    assert "duplicate_instance" in codes
    assert "missing_field" in codes
    assert "missing_instance" in codes
    assert "malformed_json" in codes
    assert result.affected_instance_ids == [
        "repo__repo-1",
        "repo__repo-2",
        "repo__repo-3",
    ]
    with pytest.raises(PredictionValidationError):
        require_valid_predictions_jsonl(path, ["repo__repo-1"])


def test_parse_report_statuses_for_instance_and_aggregate_reports():
    instance_report = {
        "repo__repo-1": {"resolved": True},
        "repo__repo-2": {"resolved": False},
    }
    aggregate_report = {
        "completed_ids": ["repo__repo-1", "repo__repo-2"],
        "resolved_ids": ["repo__repo-1"],
        "unresolved_ids": ["repo__repo-2"],
        "empty_patch_ids": ["repo__repo-3"],
        "error_ids": ["repo__repo-4"],
        "incomplete_ids": ["repo__repo-5"],
    }

    assert parse_report_statuses(instance_report) == {
        "repo__repo-1": InstanceStatus.RESOLVED,
        "repo__repo-2": InstanceStatus.UNRESOLVED,
    }
    assert parse_report_statuses(aggregate_report) == {
        "repo__repo-1": InstanceStatus.RESOLVED,
        "repo__repo-2": InstanceStatus.UNRESOLVED,
        "repo__repo-3": InstanceStatus.UNRESOLVED,
        "repo__repo-4": InstanceStatus.ERROR,
        "repo__repo-5": InstanceStatus.QUEUED,
    }


def test_status_transition_validation():
    assert is_valid_status_transition("queued", "preparing")
    assert is_valid_status_transition("resolved", "resolved")
    assert not is_valid_status_transition("resolved", "evaluating")
    with pytest.raises(ValueError, match="Invalid instance status transition"):
        validate_status_transition("resolved", "evaluating")


def test_run_provenance_merge_preserves_existing_fields():
    created = "2026-04-29T00:00:00Z"
    existing = BenchmarkRunProvenance(
        run_id="run-123",
        evaluator_image="old-image",
        predictions_sha256="abc",
        environment_images={"base": {"image": "base:v1", "digest": "sha256:old"}},
        raw_notes={"instances": {"a": {"summary": "kept"}}},
        created_at=created,
    )

    merged = merge_run_provenance(
        existing,
        {
            "runId": "run-123",
            "evaluatorJobName": "job-123",
            "environmentImages": {"base": {"digest": "sha256:new"}, "env": "env:v1"},
            "rawNotes": {"instances": {"b": {"summary": "added"}}},
        },
    ).to_dict()

    assert merged["createdAt"] == created
    assert merged["evaluatorImage"] == "old-image"
    assert merged["evaluatorJobName"] == "job-123"
    assert merged["predictionsSha256"] == "abc"
    assert merged["environmentImages"]["base"] == {
        "image": "base:v1",
        "digest": "sha256:new",
    }
    assert merged["environmentImages"]["env"] == "env:v1"
    assert merged["rawNotes"]["instances"]["a"]["summary"] == "kept"
    assert merged["rawNotes"]["instances"]["b"]["summary"] == "added"


def test_raw_harness_notes_keep_official_result_authoritative(tmp_path):
    report = {
        "repo__repo-1": {
            "resolved": True,
            "tests_status": {
                "FAIL_TO_PASS": {
                    "success": ["tests/test_issue.py::test_fixed"],
                    "failure": [],
                },
                "PASS_TO_PASS": {
                    "success": ["tests/test_existing.py::test_still_passes"],
                    "failure": [],
                },
            },
        }
    }
    test_output = "\n".join(
        [
            "FAILED tests/test_issue.py::test_fixed - old failure",
            "ERROR tests/test_ungraded.py::test_extra - RuntimeError",
            "===== 1 failed, 1 passed, 1 error in 1.23s =====",
        ]
    )
    test_output_path = tmp_path / "test_output.txt"
    test_output_path.write_text(test_output)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report))

    notes = summarize_raw_harness_notes(report["repo__repo-1"], test_output)
    summary = build_harness_result_summary(
        report_path,
        report_path=report_path,
        test_output_path=test_output_path,
    )

    assert parse_pytest_summary_counts(test_output) == {
        "failed": 1,
        "passed": 1,
        "errors": 1,
    }
    assert notes["ungradedPytestEvents"] == [
        {"status": "error", "nodeid": "tests/test_ungraded.py::test_extra"}
    ]
    instance_summary = summary["instances"]["repo__repo-1"]
    assert instance_summary["officialResult"] == "resolved"
    assert instance_summary["resolved"] is True
    assert instance_summary["rawHarnessNotes"]["summary"].startswith(
        "Raw pytest output contains 1"
    )


def test_build_evaluator_command_uses_official_harness_entrypoint():
    command = build_evaluator_command(
        predictions_path="/artifacts/predictions.jsonl",
        run_id="run-123",
        suite="verified",
        instance_ids=["django__django-11099"],
        timeout_seconds=120,
        max_workers=2,
        report_dir="/artifacts",
    )

    assert command[:3] == ["python", "-m", "swebench.harness.run_evaluation"]
    assert "SWE-bench/SWE-bench_Verified" in command
    assert command[command.index("--instance_ids") + 1 :] == ["django__django-11099"]
    assert command[command.index("--report_dir") + 1] == "/artifacts"


def test_prepare_evaluator_launch_validates_predictions_and_records_provenance(tmp_path):
    patch = "\n".join(
        [
            "diff --git a/a.py b/a.py",
            "--- a/a.py",
            "+++ b/a.py",
            "@@ -1 +1 @@",
            "-old",
            "+new",
            "",
        ]
    )
    predictions_path = write_predictions_jsonl(
        [prediction_record("repo__repo-1", patch, "agent-v1")],
        tmp_path / "predictions.jsonl",
    )

    launch = prepare_evaluator_launch(
        predictions_path=predictions_path,
        run_id="run-123",
        suite="verified",
        instance_ids=["repo__repo-1"],
        timeout_seconds=120,
        max_workers=2,
        resource_class="large",
        evaluator_image="swebench-evaluator:v1",
    )

    assert launch["validation"]["valid"] is True
    assert launch["provenance"]["evaluatorImage"] == "swebench-evaluator:v1"
    assert launch["provenance"]["resourceClass"] == "large"
    assert launch["provenance"]["maxWorkers"] == 2
    assert launch["provenance"]["timeoutSeconds"] == 120
    assert launch["provenance"]["predictionsSha256"] == patch_sha256(
        predictions_path.read_text()
    )
    assert launch["command"][:3] == ["python", "-m", "swebench.harness.run_evaluation"]


def test_golden_canary_manifest_writes_machine_readable_artifacts(tmp_path):
    instances = [
        {
            KEY_INSTANCE_ID: "django__django-11099",
            "patch": "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-a\n+b\n",
        },
        {KEY_INSTANCE_ID: "sympy__sympy-20590", "patch": "unused"},
    ]

    manifest = build_golden_canary_run_manifest(
        suite="verified",
        agent="agent-v1",
        project_id="project-1",
        user_id="user-1",
        artifact_dir=tmp_path,
        run_id="run-123",
        instances=instances,
    )

    assert manifest["runId"] == "run-123"
    assert manifest["coordinatorExecutionId"] == "swebench-golden-canary-run-123"
    assert manifest["selectedInstanceIds"] == [
        "django__django-11099",
        "sympy__sympy-20590",
    ]
    assert Path(manifest["artifactPaths"]["predictions"]).exists()
    assert Path(manifest["artifactPaths"]["provenance"]).exists()
    rows = [
        json.loads(line)
        for line in Path(manifest["artifactPaths"]["predictions"]).read_text().splitlines()
    ]
    assert rows[0][KEY_PREDICTION].startswith("diff --git")
    assert rows[1][KEY_PREDICTION] == ""


def test_make_run_report_honors_report_dir(tmp_path):
    output_path = make_run_report(
        {
            "repo__repo-1": {
                KEY_INSTANCE_ID: "repo__repo-1",
                KEY_MODEL: "agent/v1",
                KEY_PREDICTION: "",
            }
        },
        [{KEY_INSTANCE_ID: "repo__repo-1"}],
        "run-123",
        client=None,
        report_dir=tmp_path / "reports",
    )

    assert output_path == tmp_path / "reports" / "agent__v1.run-123.json"
    report = json.loads(output_path.read_text())
    assert report["empty_patch_ids"] == ["repo__repo-1"]
