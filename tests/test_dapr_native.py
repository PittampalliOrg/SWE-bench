import json
import subprocess

import pytest

from swebench.harness.constants import KEY_INSTANCE_ID, KEY_MODEL, KEY_PREDICTION
from swebench.harness.dapr_native import (
    InstanceResult,
    InstanceStatus,
    StartRunRequest,
    build_agent_prompt,
    build_evaluator_command,
    extract_git_diff,
    filter_instances,
    is_valid_status_transition,
    parse_report_statuses,
    patch_sha256,
    prediction_record,
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

    assert "Work only in /sandbox/repo" in prompt
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
