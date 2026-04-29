from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from swebench.harness.constants import (
    KEY_INSTANCE_ID,
    KEY_MODEL,
    KEY_PREDICTION,
    SWEbenchInstance,
    UTF8,
)
from swebench.harness.utils import load_swebench_dataset


class SwebenchSuite(str, Enum):
    LITE = "lite"
    VERIFIED = "verified"


SUITE_DATASETS: dict[SwebenchSuite, tuple[str, str]] = {
    SwebenchSuite.LITE: ("SWE-bench/SWE-bench_Lite", "test"),
    SwebenchSuite.VERIFIED: ("SWE-bench/SWE-bench_Verified", "test"),
}

SUITE_ALIASES = {
    "lite": SwebenchSuite.LITE,
    "swe-bench-lite": SwebenchSuite.LITE,
    "swebench-lite": SwebenchSuite.LITE,
    "swe_bench_lite": SwebenchSuite.LITE,
    "verified": SwebenchSuite.VERIFIED,
    "swe-bench-verified": SwebenchSuite.VERIFIED,
    "swebench-verified": SwebenchSuite.VERIFIED,
    "swe_bench_verified": SwebenchSuite.VERIFIED,
}


class InstanceStatus(str, Enum):
    QUEUED = "queued"
    PREPARING = "preparing"
    INFERENCING = "inferencing"
    PATCH_EXTRACTED = "patch_extracted"
    EVALUATING = "evaluating"
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


TERMINAL_STATUSES = {
    InstanceStatus.RESOLVED,
    InstanceStatus.UNRESOLVED,
    InstanceStatus.ERROR,
    InstanceStatus.TIMEOUT,
    InstanceStatus.CANCELLED,
}

VALID_STATUS_TRANSITIONS: dict[InstanceStatus, set[InstanceStatus]] = {
    InstanceStatus.QUEUED: {
        InstanceStatus.PREPARING,
        InstanceStatus.CANCELLED,
    },
    InstanceStatus.PREPARING: {
        InstanceStatus.INFERENCING,
        InstanceStatus.ERROR,
        InstanceStatus.TIMEOUT,
        InstanceStatus.CANCELLED,
    },
    InstanceStatus.INFERENCING: {
        InstanceStatus.PATCH_EXTRACTED,
        InstanceStatus.ERROR,
        InstanceStatus.TIMEOUT,
        InstanceStatus.CANCELLED,
    },
    InstanceStatus.PATCH_EXTRACTED: {
        InstanceStatus.EVALUATING,
        InstanceStatus.ERROR,
        InstanceStatus.CANCELLED,
    },
    InstanceStatus.EVALUATING: {
        InstanceStatus.RESOLVED,
        InstanceStatus.UNRESOLVED,
        InstanceStatus.ERROR,
        InstanceStatus.TIMEOUT,
        InstanceStatus.CANCELLED,
    },
    InstanceStatus.RESOLVED: set(),
    InstanceStatus.UNRESOLVED: set(),
    InstanceStatus.ERROR: set(),
    InstanceStatus.TIMEOUT: set(),
    InstanceStatus.CANCELLED: set(),
}


def normalize_suite(suite: SwebenchSuite | str) -> SwebenchSuite:
    if isinstance(suite, SwebenchSuite):
        return suite
    key = suite.strip().lower().replace("_", "-")
    if key not in SUITE_ALIASES:
        valid = ", ".join(sorted(SUITE_ALIASES))
        raise ValueError(f"Unknown SWE-bench suite {suite!r}. Valid aliases: {valid}")
    return SUITE_ALIASES[key]


def normalize_status(status: InstanceStatus | str) -> InstanceStatus:
    if isinstance(status, InstanceStatus):
        return status
    try:
        return InstanceStatus(status)
    except ValueError as exc:
        valid = ", ".join(s.value for s in InstanceStatus)
        raise ValueError(f"Unknown instance status {status!r}. Valid: {valid}") from exc


def suite_dataset(suite: SwebenchSuite | str) -> tuple[str, str]:
    return SUITE_DATASETS[normalize_suite(suite)]


@dataclass
class StartRunRequest:
    suite: SwebenchSuite | str
    instance_ids: list[str] = field(default_factory=list)
    agent_ref: str | Mapping[str, Any] | None = None
    concurrency: int = 1
    timeout_seconds: int = 1800
    max_turns: int | None = None
    keep_sandbox: bool = False
    evaluator_resource_class: str = "standard"

    def __post_init__(self) -> None:
        self.suite = normalize_suite(self.suite)
        self.instance_ids = list(self.instance_ids or [])
        if self.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be >= 1")
        if self.max_turns is not None and self.max_turns < 1:
            raise ValueError("max_turns must be >= 1 when provided")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> StartRunRequest:
        return cls(
            suite=data["suite"],
            instance_ids=list(data.get("instanceIds", data.get("instance_ids", []))),
            agent_ref=data.get("agentRef", data.get("agent_ref")),
            concurrency=int(data.get("concurrency", 1)),
            timeout_seconds=int(
                data.get("timeoutSeconds", data.get("timeout_seconds", 1800))
            ),
            max_turns=data.get("maxTurns", data.get("max_turns")),
            keep_sandbox=bool(data.get("keepSandbox", data.get("keep_sandbox", False))),
            evaluator_resource_class=data.get(
                "evaluatorResourceClass",
                data.get("evaluator_resource_class", "standard"),
            ),
        )

    @property
    def dataset_name(self) -> str:
        return suite_dataset(self.suite)[0]

    @property
    def split(self) -> str:
        return suite_dataset(self.suite)[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": normalize_suite(self.suite).value,
            "instanceIds": list(self.instance_ids),
            "agentRef": self.agent_ref,
            "concurrency": self.concurrency,
            "timeoutSeconds": self.timeout_seconds,
            "maxTurns": self.max_turns,
            "keepSandbox": self.keep_sandbox,
            "evaluatorResourceClass": self.evaluator_resource_class,
        }


@dataclass
class InstanceResult:
    instance_id: str
    status: InstanceStatus | str = InstanceStatus.QUEUED
    model_patch: str | None = None
    patch_sha256: str | None = None
    patch_bytes: int = 0
    session_id: str | None = None
    workflow_execution_id: str | None = None
    dapr_instance_id: str | None = None
    workspace_ref: str | Mapping[str, Any] | None = None
    report_path: str | None = None
    test_output_path: str | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        self.status = normalize_status(self.status)
        if self.model_patch is not None:
            if self.patch_sha256 is None:
                self.patch_sha256 = patch_sha256(self.model_patch)
            if self.patch_bytes == 0:
                self.patch_bytes = len(self.model_patch.encode(UTF8))

    @classmethod
    def from_patch(
        cls,
        instance_id: str,
        model_patch: str,
        **kwargs: Any,
    ) -> InstanceResult:
        return cls(
            instance_id=instance_id,
            status=InstanceStatus.PATCH_EXTRACTED,
            model_patch=model_patch,
            **kwargs,
        )

    def to_prediction(self, model_name_or_path: str) -> dict[str, str]:
        return prediction_record(
            self.instance_id,
            self.model_patch or "",
            model_name_or_path,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "instanceId": self.instance_id,
            "status": normalize_status(self.status).value,
            "modelPatch": self.model_patch,
            "patchSha256": self.patch_sha256,
            "patchBytes": self.patch_bytes,
            "sessionId": self.session_id,
            "workflowExecutionId": self.workflow_execution_id,
            "daprInstanceId": self.dapr_instance_id,
            "workspaceRef": self.workspace_ref,
            "reportPath": self.report_path,
            "testOutputPath": self.test_output_path,
            "error": self.error,
        }


def is_valid_status_transition(
    current: InstanceStatus | str,
    target: InstanceStatus | str,
) -> bool:
    current_status = normalize_status(current)
    target_status = normalize_status(target)
    if current_status == target_status:
        return True
    return target_status in VALID_STATUS_TRANSITIONS[current_status]


def validate_status_transition(
    current: InstanceStatus | str,
    target: InstanceStatus | str,
) -> None:
    if not is_valid_status_transition(current, target):
        raise ValueError(f"Invalid instance status transition: {current} -> {target}")


def filter_instances(
    instances: Iterable[Mapping[str, Any]],
    instance_ids: Sequence[str] | None = None,
) -> list[Mapping[str, Any]]:
    instances = list(instances)
    if not instance_ids:
        return instances
    by_id = {instance[KEY_INSTANCE_ID]: instance for instance in instances}
    missing = [instance_id for instance_id in instance_ids if instance_id not in by_id]
    if missing:
        raise ValueError(f"Instance IDs not found in dataset: {' '.join(missing)}")
    return [by_id[instance_id] for instance_id in instance_ids]


def load_suite_instances(
    suite: SwebenchSuite | str,
    instance_ids: Sequence[str] | None = None,
) -> list[SWEbenchInstance]:
    dataset_name, split = suite_dataset(suite)
    dataset = load_swebench_dataset(dataset_name, split)
    return [dict(instance) for instance in filter_instances(dataset, instance_ids)]


def build_agent_prompt(
    instance: Mapping[str, Any],
    *,
    workspace: str = "/testbed",
    max_turns: int | None = None,
) -> str:
    hints = (instance.get("hints_text") or "").strip()
    max_turns_line = f"\nMax turns: {max_turns}" if max_turns is not None else ""
    hints_section = f"\nHints:\n{hints}\n" if hints else ""
    return (
        "You are solving a SWE-bench task inside an OpenShell sandbox.\n\n"
        "Contract:\n"
        f"- Work only in {workspace}.\n"
        "- The repository is already checked out and prepared there.\n"
        "- Dependencies are installed from the SWE-bench harness spec in the conda testbed environment.\n"
        "- Do not reinstall project dependencies unless the issue explicitly requires it.\n"
        "- Do not commit.\n"
        "- Make minimal source changes that address the issue.\n"
        "- Do not modify setup, test, or benchmark metadata files unless required by the issue.\n"
        "- Leave final changes in the working tree.\n"
        "- The workflow will extract the diff after you finish.\n\n"
        f"Repository: {instance.get('repo')}\n"
        f"Base commit: {instance.get('base_commit')}\n"
        f"Instance ID: {instance.get(KEY_INSTANCE_ID)}"
        f"{max_turns_line}\n\n"
        "Problem statement:\n"
        f"{instance.get('problem_statement', '').strip()}\n"
        f"{hints_section}"
    )


def _git(repo_path: Path, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "git command failed: "
            f"git -C {repo_path} {' '.join(args)}\n{result.stderr.strip()}"
        )
    return result


def _mark_untracked_for_diff(repo_path: Path) -> None:
    result = _git(repo_path, ["ls-files", "--others", "--exclude-standard", "-z"])
    untracked_paths = [path for path in result.stdout.split("\0") if path]
    if untracked_paths:
        _git(repo_path, ["add", "--intent-to-add", "--", *untracked_paths])


def extract_git_diff(
    repo_path: str | Path,
    base_commit: str = "HEAD",
    *,
    include_untracked: bool = True,
) -> str:
    repo = Path(repo_path)
    if include_untracked:
        _mark_untracked_for_diff(repo)
    result = _git(
        repo,
        [
            "-c",
            "core.fileMode=false",
            "diff",
            "--binary",
            base_commit,
            "--",
        ],
    )
    return result.stdout


def patch_sha256(model_patch: str) -> str:
    return hashlib.sha256(model_patch.encode(UTF8)).hexdigest()


def prediction_record(
    instance_id: str,
    model_patch: str,
    model_name_or_path: str,
) -> dict[str, str]:
    return {
        KEY_INSTANCE_ID: instance_id,
        KEY_MODEL: model_name_or_path,
        KEY_PREDICTION: model_patch,
    }


def predictions_from_results(
    results: Iterable[InstanceResult],
    model_name_or_path: str,
) -> list[dict[str, str]]:
    return [result.to_prediction(model_name_or_path) for result in results]


def write_predictions_jsonl(
    predictions: Iterable[Mapping[str, Any]],
    path: str | Path,
) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        for prediction in predictions:
            f.write(json.dumps(dict(prediction), sort_keys=True) + "\n")
    return output_path


def _load_report(report: str | Path | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(report, Mapping):
        return report
    return json.loads(Path(report).read_text())


def parse_report_statuses(
    report: str | Path | Mapping[str, Any],
) -> dict[str, InstanceStatus]:
    content = _load_report(report)
    if "resolved_ids" in content or "unresolved_ids" in content:
        return parse_aggregate_report_statuses(content)
    return parse_instance_report_statuses(content)


def parse_instance_report_statuses(
    report: str | Path | Mapping[str, Any],
) -> dict[str, InstanceStatus]:
    content = _load_report(report)
    statuses = {}
    for instance_id, instance_report in content.items():
        if not isinstance(instance_report, Mapping):
            raise ValueError(f"Invalid report payload for instance {instance_id}")
        statuses[instance_id] = (
            InstanceStatus.RESOLVED
            if instance_report.get("resolved") is True
            else InstanceStatus.UNRESOLVED
        )
    return statuses


def parse_aggregate_report_statuses(
    report: str | Path | Mapping[str, Any],
) -> dict[str, InstanceStatus]:
    content = _load_report(report)
    statuses: dict[str, InstanceStatus] = {}
    for instance_id in content.get("completed_ids", []):
        statuses[instance_id] = InstanceStatus.UNRESOLVED
    for instance_id in content.get("unresolved_ids", []):
        statuses[instance_id] = InstanceStatus.UNRESOLVED
    for instance_id in content.get("empty_patch_ids", []):
        statuses[instance_id] = InstanceStatus.UNRESOLVED
    for instance_id in content.get("resolved_ids", []):
        statuses[instance_id] = InstanceStatus.RESOLVED
    for instance_id in content.get("incomplete_ids", []):
        statuses.setdefault(instance_id, InstanceStatus.QUEUED)
    for instance_id in content.get("error_ids", []):
        statuses[instance_id] = InstanceStatus.ERROR
    return statuses


def build_evaluator_command(
    *,
    predictions_path: str | Path,
    run_id: str,
    suite: SwebenchSuite | str = SwebenchSuite.LITE,
    instance_ids: Sequence[str] | None = None,
    timeout_seconds: int = 1800,
    max_workers: int = 1,
    report_dir: str | Path = "/artifacts",
    dataset_name: str | None = None,
    split: str | None = None,
) -> list[str]:
    resolved_dataset_name, resolved_split = suite_dataset(suite)
    dataset_name = dataset_name or resolved_dataset_name
    split = split or resolved_split
    command = [
        "python",
        "-m",
        "swebench.harness.run_evaluation",
        "--dataset_name",
        dataset_name,
        "--split",
        split,
        "--predictions_path",
        str(predictions_path),
        "--run_id",
        run_id,
        "--timeout",
        str(timeout_seconds),
        "--max_workers",
        str(max_workers),
        "--report_dir",
        str(report_dir),
    ]
    if instance_ids:
        command.extend(["--instance_ids", *instance_ids])
    return command
