from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from swebench.harness.constants import (
    FAIL_TO_PASS,
    KEY_INSTANCE_ID,
    KEY_MODEL,
    KEY_PREDICTION,
    PASS_TO_PASS,
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

DEFAULT_GOLDEN_CANARY_INSTANCE_IDS: dict[SwebenchSuite, tuple[str, str]] = {
    SwebenchSuite.LITE: ("django__django-11099", "sympy__sympy-20590"),
    SwebenchSuite.VERIFIED: ("django__django-11099", "sympy__sympy-20590"),
}


BENCHMARK_RUN_PROVENANCE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS benchmark_run_provenance (
    run_id TEXT PRIMARY KEY,
    evaluator_image TEXT,
    evaluator_image_digest TEXT,
    evaluator_job_name TEXT,
    resource_class TEXT,
    max_workers INTEGER,
    timeout_seconds INTEGER,
    deadline_seconds INTEGER,
    dataset_path TEXT,
    dataset_sha256 TEXT,
    predictions_path TEXT,
    predictions_sha256 TEXT,
    harness_args JSONB,
    harness_report_path TEXT,
    stdout_path TEXT,
    stderr_path TEXT,
    environment_images JSONB,
    raw_notes JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _first_present(data: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _drop_none(data: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}


def _merge_json_value(existing: Any, update: Any) -> Any:
    if update is None:
        return existing
    if isinstance(existing, Mapping) and isinstance(update, Mapping):
        merged = dict(existing)
        for key, value in update.items():
            if value is None:
                continue
            merged[key] = _merge_json_value(merged.get(key), value)
        return merged
    return update


@dataclass
class BenchmarkRunProvenance:
    run_id: str
    evaluator_image: str | None = None
    evaluator_image_digest: str | None = None
    evaluator_job_name: str | None = None
    resource_class: str | None = None
    max_workers: int | None = None
    timeout_seconds: int | None = None
    deadline_seconds: int | None = None
    dataset_path: str | None = None
    dataset_sha256: str | None = None
    predictions_path: str | None = None
    predictions_sha256: str | None = None
    harness_args: list[str] | dict[str, Any] | None = None
    harness_report_path: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    environment_images: Mapping[str, Any] | None = None
    raw_notes: Mapping[str, Any] | None = None
    created_at: str | None = None
    updated_at: str | None = None

    def __post_init__(self) -> None:
        if not self.run_id:
            raise ValueError("run_id is required")
        now = utc_now_iso()
        if self.created_at is None:
            self.created_at = now
        if self.updated_at is None:
            self.updated_at = now

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> BenchmarkRunProvenance:
        run_id = _first_present(data, "runId", "run_id")
        if not run_id:
            raise ValueError("runId is required")
        return cls(
            run_id=str(run_id),
            evaluator_image=_first_present(
                data, "evaluatorImage", "evaluator_image"
            ),
            evaluator_image_digest=_first_present(
                data, "evaluatorImageDigest", "evaluator_image_digest"
            ),
            evaluator_job_name=_first_present(
                data, "evaluatorJobName", "evaluator_job_name"
            ),
            resource_class=_first_present(data, "resourceClass", "resource_class"),
            max_workers=_first_present(data, "maxWorkers", "max_workers"),
            timeout_seconds=_first_present(
                data, "timeoutSeconds", "timeout_seconds"
            ),
            deadline_seconds=_first_present(
                data, "deadlineSeconds", "deadline_seconds"
            ),
            dataset_path=_first_present(data, "datasetPath", "dataset_path"),
            dataset_sha256=_first_present(data, "datasetSha256", "dataset_sha256"),
            predictions_path=_first_present(
                data, "predictionsPath", "predictions_path"
            ),
            predictions_sha256=_first_present(
                data, "predictionsSha256", "predictions_sha256"
            ),
            harness_args=_first_present(data, "harnessArgs", "harness_args"),
            harness_report_path=_first_present(
                data, "harnessReportPath", "harness_report_path", "reportPath"
            ),
            stdout_path=_first_present(data, "stdoutPath", "stdout_path"),
            stderr_path=_first_present(data, "stderrPath", "stderr_path"),
            environment_images=_first_present(
                data, "environmentImages", "environment_images"
            ),
            raw_notes=_first_present(data, "rawNotes", "raw_notes"),
            created_at=_first_present(data, "createdAt", "created_at"),
            updated_at=_first_present(data, "updatedAt", "updated_at"),
        )

    def to_dict(self, *, include_none: bool = False) -> dict[str, Any]:
        data = {
            "runId": self.run_id,
            "evaluatorImage": self.evaluator_image,
            "evaluatorImageDigest": self.evaluator_image_digest,
            "evaluatorJobName": self.evaluator_job_name,
            "resourceClass": self.resource_class,
            "maxWorkers": self.max_workers,
            "timeoutSeconds": self.timeout_seconds,
            "deadlineSeconds": self.deadline_seconds,
            "datasetPath": self.dataset_path,
            "datasetSha256": self.dataset_sha256,
            "predictionsPath": self.predictions_path,
            "predictionsSha256": self.predictions_sha256,
            "harnessArgs": self.harness_args,
            "harnessReportPath": self.harness_report_path,
            "stdoutPath": self.stdout_path,
            "stderrPath": self.stderr_path,
            "environmentImages": self.environment_images,
            "rawNotes": self.raw_notes,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }
        return data if include_none else _drop_none(data)


def merge_run_provenance(
    existing: BenchmarkRunProvenance | Mapping[str, Any] | None,
    update: BenchmarkRunProvenance | Mapping[str, Any],
) -> BenchmarkRunProvenance:
    if existing is None:
        existing_dict: dict[str, Any] = {}
    elif isinstance(existing, BenchmarkRunProvenance):
        existing_dict = existing.to_dict(include_none=True)
    else:
        existing_dict = BenchmarkRunProvenance.from_mapping(existing).to_dict(
            include_none=True
        )

    update_dict = (
        update.to_dict(include_none=True)
        if isinstance(update, BenchmarkRunProvenance)
        else BenchmarkRunProvenance.from_mapping(update).to_dict(include_none=True)
    )

    run_id = existing_dict.get("runId") or update_dict.get("runId")
    if existing_dict.get("runId") and update_dict.get("runId") != existing_dict["runId"]:
        raise ValueError(
            f"Cannot merge provenance for different runs: {existing_dict['runId']} "
            f"!= {update_dict.get('runId')}"
        )

    merged = dict(existing_dict)
    for key, value in update_dict.items():
        if key == "createdAt" and merged.get("createdAt"):
            continue
        if value is None:
            continue
        if key in {"environmentImages", "rawNotes"}:
            merged[key] = _merge_json_value(merged.get(key), value)
        else:
            merged[key] = value
    merged["runId"] = run_id
    merged["updatedAt"] = update_dict.get("updatedAt") or utc_now_iso()
    return BenchmarkRunProvenance.from_mapping(merged)


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
    stdout_path: str | None = None
    stderr_path: str | None = None
    test_output_path: str | None = None
    harness_result: Mapping[str, Any] | None = None
    test_output_summary: Mapping[str, Any] | None = None
    raw_harness_notes: Mapping[str, Any] | None = None
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
            "stdoutPath": self.stdout_path,
            "stderrPath": self.stderr_path,
            "testOutputPath": self.test_output_path,
            "harnessResult": self.harness_result,
            "testOutputSummary": self.test_output_summary,
            "rawHarnessNotes": self.raw_harness_notes,
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


class PredictionValidationCode(str, Enum):
    MISSING_FILE = "missing_file"
    MALFORMED_JSON = "malformed_json"
    ROW_NOT_OBJECT = "row_not_object"
    MISSING_FIELD = "missing_field"
    INVALID_FIELD = "invalid_field"
    DUPLICATE_INSTANCE = "duplicate_instance"
    MISSING_INSTANCE = "missing_instance"
    UNSELECTED_INSTANCE = "unselected_instance"
    MARKDOWN_WRAPPED_DIFF = "markdown_wrapped_diff"
    MALFORMED_DIFF = "malformed_diff"


@dataclass
class PredictionValidationIssue:
    code: PredictionValidationCode | str
    message: str
    instance_id: str | None = None
    line_number: int | None = None

    def __post_init__(self) -> None:
        if isinstance(self.code, PredictionValidationCode):
            return
        self.code = PredictionValidationCode(self.code)

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "code": self.code.value,
                "message": self.message,
                "instanceId": self.instance_id,
                "lineNumber": self.line_number,
            }
        )


@dataclass
class PredictionValidationResult:
    predictions_path: str
    selected_instance_ids: list[str]
    rows: list[Mapping[str, Any]] = field(default_factory=list)
    issues: list[PredictionValidationIssue] = field(default_factory=list)
    empty_patch_ids: list[str] = field(default_factory=list)
    predictions_sha256: str | None = None

    @property
    def valid(self) -> bool:
        return not self.issues

    @property
    def affected_instance_ids(self) -> list[str]:
        ids = {
            issue.instance_id
            for issue in self.issues
            if issue.instance_id is not None
        }
        return sorted(ids)

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "valid": self.valid,
                "predictionsPath": self.predictions_path,
                "predictionsSha256": self.predictions_sha256,
                "selectedInstanceIds": list(self.selected_instance_ids),
                "emptyPatchIds": list(self.empty_patch_ids),
                "affectedInstanceIds": self.affected_instance_ids,
                "issues": [issue.to_dict() for issue in self.issues],
                "rowCount": len(self.rows),
            }
        )


class PredictionValidationError(ValueError):
    def __init__(self, result: PredictionValidationResult):
        self.result = result
        issue_summary = "; ".join(issue.message for issue in result.issues[:3])
        if len(result.issues) > 3:
            issue_summary += f"; {len(result.issues) - 3} more issue(s)"
        super().__init__(f"Invalid predictions JSONL: {issue_summary}")


def _is_empty_patch(model_patch: Any) -> bool:
    return model_patch is None or (
        isinstance(model_patch, str) and model_patch.strip() == ""
    )


def validate_model_patch_diff(model_patch: str | None) -> tuple[bool, str | None]:
    if _is_empty_patch(model_patch):
        return True, None
    if not isinstance(model_patch, str):
        return False, "model_patch must be a string or null"

    text = model_patch.strip()
    if re.search(r"(?m)^\s*```", text):
        return False, "model_patch must be a raw diff, not markdown fenced content"

    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return True, None
    first_line = lines[0]

    has_unified_header = any(line.startswith("--- ") for line in lines) and any(
        line.startswith("+++ ") for line in lines
    )
    has_hunk = any(line.startswith("@@ ") or line.startswith("@@") for line in lines)
    has_binary_marker = any(
        line.startswith("GIT binary patch") or line.startswith("Binary files ")
        for line in lines
    )
    has_metadata_only_change = any(
        line.startswith(
            (
                "old mode ",
                "new mode ",
                "deleted file mode ",
                "new file mode ",
                "rename from ",
                "rename to ",
                "copy from ",
                "copy to ",
            )
        )
        for line in lines
    )

    if first_line.startswith("diff --git "):
        if not (
            has_binary_marker
            or has_metadata_only_change
            or (has_unified_header and has_hunk)
        ):
            return (
                False,
                "git diff patches must include file headers and at least one hunk "
                "or binary/metadata marker",
            )
        return True, None
    if first_line.startswith("--- "):
        if has_unified_header and has_hunk:
            return True, None
        return False, "unified diffs must include ---/+++ headers and a hunk"
    return (
        False,
        "model_patch must start with a git diff or unified diff header",
    )


def validate_predictions_jsonl(
    predictions_path: str | Path,
    selected_instance_ids: Sequence[str] | None = None,
    *,
    allow_extra_instances: bool = True,
) -> PredictionValidationResult:
    path = Path(predictions_path)
    selected_ids = list(selected_instance_ids or [])
    selected_set = set(selected_ids)
    result = PredictionValidationResult(
        predictions_path=str(path),
        selected_instance_ids=selected_ids,
        predictions_sha256=file_sha256(path) if path.exists() else None,
    )
    rows_by_instance: dict[str, list[int]] = {}

    if not path.is_file():
        result.issues.append(
            PredictionValidationIssue(
                PredictionValidationCode.MISSING_FILE,
                f"Predictions JSONL file does not exist: {path}",
            )
        )
        return result

    with path.open() as f:
        for line_number, raw_line in enumerate(f, start=1):
            if raw_line.strip() == "":
                result.issues.append(
                    PredictionValidationIssue(
                        PredictionValidationCode.MALFORMED_JSON,
                        "Blank lines are not valid prediction JSONL rows",
                        line_number=line_number,
                    )
                )
                continue
            try:
                row = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                result.issues.append(
                    PredictionValidationIssue(
                        PredictionValidationCode.MALFORMED_JSON,
                        f"Line {line_number} is not valid JSON: {exc.msg}",
                        line_number=line_number,
                    )
                )
                continue
            if not isinstance(row, Mapping):
                result.issues.append(
                    PredictionValidationIssue(
                        PredictionValidationCode.ROW_NOT_OBJECT,
                        f"Line {line_number} must be a JSON object",
                        line_number=line_number,
                    )
                )
                continue

            result.rows.append(row)
            instance_id = row.get(KEY_INSTANCE_ID)
            if not isinstance(instance_id, str) or not instance_id.strip():
                result.issues.append(
                    PredictionValidationIssue(
                        PredictionValidationCode.MISSING_FIELD,
                        "Prediction row requires a non-empty instance_id",
                        line_number=line_number,
                    )
                )
                continue
            rows_by_instance.setdefault(instance_id, []).append(line_number)

            if selected_set and instance_id not in selected_set:
                if not allow_extra_instances:
                    result.issues.append(
                        PredictionValidationIssue(
                            PredictionValidationCode.UNSELECTED_INSTANCE,
                            f"Prediction row is not selected for this run: {instance_id}",
                            instance_id=instance_id,
                            line_number=line_number,
                        )
                    )
                continue

            model_name = row.get(KEY_MODEL)
            if not isinstance(model_name, str) or not model_name.strip():
                result.issues.append(
                    PredictionValidationIssue(
                        PredictionValidationCode.MISSING_FIELD,
                        f"{instance_id} requires a non-empty {KEY_MODEL}",
                        instance_id=instance_id,
                        line_number=line_number,
                    )
                )
            if KEY_PREDICTION not in row:
                result.issues.append(
                    PredictionValidationIssue(
                        PredictionValidationCode.MISSING_FIELD,
                        f"{instance_id} requires {KEY_PREDICTION}",
                        instance_id=instance_id,
                        line_number=line_number,
                    )
                )
                continue

            patch = row.get(KEY_PREDICTION)
            if _is_empty_patch(patch):
                result.empty_patch_ids.append(instance_id)
                continue
            is_valid_patch, message = validate_model_patch_diff(patch)
            if is_valid_patch:
                continue
            code = (
                PredictionValidationCode.MARKDOWN_WRAPPED_DIFF
                if isinstance(patch, str) and "```" in patch
                else PredictionValidationCode.MALFORMED_DIFF
            )
            result.issues.append(
                PredictionValidationIssue(
                    code,
                    f"{instance_id} has invalid model_patch: {message}",
                    instance_id=instance_id,
                    line_number=line_number,
                )
            )

    ids_to_check = selected_ids or list(rows_by_instance)
    for instance_id in ids_to_check:
        line_numbers = rows_by_instance.get(instance_id, [])
        if not line_numbers:
            result.issues.append(
                PredictionValidationIssue(
                    PredictionValidationCode.MISSING_INSTANCE,
                    f"Missing prediction row for selected instance {instance_id}",
                    instance_id=instance_id,
                )
            )
        elif len(line_numbers) > 1:
            result.issues.append(
                PredictionValidationIssue(
                    PredictionValidationCode.DUPLICATE_INSTANCE,
                    f"Expected one prediction row for {instance_id}, found "
                    f"{len(line_numbers)}",
                    instance_id=instance_id,
                    line_number=line_numbers[-1],
                )
            )
    result.empty_patch_ids = sorted(set(result.empty_patch_ids))
    return result


def require_valid_predictions_jsonl(
    predictions_path: str | Path,
    selected_instance_ids: Sequence[str] | None = None,
    *,
    allow_extra_instances: bool = True,
) -> PredictionValidationResult:
    result = validate_predictions_jsonl(
        predictions_path,
        selected_instance_ids,
        allow_extra_instances=allow_extra_instances,
    )
    if not result.valid:
        raise PredictionValidationError(result)
    return result


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


_PYTEST_COUNT_RE = re.compile(
    r"(?P<count>\d+)\s+"
    r"(?P<label>failed|passed|error|errors|skipped|xfailed|xpassed|"
    r"warning|warnings|deselected)\b"
)
_PYTEST_EVENT_RE = re.compile(
    r"^(?P<status>FAILED|ERROR)\s+(?P<nodeid>\S+)"
)


def parse_pytest_summary_counts(output: str | None) -> dict[str, int]:
    if not output:
        return {}
    best_counts: dict[str, int] = {}
    for line in output.splitlines()[-80:]:
        matches = list(_PYTEST_COUNT_RE.finditer(line))
        if not matches:
            continue
        counts: dict[str, int] = {}
        for match in matches:
            label = match.group("label")
            if label == "error":
                label = "errors"
            elif label == "warning":
                label = "warnings"
            counts[label] = counts.get(label, 0) + int(match.group("count"))
        if counts:
            best_counts = counts
    return best_counts


def _graded_tests_from_instance_report(
    instance_report: Mapping[str, Any],
) -> set[str]:
    tests_status = instance_report.get("tests_status")
    if not isinstance(tests_status, Mapping):
        return set()

    graded_tests: set[str] = set()
    for bucket_name in (FAIL_TO_PASS, PASS_TO_PASS):
        bucket = tests_status.get(bucket_name)
        if not isinstance(bucket, Mapping):
            continue
        for outcome_name in ("success", "failure"):
            tests = bucket.get(outcome_name, [])
            if isinstance(tests, list):
                graded_tests.update(str(test) for test in tests)
    return graded_tests


def extract_ungraded_pytest_events(
    output: str | None,
    graded_tests: Iterable[str],
) -> list[dict[str, str]]:
    if not output:
        return []
    graded = set(graded_tests)
    events: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in output.splitlines():
        match = _PYTEST_EVENT_RE.match(line.strip())
        if not match:
            continue
        status = match.group("status").lower()
        nodeid = match.group("nodeid")
        if nodeid in graded:
            continue
        key = (status, nodeid)
        if key in seen:
            continue
        seen.add(key)
        events.append({"status": status, "nodeid": nodeid})
    return events


def summarize_raw_harness_notes(
    instance_report: Mapping[str, Any],
    test_output: str | None = None,
) -> dict[str, Any]:
    counts = parse_pytest_summary_counts(test_output)
    ungraded_events = extract_ungraded_pytest_events(
        test_output,
        _graded_tests_from_instance_report(instance_report),
    )
    notes: dict[str, Any] = {}
    if counts:
        notes["rawTestCounters"] = counts
    if ungraded_events:
        notes["ungradedPytestEvents"] = ungraded_events
        notes["summary"] = (
            f"Raw pytest output contains {len(ungraded_events)} failure/error "
            "event(s) outside the graded FAIL_TO_PASS/PASS_TO_PASS sets."
        )
    return notes


def _read_optional_text(path: str | Path | None) -> str | None:
    if path is None:
        return None
    resolved = Path(path)
    if not resolved.exists():
        return None
    return resolved.read_text(errors="replace")


def build_harness_result_summary(
    report: str | Path | Mapping[str, Any],
    *,
    report_path: str | Path | None = None,
    stdout_path: str | Path | None = None,
    stderr_path: str | Path | None = None,
    test_output_path: str | Path | None = None,
) -> dict[str, Any]:
    content = _load_report(report)
    statuses = parse_report_statuses(content)
    test_output = _read_optional_text(test_output_path)
    instances: dict[str, dict[str, Any]] = {}

    for instance_id, status in statuses.items():
        instance_report = content.get(instance_id)
        if not isinstance(instance_report, Mapping):
            instance_report = {}
        raw_notes = summarize_raw_harness_notes(instance_report, test_output)
        instances[instance_id] = _drop_none(
            {
                "instanceId": instance_id,
                "officialResult": status.value,
                "resolved": status == InstanceStatus.RESOLVED,
                "reportPath": str(report_path) if report_path is not None else None,
                "stdoutPath": str(stdout_path) if stdout_path is not None else None,
                "stderrPath": str(stderr_path) if stderr_path is not None else None,
                "testOutputPath": str(test_output_path)
                if test_output_path is not None
                else None,
                "rawTestCounters": raw_notes.get("rawTestCounters"),
                "rawHarnessNotes": raw_notes or None,
            }
        )

    return _drop_none(
        {
            "reportPath": str(report_path) if report_path is not None else None,
            "stdoutPath": str(stdout_path) if stdout_path is not None else None,
            "stderrPath": str(stderr_path) if stderr_path is not None else None,
            "testOutputPath": str(test_output_path)
            if test_output_path is not None
            else None,
            "instances": instances,
        }
    )


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


def build_evaluator_launch_provenance(
    *,
    run_id: str,
    predictions_path: str | Path,
    command: Sequence[str],
    suite: SwebenchSuite | str = SwebenchSuite.LITE,
    dataset_path: str | Path | None = None,
    evaluator_image: str | None = None,
    evaluator_image_digest: str | None = None,
    evaluator_job_name: str | None = None,
    resource_class: str = "standard",
    max_workers: int = 1,
    timeout_seconds: int = 1800,
    deadline_seconds: int | None = None,
    harness_report_path: str | Path | None = None,
    stdout_path: str | Path | None = None,
    stderr_path: str | Path | None = None,
    environment_images: Mapping[str, Any] | None = None,
) -> BenchmarkRunProvenance:
    dataset_name, split = suite_dataset(suite)
    dataset_sha = file_sha256(dataset_path) if dataset_path is not None else None
    return BenchmarkRunProvenance(
        run_id=run_id,
        evaluator_image=evaluator_image,
        evaluator_image_digest=evaluator_image_digest,
        evaluator_job_name=evaluator_job_name,
        resource_class=resource_class,
        max_workers=max_workers,
        timeout_seconds=timeout_seconds,
        deadline_seconds=deadline_seconds,
        dataset_path=str(dataset_path) if dataset_path is not None else dataset_name,
        dataset_sha256=dataset_sha,
        predictions_path=str(predictions_path),
        predictions_sha256=file_sha256(predictions_path),
        harness_args=list(command),
        harness_report_path=str(harness_report_path)
        if harness_report_path is not None
        else None,
        stdout_path=str(stdout_path) if stdout_path is not None else None,
        stderr_path=str(stderr_path) if stderr_path is not None else None,
        environment_images=environment_images
        or {"dataset": dataset_name, "split": split},
    )


def prepare_evaluator_launch(
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
    evaluator_image: str | None = None,
    evaluator_image_digest: str | None = None,
    evaluator_job_name: str | None = None,
    resource_class: str = "standard",
    deadline_seconds: int | None = None,
    allow_extra_instances: bool = True,
) -> dict[str, Any]:
    validation = require_valid_predictions_jsonl(
        predictions_path,
        instance_ids,
        allow_extra_instances=allow_extra_instances,
    )
    command = build_evaluator_command(
        predictions_path=predictions_path,
        run_id=run_id,
        suite=suite,
        instance_ids=instance_ids,
        timeout_seconds=timeout_seconds,
        max_workers=max_workers,
        report_dir=report_dir,
        dataset_name=dataset_name,
        split=split,
    )
    provenance = build_evaluator_launch_provenance(
        run_id=run_id,
        predictions_path=predictions_path,
        command=command,
        suite=suite,
        evaluator_image=evaluator_image,
        evaluator_image_digest=evaluator_image_digest,
        evaluator_job_name=evaluator_job_name,
        resource_class=resource_class,
        max_workers=max_workers,
        timeout_seconds=timeout_seconds,
        deadline_seconds=deadline_seconds,
    )
    return {
        "command": command,
        "validation": validation.to_dict(),
        "provenance": provenance.to_dict(),
    }


def build_golden_canary_run_manifest(
    *,
    suite: SwebenchSuite | str = SwebenchSuite.VERIFIED,
    agent: str,
    project_id: str,
    user_id: str,
    artifact_dir: str | Path,
    run_id: str | None = None,
    instance_ids: Sequence[str] | None = None,
    environment_instance_id: str | None = None,
    instances: Sequence[Mapping[str, Any]] | None = None,
    concurrency: int = 1,
    resource_class: str = "standard",
    timeout_seconds: int = 1800,
    max_workers: int | None = None,
    evaluator_image: str | None = None,
    evaluator_image_digest: str | None = None,
) -> dict[str, Any]:
    resolved_suite = normalize_suite(suite)
    if run_id is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        run_id = f"golden-canary-{resolved_suite.value}-{stamp}"

    selected_ids = list(
        instance_ids or DEFAULT_GOLDEN_CANARY_INSTANCE_IDS[resolved_suite]
    )
    if environment_instance_id and environment_instance_id not in selected_ids:
        selected_ids.append(environment_instance_id)

    selected_instances = (
        [dict(instance) for instance in instances]
        if instances is not None
        else load_suite_instances(resolved_suite, selected_ids)
    )
    instances_by_id = {
        str(instance[KEY_INSTANCE_ID]): instance for instance in selected_instances
    }
    missing = [instance_id for instance_id in selected_ids if instance_id not in instances_by_id]
    if missing:
        raise ValueError(f"Canary instances not found: {' '.join(missing)}")

    predictions = []
    roles: dict[str, str] = {}
    for index, instance_id in enumerate(selected_ids):
        instance = instances_by_id[instance_id]
        if index == 1:
            patch = ""
            roles[instance_id] = "empty_patch_unresolved_expected"
        else:
            patch = str(instance.get("patch") or "")
            roles[instance_id] = (
                "environment_validation"
                if environment_instance_id == instance_id
                else "gold_resolved_smoke"
            )
        predictions.append(prediction_record(instance_id, patch, agent))

    output_dir = Path(artifact_dir) / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = write_predictions_jsonl(
        predictions,
        output_dir / "predictions.jsonl",
    )
    command = build_evaluator_command(
        predictions_path=predictions_path,
        run_id=run_id,
        suite=resolved_suite,
        instance_ids=selected_ids,
        timeout_seconds=timeout_seconds,
        max_workers=max_workers or concurrency,
        report_dir=output_dir,
    )
    coordinator_execution_id = f"swebench-golden-canary-{run_id}"
    provenance = build_evaluator_launch_provenance(
        run_id=run_id,
        predictions_path=predictions_path,
        command=command,
        suite=resolved_suite,
        evaluator_image=evaluator_image,
        evaluator_image_digest=evaluator_image_digest,
        evaluator_job_name=f"swebench-evaluator-{run_id}",
        resource_class=resource_class,
        max_workers=max_workers or concurrency,
        timeout_seconds=timeout_seconds,
        harness_report_path=output_dir,
    )

    provenance_path = output_dir / "provenance.json"
    provenance_path.write_text(json.dumps(provenance.to_dict(), indent=2) + "\n")
    manifest = {
        "runId": run_id,
        "coordinatorExecutionId": coordinator_execution_id,
        "suite": resolved_suite.value,
        "agent": agent,
        "projectId": project_id,
        "userId": user_id,
        "concurrency": concurrency,
        "resourceClass": resource_class,
        "timeoutSeconds": timeout_seconds,
        "selectedInstanceIds": selected_ids,
        "instanceRoles": roles,
        "artifactPaths": {
            "artifactDir": str(output_dir),
            "predictions": str(predictions_path),
            "provenance": str(provenance_path),
        },
        "evaluatorCommand": command,
        "provenance": provenance.to_dict(),
    }
    manifest_path = output_dir / "manifest.json"
    manifest["artifactPaths"]["manifest"] = str(manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
