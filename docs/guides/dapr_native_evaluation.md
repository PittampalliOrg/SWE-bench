# Dapr-Native SWE-bench Evaluation

This integration keeps agent inference separate from deterministic SWE-bench grading.
Agents work in OpenShell sandboxes and leave changes in the working tree. The
official SWE-bench harness remains the grading authority and runs in a separate
evaluator job with Docker or an equivalent controlled image builder.

## Architecture

The coordinator service owns run lifecycle, dataset loading, fan-out concurrency,
cancellation, and result aggregation. Each SWE-bench instance runs as a Dapr child
workflow:

1. Load instance metadata from SWE-bench Lite or SWE-bench Verified.
2. Provision an OpenShell sandbox and clone the repository at `base_commit`.
3. Invoke the published `dapr-agent-py` agent with the SWE-bench prompt contract.
4. Extract `git diff --binary <base_commit> --`.
5. Persist the patch, patch hash, logs, session ID, sandbox reference, and workflow
   identifiers.

The evaluator job consumes the generated predictions JSONL plus the selected
instance IDs. It calls the normal harness entry point:

```bash
python -m swebench.harness.run_evaluation \
  --dataset_name SWE-bench/SWE-bench_Lite \
  --split test \
  --predictions_path /artifacts/predictions.jsonl \
  --instance_ids django__django-11099 \
  --run_id run_123 \
  --report_dir /artifacts
```

Per-instance harness artifacts stay under `logs/run_evaluation/<run_id>/...`.
The aggregate report is written to `--report_dir`, which lets a Kubernetes job
publish it directly to a PVC or object-store sync path.

## Workflow-Builder Handoff

The workflow-builder side should dispatch the agent step as `durable/run`, which
runs as a Dapr child workflow in the selected per-agent runtime. Stamp `agentRef`
as an object before execution rather than leaving it as a jq string placeholder.
Workspace file operations should use slug-as-action names such as
`workspace/read_file` and `workspace/write_file`.

## Python Adapter

`swebench.harness.dapr_native` contains small deterministic helpers for the
workflow-builder integration:

- `StartRunRequest` validates the public run contract.
- `load_suite_instances` loads Lite or Verified metadata.
- `build_agent_prompt` produces the OpenShell agent prompt contract.
- `extract_git_diff` extracts a binary patch from a sandbox repo.
- `InstanceResult`, `prediction_record`, and `write_predictions_jsonl` create
  official predictions JSONL.
- `validate_predictions_jsonl` checks the predictions artifact before launching
  an evaluator job. It requires one row for each selected instance, validates
  required SWE-bench fields, accepts empty patches as unresolved candidates, and
  rejects markdown/prose-wrapped or malformed non-empty diffs.
- `parse_report_statuses` converts harness reports into instance statuses.
- `build_harness_result_summary` preserves the official resolved/unresolved
  result while adding artifact paths, raw pytest counters, and ungraded raw
  harness notes when available.
- `BenchmarkRunProvenance` and `merge_run_provenance` provide the shape and
  merge behavior expected by the benchmark run provenance table.
- `validate_status_transition` enforces the supported lifecycle transitions.
- `build_evaluator_command` builds the evaluator job command.
- `prepare_evaluator_launch` combines prediction validation, evaluator command
  construction, and launch provenance into one pre-flight payload.

The prompt contract is intentionally narrow:

- Work only in `/sandbox/repo`.
- Do not commit.
- Make minimal source changes.
- Leave final changes in the working tree.
- The workflow extracts the diff.

Empty patches should still be written to predictions JSONL. The harness records
them as unresolved through the aggregate report.

## Golden Canary Artifacts

`scripts/create_golden_canary_run.py` creates a machine-readable manifest for an
admin-triggered canary run:

```bash
python scripts/create_golden_canary_run.py \
  --agent coding-assistant \
  --project-id project_123 \
  --user-id user_123 \
  --suite verified
```

The script writes a predictions JSONL, provenance JSON, and manifest JSON under
`artifacts/golden-canaries/<run_id>/`, then prints the manifest as a single JSON
object. The default canary includes a gold-patch smoke instance and an
empty-patch unresolved-expected instance. Pass `--environment-instance-id` to add
a third environment/build validation case when a validated evaluator image is
available.

## Environment Strategy

Use maintained images by default:

- `dapr-agent` or `swebench-agent` for inference.
- `swebench-evaluator` for official harness grading.

Nixery can be used for coarse base images, such as Python plus git and compilers,
when that reduces image sprawl. It should not replace the official evaluator
harness path unless compatibility is proven.
