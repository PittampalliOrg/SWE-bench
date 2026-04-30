#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
from pathlib import Path

from swebench.harness.dapr_native import build_golden_canary_run_manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create local SWE-bench golden canary artifacts and launch metadata."
    )
    parser.add_argument("--agent", required=True, help="Agent/model name for predictions")
    parser.add_argument("--project-id", required=True, help="Project/workspace identity")
    parser.add_argument("--user-id", required=True, help="User identity")
    parser.add_argument("--suite", default="verified", choices=["lite", "verified"])
    parser.add_argument(
        "--artifact-dir",
        default="artifacts/golden-canaries",
        help="Directory where canary artifacts should be written",
    )
    parser.add_argument("--run-id", help="Optional explicit benchmark run ID")
    parser.add_argument(
        "--instance-id",
        dest="instance_ids",
        action="append",
        help="Override fixed canary IDs. Pass twice for smoke + empty-patch cases.",
    )
    parser.add_argument(
        "--environment-instance-id",
        help="Optional third instance used as an environment/build validation case",
    )
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--resource-class", default="standard")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--max-workers", type=int)
    parser.add_argument("--evaluator-image")
    parser.add_argument("--evaluator-image-digest")
    args = parser.parse_args()

    manifest = build_golden_canary_run_manifest(
        suite=args.suite,
        agent=args.agent,
        project_id=args.project_id,
        user_id=args.user_id,
        artifact_dir=Path(args.artifact_dir),
        run_id=args.run_id,
        instance_ids=args.instance_ids,
        environment_instance_id=args.environment_instance_id,
        concurrency=args.concurrency,
        resource_class=args.resource_class,
        timeout_seconds=args.timeout_seconds,
        max_workers=args.max_workers,
        evaluator_image=args.evaluator_image,
        evaluator_image_digest=args.evaluator_image_digest,
    )
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
