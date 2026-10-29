"""GeekNosy automation CLI.

Examples:
  python -m app.cli scan example.com --authorized --wait
  python -m app.cli jobs
  python -m app.cli report 12 sarif --output result.sarif
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx


def _client(args) -> httpx.Client:
    headers = {}
    key = args.api_key or os.getenv("GEEKNOSY_API_KEY")
    if key:
        headers["X-API-Key"] = key
    return httpx.Client(base_url=args.url.rstrip("/"), headers=headers, timeout=30)


def _wait(client: httpx.Client, job_id: str) -> dict:
    while True:
        response = client.get(f"/api/jobs/{job_id}")
        response.raise_for_status()
        job = response.json()
        print(
            f"\r{job['status']:10} {job['progress']:6.1f}% {job.get('phase') or ''}",
            end="",
            flush=True,
        )
        if job["status"] in ("completed", "failed", "cancelled"):
            print()
            return job
        time.sleep(1)


def main() -> int:
    parser = argparse.ArgumentParser(prog="geeknosy")
    parser.add_argument("--url", default="http://localhost:3000")
    parser.add_argument("--api-key")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan")
    scan.add_argument("domains", nargs="+")
    scan.add_argument("--institution")
    scan.add_argument("--mode", choices=("standard", "advanced"), default="advanced")
    scan.add_argument(
        "--intensity",
        choices=("passive", "fast", "standard", "bug_bounty", "deep", "custom"),
        default="standard",
    )
    scan.add_argument("--route-profile", default="auto")
    scan.add_argument("--max-paths", type=int, default=40)
    scan.add_argument("--exposure-checks", action="store_true")
    scan.add_argument("--authorized", action="store_true", required=True)
    scan.add_argument("--execution-mode", choices=("passive", "authorized"), default="passive")
    scan.add_argument("--active-check", action="append", choices=("reflection", "open_redirect", "sql_error", "dangerous_methods", "cors", "crlf"), default=[])
    scan.add_argument("--authorization-reference")
    scan.add_argument("--credential-profile")
    scan.add_argument("--confirm-active", action="store_true")
    scan.add_argument("--wait", action="store_true")

    sub.add_parser("jobs")
    status_parser = sub.add_parser("status")
    status_parser.add_argument("job_id")
    cancel_parser = sub.add_parser("cancel")
    cancel_parser.add_argument("job_id")
    report = sub.add_parser("report")
    report.add_argument("scan_id", type=int)
    report.add_argument(
        "format", choices=("json", "jsonl", "csv", "pdf", "sarif", "sbom", "markdown", "html")
    )
    report.add_argument("--output", required=True)

    args = parser.parse_args()
    try:
        with _client(args) as client:
            if args.command == "scan":
                payload = {
                    "request": {
                        "domains": args.domains,
                        "institution": args.institution,
                        "mode": args.mode,
                        "intensity": args.intensity,
                        "route_profile": args.route_profile,
                        "max_paths_per_domain": args.max_paths,
                        "include_exposure_checks": args.exposure_checks,
                        "authorization_confirmed": args.authorized,
                        "execution_mode": args.execution_mode,
                        "active_checks": args.active_check,
                        "authorization_reference": args.authorization_reference,
                        "credential_profile": args.credential_profile,
                        "active_authorization_confirmed": args.confirm_active,
                    }
                }
                response = client.post("/api/jobs", json=payload)
                response.raise_for_status()
                job = response.json()
                print(json.dumps(job, indent=2, ensure_ascii=False))
                if args.wait:
                    job = _wait(client, job["id"])
                    return 0 if job["status"] == "completed" else 2
            elif args.command == "jobs":
                response = client.get("/api/jobs")
                response.raise_for_status()
                print(json.dumps(response.json(), indent=2, ensure_ascii=False))
            elif args.command == "status":
                response = client.get(f"/api/jobs/{args.job_id}")
                response.raise_for_status()
                print(json.dumps(response.json(), indent=2, ensure_ascii=False))
            elif args.command == "cancel":
                response = client.post(f"/api/jobs/{args.job_id}/cancel")
                response.raise_for_status()
                print(json.dumps(response.json(), indent=2, ensure_ascii=False))
            elif args.command == "report":
                response = client.get(f"/api/reports/{args.scan_id}/{args.format}")
                response.raise_for_status()
                Path(args.output).write_bytes(response.content)
                print(args.output)
        return 0
    except httpx.HTTPError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
