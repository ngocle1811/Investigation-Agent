"""Verify the four Checkpoint 2 top-result expectations through the HTTP API."""

import argparse
import json

import httpx

CASES = (
    (
        "Windows Event ID 4625 failed logon",
        lambda chunk: chunk["source_type"] == "windows_event_doc" and chunk["event_id"] == 4625,
        "Microsoft Windows Event 4625",
    ),
    (
        "Sysmon process creation Event ID 1",
        lambda chunk: chunk["source_type"] == "sysmon_doc" and chunk["event_id"] == 1,
        "Sysmon Event ID 1",
    ),
    (
        "PowerShell MITRE technique T1059.001",
        lambda chunk: chunk["source_type"] == "mitre_attack"
        and chunk["technique_id"] == "T1059.001",
        "MITRE ATT&CK T1059.001",
    ),
    (
        "Sigma encoded PowerShell command detection rule",
        lambda chunk: chunk["source_type"] == "sigma_rule" and bool(chunk["sigma_rule_id"]),
        "Sigma PowerShell rule",
    ),
)


def parse_args() -> argparse.Namespace:
    """Parse the target API base URL."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:18000")
    return parser.parse_args()


def main() -> int:
    """Fail fast unless each acceptance query returns its expected top result."""

    args = parse_args()
    checks = []
    with httpx.Client(base_url=args.base_url, timeout=60) as client:
        for query, predicate, expected in CASES:
            response = client.get("/knowledge/search", params={"q": query, "top_k": 1})
            response.raise_for_status()
            results = response.json()["results"]
            if not results or not predicate(results[0]["chunk"]):
                actual = results[0]["chunk"] if results else None
                raise SystemExit(f"Expected {expected} for {query!r}; got {actual!r}")
            hit = results[0]
            checks.append(
                {
                    "query": query,
                    "expected": expected,
                    "score": round(hit["score"], 4),
                    "chunk_id": hit["chunk"]["chunk_id"],
                }
            )
    print(json.dumps({"status": "ok", "checks": checks}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
