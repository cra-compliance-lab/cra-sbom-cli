from pathlib import Path

from .command_runner import CommandError, run_command


def run_grype(sbom_path: Path) -> dict:
    try:
        output = run_command(["grype", f"sbom:{sbom_path}", "-o", "json"])
        import json

        parsed = json.loads(output)
        return {
            "tool": "grype",
            "status": "ok",
            "vulnerabilities": len(parsed.get("matches", [])),
            "raw": parsed,
        }
    except (CommandError, FileNotFoundError, ValueError) as exc:
        return {
            "tool": "grype",
            "status": "unavailable",
            "error": str(exc),
        }


def run_sbomqs(sbom_path: Path) -> dict:
    try:
        output = run_command(["sbomqs", "score", str(sbom_path)])
        return {
            "tool": "sbomqs",
            "status": "ok",
            "output": output,
        }
    except (CommandError, FileNotFoundError) as exc:
        return {
            "tool": "sbomqs",
            "status": "unavailable",
            "error": str(exc),
        }
