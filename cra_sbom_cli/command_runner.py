import subprocess


class CommandError(RuntimeError):
    pass


def run_command(
    command: list[str],
    cwd: str | None = None,
    timeout: int = 3600,
    env: dict | None = None,
) -> str:
    process = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )
    if process.returncode != 0:
        raise CommandError(
            f"Command failed ({process.returncode}): {' '.join(command)}\n"
            f"stdout:\n{process.stdout}\n"
            f"stderr:\n{process.stderr}"
        )
    return process.stdout
