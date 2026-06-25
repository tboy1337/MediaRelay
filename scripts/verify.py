#!/usr/bin/env python3
"""Local verification pipeline for MediaRelay development.

Runs the full quality gate locally on Windows, macOS, and Linux using only
``sys.executable`` (no shell), so path and quoting behavior is consistent
across platforms.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
TESTS = ROOT / "tests"
SCRIPTS = ROOT / "scripts"
PACKAGE = SRC / "mediarelay"
PYLINT_REPORT = ROOT / "pylint-report.txt"


def _python_module(*args: str) -> list[str]:
    """Build a ``python -m ...`` command without invoking a shell."""
    return [sys.executable, "-m", *args]


def _path(path: Path) -> str:
    """Return a path string safe to pass as a subprocess argument."""
    return str(path)


def _editable_install_target() -> str:
    """Return an absolute editable-install target with dev extras."""
    return f"{ROOT}[dev]"


def _ensure_project_root() -> None:
    """Fail fast when the script is not run from a MediaRelay checkout."""
    if not (ROOT / "pyproject.toml").is_file():
        print(f"ERROR: Expected pyproject.toml in {ROOT}", file=sys.stderr)
        sys.exit(2)
    if not PACKAGE.is_dir():
        print(f"ERROR: Expected package directory at {PACKAGE}", file=sys.stderr)
        sys.exit(2)


def run_step(
    name: str,
    command: list[str],
    *,
    optional: bool = False,
    cwd: Path = ROOT,
) -> bool:
    """Run a verification step and return True on success."""
    print(f"\n{'=' * 70}")
    print(f"STEP: {name}")
    print(f"CMD:  {' '.join(command)}")
    print("=" * 70)

    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
    )
    if result.returncode != 0:
        label = "WARNING" if optional else "FAILED"
        print(f"\n[{label}] {name} (exit code {result.returncode})")
        return optional
    print(f"\n[OK] {name}")
    return True


def run_pylint() -> bool:
    """Run pylint and write the full report to ``pylint-report.txt``."""
    name = "Pylint static analysis"
    command = _python_module("pylint", _path(PACKAGE), "--output-format=text")
    print(f"\n{'=' * 70}")
    print(f"STEP: {name}")
    print(f"CMD:  {' '.join(command)}")
    print(f"REPORT: {PYLINT_REPORT}")
    print("=" * 70)

    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    report_body = (result.stdout or "") + (result.stderr or "")
    PYLINT_REPORT.write_text(report_body, encoding="utf-8", newline="\n")

    if result.returncode != 0:
        print(f"\n[FAILED] {name} (exit code {result.returncode})")
        if report_body.strip():
            tail = report_body.strip().splitlines()[-8:]
            print("Last pylint output:")
            for line in tail:
                print(f"  {line}")
        return False

    print(f"\n[OK] {name}")
    return True


def check_trailing_whitespace() -> bool:
    """Fail when source or test files contain trailing whitespace."""
    name = "Trailing whitespace check (autopep8)"
    command = _python_module(
        "autopep8",
        "--diff",
        "--recursive",
        "--select=W291,W293",
        _path(SRC),
        _path(TESTS),
        _path(SCRIPTS),
    )
    print(f"\n{'=' * 70}")
    print(f"STEP: {name}")
    print(f"CMD:  {' '.join(command)}")
    print("=" * 70)

    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    diff_output = (result.stdout or "") + (result.stderr or "")
    if diff_output.strip():
        print(f"\n[FAILED] {name}")
        print("Trailing whitespace found. Run:")
        print(
            "  "
            + " ".join(
                _python_module(
                    "autopep8",
                    "--in-place",
                    "--recursive",
                    "--select=W291,W293",
                    _path(SRC),
                    _path(TESTS),
                    _path(SCRIPTS),
                )
            )
        )
        tail = diff_output.strip().splitlines()[-12:]
        print("Diff tail:")
        for line in tail:
            print(f"  {line}")
        return False

    print(f"\n[OK] {name}")
    return True


def _build_verification_steps() -> list[tuple[str, list[str], bool]]:
    """Return the ordered verification pipeline steps."""
    return [
        (
            "Editable install with dev dependencies",
            _python_module("pip", "install", "-e", _editable_install_target()),
            False,
        ),
        (
            "Black formatting",
            _python_module("black", "--check", _path(SRC), _path(TESTS)),
            False,
        ),
        (
            "Import sorting (isort)",
            _python_module("isort", "--check-only", _path(SRC), _path(TESTS)),
            False,
        ),
        (
            "Mypy type checking",
            _python_module("mypy", "--package", "mediarelay"),
            False,
        ),
        (
            "Bandit security scan",
            _python_module(
                "bandit",
                "-r",
                _path(PACKAGE),
                "-c",
                _path(ROOT / "pyproject.toml"),
            ),
            False,
        ),
        (
            "pip-audit dependency check",
            _python_module("pip_audit"),
            False,
        ),
        (
            "Pytest with coverage",
            _python_module("pytest"),
            False,
        ),
    ]


def _run_named_steps(
    failures: list[str],
    steps: list[tuple[str, list[str], bool]],
) -> None:
    """Run subprocess steps and record required-step failures."""
    for name, command, optional in steps:
        if not run_step(name, command, optional=optional) and not optional:
            failures.append(name)


def _print_verification_result(failures: list[str]) -> int:
    """Print the final verification summary and return the exit code."""
    print(f"\n{'=' * 70}")
    if failures:
        print("VERIFICATION FAILED")
        for failure in failures:
            print(f"  - {failure}")
        print("=" * 70)
        return 1

    print("VERIFICATION PASSED")
    print("=" * 70)
    return 0


def main() -> int:
    """Run the full local verification pipeline."""
    _ensure_project_root()
    failures: list[str] = []
    steps = _build_verification_steps()

    _run_named_steps(failures, [steps[0]])

    if not check_trailing_whitespace():
        failures.append("Trailing whitespace check (autopep8)")

    _run_named_steps(failures, steps[1:5])

    if not run_pylint():
        failures.append("Pylint static analysis")

    _run_named_steps(failures, steps[5:])

    return _print_verification_result(failures)


if __name__ == "__main__":
    sys.exit(main())
