"""Non-interactive tests for public command-line operations."""

from pathlib import Path

from password_manager import main as cli


def test_generate_cli(capsys: object) -> None:
    """The CLI generates a password without requiring an existing vault."""
    assert cli.main(["--generate", "--length", "18"]) == 0


def test_missing_vault_cli(tmp_path: Path) -> None:
    """Missing files yield a controlled error exit code."""
    assert cli.main(["--file", str(tmp_path / "missing.json"), "--unlock"]) == 1
