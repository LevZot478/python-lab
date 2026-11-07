"""Tests for encrypted vault, authentication, and password generation."""

import json
import string
from pathlib import Path

import pytest

from password_manager.manager import PasswordManager, VaultError, generate_password


@pytest.fixture
def vault(tmp_path: Path) -> PasswordManager:
    """Return an initialized and unlocked temporary vault."""
    manager = PasswordManager(tmp_path / "vault.json")
    manager.init_master("example-master-password")
    return manager


def test_unlock_accepts_correct_password_and_rejects_wrong(vault: PasswordManager) -> None:
    """Master verification distinguishes right and wrong passwords."""
    assert vault.unlock("example-master-password") is True
    assert vault.unlock("wrong-password") is False
    with pytest.raises(PermissionError):
        vault.list_entries()
    assert vault.unlock("example-master-password") is True


def test_init_cannot_overwrite_existing_vault(vault: PasswordManager) -> None:
    """Reinitialization must not wipe stored data."""
    vault.add_entry("github", "test", "fake-secret")
    with pytest.raises(ValueError, match="already exists"):
        vault.init_master("another-master-password")
    assert vault.get_entry("github") == {"login": "test", "password": "fake-secret"}


def test_add_list_get_delete_and_reload(vault: PasswordManager) -> None:
    """CRUD survives a new process-like object with the same vault file."""
    vault.add_entry("github", "learner", "fake-secret")
    assert vault.list_entries() == ["github"]
    restored = PasswordManager(vault.filepath)
    assert restored.unlock("example-master-password")
    assert restored.get_entry("github") == {"login": "learner", "password": "fake-secret"}
    assert restored.delete_entry("github") is True
    assert restored.delete_entry("github") is False
    assert restored.list_entries() == []


def test_file_contains_no_plaintext_passwords(vault: PasswordManager) -> None:
    """Neither master nor service passwords may occur in saved JSON."""
    vault.add_entry("github", "learner", "service-secret-123")
    text = vault.filepath.read_text(encoding="utf-8")
    assert "example-master-password" not in text
    assert "service-secret-123" not in text
    assert "learner" not in text
    data = json.loads(text)
    assert "auth_salt" in data and "key_salt" in data
    assert "password_hash" in data
    assert isinstance(data["entries"]["github"], str)


def test_generate_password_has_all_required_groups() -> None:
    """Generated passwords use secure randomness and multiple character groups."""
    password = generate_password(24)
    assert len(password) == 24
    assert any(char.isalpha() for char in password)
    assert any(char.isdigit() for char in password)
    assert any(char in string.punctuation for char in password)
    with pytest.raises(ValueError, match="at least 12"):
        generate_password(5)


def test_corrupted_vault_rejected(tmp_path: Path) -> None:
    """Malformed files produce a readable custom error."""
    file = tmp_path / "vault.json"
    file.write_text('{"entries": "bad"}', encoding="utf-8")
    with pytest.raises(VaultError):
        PasswordManager(file)


def test_entry_requires_unlock(tmp_path: Path) -> None:
    """Operations cannot retrieve secrets without authentication."""
    file = tmp_path / "vault.json"
    maker = PasswordManager(file)
    maker.init_master("example-master-password")
    maker.add_entry("github", "user", "fake-secret")
    new_manager = PasswordManager(file)
    with pytest.raises(PermissionError):
        new_manager.get_entry("github")
