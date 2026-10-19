
"""Password manager logic."""

import json
from pathlib import Path


class PasswordManager:
    """Manage password entries."""

    def __init__(self, filename: str = "vault.json") -> None:
        self.filepath = Path(filename)
        self.entries: dict[str, dict[str, str]] = {}
        self._load()

    def add_entry(
        self, name: str, login: str, password: str
    ) -> None:
        self.entries[name] = {
            "login": login,
            "password": password,
        }
        self._persist()

    def list_entries(self) -> list[str]:
        return list(self.entries.keys())

    def get_entry(self, name: str) -> dict[str, str] | None:
        return self.entries.get(name)

    def delete_entry(self, name: str) -> bool:
        if name not in self.entries:
            return False

        del self.entries[name]
        self._persist()
        return True

    def _persist(self) -> None:
        with self.filepath.open("w", encoding="utf-8") as file:
            json.dump(self.entries, file, indent=4)

    def _load(self) -> None:
        if not self.filepath.exists():
            return

        with self.filepath.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("Invalid vault format")

        self.entries = data
