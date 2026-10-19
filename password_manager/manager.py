"""Password manager logic."""


class PasswordManager:
    """Manage password entries."""

    def __init__(self) -> None:
        self.entries: dict[str, dict[str, str]] = {}

    def add_entry(self, name: str, login: str, password: str) -> None:
        self.entries[name] = {
            "login": login,
            "password": password,
        }

    def list_entries(self) -> list[str]:
        return list(self.entries.keys())

    def delete_entry(self, name: str) -> bool:
        if name not in self.entries:
            return False

        del self.entries[name]
        return True