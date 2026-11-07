"""Password vault: salted master verification and encrypted JSON entries."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import string
import tempfile
from pathlib import Path
from typing import TypedDict

from cryptography.fernet import Fernet, InvalidToken

_ITERATIONS = 600_000
_VERSION = 1


class VaultError(Exception):
    """A vault is invalid, inaccessible, or contains undecryptable data."""


class Entry(TypedDict):
    """Decrypted credentials of one service."""

    login: str
    password: str


class VaultData(TypedDict):
    """On-disk encrypted vault structure."""

    version: int
    auth_salt: str
    key_salt: str
    password_hash: str
    entries: dict[str, str]


def _derive(password: str, salt: bytes) -> bytes:
    """Derive 32 bytes from a password using salted PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS, dklen=32)


def generate_password(length: int = 20) -> str:
    """Generate a random password with letters, digits and punctuation."""
    if length < 12:
        raise ValueError("Password length must be at least 12")
    groups = (string.ascii_letters, string.digits, string.punctuation)
    chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class PasswordManager:
    """Manage credentials in a password-derived, encrypted JSON vault."""

    def __init__(self, filename: str | Path = "vault.json") -> None:
        self.filepath = Path(filename)
        self._data: VaultData | None = None
        self._cipher: Fernet | None = None
        self._load()

    @property
    def initialized(self) -> bool:
        """Return whether a vault has already been created."""
        return self._data is not None

    def init_master(self, password: str) -> None:
        """Create a vault; never overwrite an existing one."""
        if self.initialized or self.filepath.exists():
            raise ValueError("Vault already exists; initialization refused")
        if len(password) < 8:
            raise ValueError("Master password must have at least 8 characters")

        auth_salt = secrets.token_bytes(16)
        key_salt = secrets.token_bytes(16)
        verifier = _derive(password, auth_salt)
        self._data = {
            "version": _VERSION,
            "auth_salt": base64.b64encode(auth_salt).decode("ascii"),
            "key_salt": base64.b64encode(key_salt).decode("ascii"),
            "password_hash": base64.b64encode(verifier).decode("ascii"),
            "entries": {},
        }
        self._cipher = self._make_cipher(password, key_salt)
        self._persist()

    def unlock(self, password: str) -> bool:
        """Verify the master password and unlock credentials on success."""
        self._cipher = None
        if self._data is None:
            return False
        try:
            auth_salt = base64.b64decode(self._data["auth_salt"], validate=True)
            stored = base64.b64decode(self._data["password_hash"], validate=True)
            key_salt = base64.b64decode(self._data["key_salt"], validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise VaultError("Vault contains invalid salt or hash data") from exc

        if not hmac.compare_digest(_derive(password, auth_salt), stored):
            return False
        self._cipher = self._make_cipher(password, key_salt)
        return True

    def add_entry(self, name: str, login: str, pwd: str) -> None:
        """Encrypt and persist credentials under the given service name."""
        cipher = self._require_unlocked()
        if not name.strip():
            raise ValueError("Service name cannot be empty")
        entry: Entry = {"login": login, "password": pwd}
        token = cipher.encrypt(json.dumps(entry).encode("utf-8"))
        if self._data is None:
            raise VaultError("Vault not initialized")
        self._data["entries"][name] = token.decode("ascii")
        self._persist()

    def list_entries(self) -> list[str]:
        """Return sorted service names, never their passwords."""
        self._require_unlocked()
        if self._data is None:
            raise VaultError("Vault not initialized")
        return sorted(self._data["entries"])

    def get_entry(self, name: str) -> Entry | None:
        """Decrypt credentials for an existing service, or return None."""
        cipher = self._require_unlocked()
        if self._data is None:
            raise VaultError("Vault not initialized")
        token = self._data["entries"].get(name)
        if token is None:
            return None
        try:
            raw: object = json.loads(cipher.decrypt(token.encode("ascii")))
        except (InvalidToken, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise VaultError("Cannot decrypt saved entry") from exc
        if not isinstance(raw, dict):
            raise VaultError("Decrypted entry has an invalid format")
        login = raw.get("login")
        password = raw.get("password")
        if not isinstance(login, str) or not isinstance(password, str):
            raise VaultError("Decrypted entry has an invalid format")
        return {"login": login, "password": password}

    def delete_entry(self, name: str) -> bool:
        """Remove an entry and save changes; return False if absent."""
        self._require_unlocked()
        if self._data is None:
            raise VaultError("Vault not initialized")
        if name not in self._data["entries"]:
            return False
        del self._data["entries"][name]
        self._persist()
        return True

    def _require_unlocked(self) -> Fernet:
        """Return the cipher or reject access to a locked vault."""
        if self._cipher is None:
            raise PermissionError("Vault is locked. Unlock it first")
        return self._cipher

    @staticmethod
    def _make_cipher(password: str, salt: bytes) -> Fernet:
        """Construct a Fernet cipher from the master password."""
        key = base64.urlsafe_b64encode(_derive(password, salt))
        return Fernet(key)

    def _persist(self) -> None:
        """Atomically save encrypted vault metadata and entries to disk."""
        if self._data is None:
            raise VaultError("Vault not initialized")
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.filepath.parent,
                prefix=".vault-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                json.dump(self._data, handle, indent=2)
                handle.write("\n")
            assert temporary is not None
            os.replace(temporary, self.filepath)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    def _load(self) -> None:
        """Load metadata and encrypted entries, validating the file format."""
        if not self.filepath.exists():
            return
        try:
            with self.filepath.open("r", encoding="utf-8") as handle:
                raw: object = json.load(handle)
        except (OSError, ValueError) as exc:
            raise VaultError("Unable to read vault JSON") from exc
        if not isinstance(raw, dict) or raw.get("version") != _VERSION:
            raise VaultError("Unsupported or damaged vault format")
        auth_salt = raw.get("auth_salt")
        key_salt = raw.get("key_salt")
        password_hash = raw.get("password_hash")
        raw_entries = raw.get("entries")
        if (
            not isinstance(auth_salt, str)
            or not isinstance(key_salt, str)
            or not isinstance(password_hash, str)
            or not isinstance(raw_entries, dict)
        ):
            raise VaultError("Vault metadata has an invalid format")
        entries: dict[str, str] = {}
        for name, token in raw_entries.items():
            if not isinstance(name, str) or not isinstance(token, str):
                raise VaultError("Vault entries have an invalid format")
            entries[name] = token
        self._data = {
            "version": _VERSION,
            "auth_salt": auth_salt,
            "key_salt": key_salt,
            "password_hash": password_hash,
            "entries": entries,
        }
