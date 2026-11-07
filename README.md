# Python Lab 1 — Encrypted Password Manager

**Track:** DevOps (B1) · **Language:** Python 3.11+ · **Submission:** GitHub, pytest, CI, defense.

Terminal app for securely storing service names, logins, and passwords. It uses a master password for access, a salted PBKDF2-HMAC-SHA256 verifier, and Fernet authenticated encryption for every saved login/password pair. The master password itself is never saved in clear text. Only service names remain visible in the JSON file.

## Quick start

Open a terminal **in the repository root** (where `pyproject.toml` is located):

```bash
python -m pip install -e '.[dev]'
python -m password_manager.main --init
python -m password_manager.main --unlock
python -m password_manager.main --generate --length 20
```

If [`uv`](https://docs.astral.sh/uv/) is installed, the same program can be launched directly through the course's preferred runner:

```bash
uv run python -m password_manager.main --init
uv run python -m password_manager.main --unlock
uv run python -m password_manager.main --generate --length 20
```

After `--unlock`, choose `1` to add, `2` to list service names, `3` to view credentials (master password confirmation), `4` to delete, `5` to exit. You can use `--file path/to/vault.json` to choose a different vault file.

**Never enter real passwords while demonstrating the assignment.** Use made-up examples. `vault.json`, `.env` and `.venv` are excluded via `.gitignore`.

## Run checks

```bash
pytest -q
ruff check .
ruff format --check .
mypy --strict password_manager tests
```

`.github/workflows/ci.yml` runs the same checks on every push and pull request.

## How it works

- `password_manager/main.py`: `argparse`, `getpass`, terminal menu, understandable error messages.
- `password_manager/manager.py`: `PasswordManager` stores encrypted entries and does create/read/delete, and `generate_password` makes strong passwords using `secrets`.
- `__init__` reads the vault file if it exists; `init_master` creates it once, `unlock` checks a salted verifier. `get_entry` decrypts a chosen record only after unlocking.
- `_persist` saves data as JSON using a temporary file and `os.replace` to avoid partially written vault files. `_load` reads and validates its structure.
- The vault has two independent random 16-byte salts: one for the master-password verifier and one for encryption-key derivation. Keys are derived with PBKDF2-HMAC-SHA256 (600,000 iterations); `cryptography.Fernet` handles authenticated encryption. This is an educational project, not a production security audit.

## Tests and assessment

Tests cover valid/invalid master password, blocked reinitialization, add/list/get/delete + reload, absence of plaintext secrets in JSON, generation, invalid vault, and access before unlock. The `pytest` suite runs in CI with strict typing and formatting checks.

## Limits

- `get` intentionally displays a password in the terminal after a master-password recheck; someone looking at the screen could see it.
- The vault uses an educational single-user local-file model, not a network service or multi-user database.
- This version does not migrate previous unencrypted JSON files. Back up any old **test-only** `vault.json` and initialize a new encrypted vault.
