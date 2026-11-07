"""Command-line interface for the encrypted password manager."""

import argparse
from getpass import getpass
from pathlib import Path

from password_manager.manager import PasswordManager, VaultError, generate_password


def _menu(manager: PasswordManager) -> None:
    """Run an interactive CRUD menu after successful authentication."""
    while True:
        print("\n=== Password Manager ===")
        print("1. Add entry")
        print("2. List services")
        print("3. Get entry")
        print("4. Delete entry")
        print("5. Exit")
        choice = input("Choose: ").strip()

        if choice == "1":
            name = input("Service: ").strip()
            login = input("Login: ").strip()
            pwd = getpass("Service password: ")
            try:
                manager.add_entry(name, login, pwd)
            except ValueError as exc:
                print(f"Error: {exc}")
            else:
                print("Entry saved.")
        elif choice == "2":
            services = manager.list_entries()
            print("Services:", ", ".join(services) if services else "(empty)")
        elif choice == "3":
            name = input("Service: ").strip()
            # Reconfirm the master password before showing a secret.
            if not manager.unlock(getpass("Confirm master password: ")):
                print("Wrong master password. Vault locked.")
                return
            entry = manager.get_entry(name)
            if entry is None:
                print("Entry not found.")
            else:
                print(f"Login: {entry['login']}")
                print(f"Password: {entry['password']}")
        elif choice == "4":
            name = input("Service to delete: ").strip()
            print("Deleted." if manager.delete_entry(name) else "Entry not found.")
        elif choice == "5":
            print("Goodbye!")
            return
        else:
            print("Unknown option. Choose 1–5.")


def main(argv: list[str] | None = None) -> int:
    """Parse CLI options, initialize or unlock the vault, and run the menu."""
    parser = argparse.ArgumentParser(description="Encrypted terminal password manager")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--init", action="store_true", help="create a new vault")
    group.add_argument("--unlock", action="store_true", help="unlock the vault and open menu")
    group.add_argument("--generate", action="store_true", help="generate a random password")
    parser.add_argument("--length", type=int, default=20, help="generated password length")
    parser.add_argument("--file", type=Path, default=Path("vault.json"), help="vault path")
    args = parser.parse_args(argv)

    try:
        if args.generate:
            print(generate_password(args.length))
            return 0

        manager = PasswordManager(args.file)
        if args.init:
            if manager.initialized:
                print("Vault already exists. Initialization refused.")
                return 1
            password = getpass("Create master password (8+ characters): ")
            confirm = getpass("Confirm master password: ")
            if password != confirm:
                print("Passwords do not match.")
                return 1
            manager.init_master(password)
            print("Encrypted vault initialized. Use --unlock to open it.")
            return 0

        if not manager.initialized:
            print("Vault does not exist. Run with --init first.")
            return 1
        if not manager.unlock(getpass("Master password: ")):
            print("Wrong master password.")
            return 1
        print("Vault unlocked.")
        _menu(manager)
        return 0
    except (VaultError, ValueError, OSError, PermissionError) as exc:
        print(f"Error: {exc}")
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
