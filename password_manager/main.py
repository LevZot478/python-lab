"""Console interface for the password manager."""

from password_manager.manager import PasswordManager


def main() -> None:
    manager = PasswordManager()

    while True:
        print("\n=== Password Manager ===")
        print("1. Add entry")
        print("2. List entries")
        print("3. Delete entry")
        print("4. Exit")

        choice = input("Choose: ")

        if choice == "1":
            name = input("Service: ")
            login = input("Login: ")
            password = input("Password (test data only): ")

            manager.add_entry(name, login, password)
            print("Entry added!")

        elif choice == "2":
            print(manager.list_entries())

        elif choice == "3":
            name = input("Service to delete: ")

            if manager.delete_entry(name):
                print("Entry deleted!")
            else:
                print("Entry not found!")

        elif choice == "4":
            print("Goodbye!")
            break

        else:
            print("Unknown command!")


if __name__ == "__main__":
    main()