import os
from cryptography.fernet import Fernet
import json

PASSWORD_FILE = 'passwords.json'
KEY_FILE = 'key.key'

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)

def load_key():
    return open(KEY_FILE, 'rb').read()

def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

def add_password(service, username, password, key):
    encrypted_password = encrypt_message(password, key)
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r') as file:
            passwords = json.load(file)
    else:
        passwords = {}

    passwords[service] = {
        'username': username,
        'password': encrypted_password.decode() 
    }

    with open(PASSWORD_FILE, 'w') as file:
        json.dump(passwords, file)

def get_password(service, key):
    """Retrieve a password."""
    with open(PASSWORD_FILE, 'r') as file:
        passwords = json.load(file)

    if service in passwords:
        encrypted_password = passwords[service]['password'].encode()  
        password = decrypt_message(encrypted_password, key)
        return passwords[service]['username'], password
    else:
        return None, None

def main():
    if not os.path.exists(KEY_FILE):
        generate_key()

    key = load_key()

    while True:
        print("Password Manager")
        print("1. Add a new password")
        print("2. Retrieve a password")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            service = input("Enter the service name: ")
            username = input("Enter the username: ")
            password = input("Enter the password: ")
            add_password(service, username, password, key)
            print("Password added successfully.")

        elif choice == '2':
            service = input("Enter the service name: ")
            username, password = get_password(service, key)
            if username:
                print(f"Username: {username}")
                print(f"Password: {password}")
            else:
                print("Service not found.")

        elif choice == '3':
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()


