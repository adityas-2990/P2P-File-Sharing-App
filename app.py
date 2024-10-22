import streamlit as st
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

# Database setup
def init_db():
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()

    # Create a table for storing user information
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        private_key BLOB NOT NULL,
        public_key BLOB NOT NULL
    )
    ''')

    # Create a table for storing file information
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        filename TEXT NOT NULL,
        file_data BLOB NOT NULL
    )
    ''')

    # Commit changes and close the connection
    conn.commit()
    conn.close()

# Initialize the database
init_db()

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt the private key using the password-derived AES key
def encrypt_private_key(private_key, password):
    salt = get_random_bytes(16)  # Generate a salt for key derivation
    aes_key = PBKDF2(password, salt, dkLen=32, count=1000000)  # Derive AES-256 key from the password

    cipher = AES.new(aes_key, AES.MODE_CBC)  # AES cipher in CBC mode
    iv = cipher.iv  # Initialization vector
    encrypted_private_key = cipher.encrypt(pad(private_key, AES.block_size))  # Encrypt the private key

    return salt, iv, encrypted_private_key

# Decrypt the private key using the password-derived AES key
def decrypt_private_key(encrypted_private_key_data, password):
    salt = encrypted_private_key_data[:16]  # First 16 bytes are the salt
    iv = encrypted_private_key_data[16:32]  # Next 16 bytes are the IV
    encrypted_private_key = encrypted_private_key_data[32:]  # The rest is the encrypted private key

    # Derive the AES key from the password using the salt
    aes_key = PBKDF2(password, salt, dkLen=32, count=1000000)

    # Decrypt the private key
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    private_key = unpad(cipher.decrypt(encrypted_private_key), AES.block_size)

    return private_key

# User registration
def register_user(username, password):
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()

    # Hash the password for future login verification
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    # Generate RSA keys
    private_key, public_key = generate_rsa_keypair()

    # Encrypt the private key using the user's password
    salt, iv, encrypted_private_key = encrypt_private_key(private_key, password)

    try:
        # Store the encrypted private key (salt + iv + encrypted_private_key) and the public key
        cursor.execute('''
        INSERT INTO users (username, password_hash, private_key, public_key)
        VALUES (?, ?, ?, ?)
        ''', (username, password_hash, salt + iv + encrypted_private_key, public_key))

        # Commit changes
        conn.commit()
        st.success(f"User {username} registered successfully.")
    except sqlite3.IntegrityError:
        st.error("Username already exists.")
    finally:
        conn.close()

# Retrieve user's public and private keys
def get_user_keys(username):
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()
    cursor.execute('SELECT private_key, public_key FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result  # Returns (private_key, public_key)

# User login
def login_user(username, password):
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()

    # Retrieve the password hash and encrypted private key from the database
    cursor.execute('''
    SELECT password_hash, private_key FROM users WHERE username = ?
    ''', (username,))
    result = cursor.fetchone()

    if result:
        stored_password_hash, encrypted_private_key_data = result
        if check_password_hash(stored_password_hash, password):
            st.success("Login successful.")
            st.session_state.logged_in = True
            st.session_state.username = username

            # Decrypt the private key using the user's password
            private_key = decrypt_private_key(encrypted_private_key_data, password)
            st.session_state.private_key = private_key

            # Fetch the public key from the database
            _, public_key = get_user_keys(username)
            st.session_state.public_key = public_key

            return public_key
        else:
            st.error("Incorrect password.")
    else:
        st.error("User not found.")

    conn.close()
    return None

# AES Encryption
def encrypt_file_with_aes(file_data):
    aes_key = get_random_bytes(32)  # AES-256 key
    aes_iv = get_random_bytes(16)   # AES initialization vector
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
    return aes_key, aes_iv, encrypted_data

def decrypt_file_with_aes(encrypted_data, aes_key, aes_iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

# RSA Encryption
def encrypt_file_with_rsa(data, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def decrypt_file_with_rsa(encrypted_data, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_data)

# Sending a file
def send_file(sender, receiver, file_name, file_data):
    keys = get_user_keys(receiver)
    
    if keys is None:
        st.error(f"Recipient '{receiver}' not found.")
        return

    _, receiver_public_key = keys

    aes_key, aes_iv, encrypted_file_data = encrypt_file_with_aes(file_data)
    encrypted_aes_key = encrypt_file_with_rsa(aes_key + aes_iv, receiver_public_key)

    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO files (sender, receiver, filename, file_data)
    VALUES (?, ?, ?, ?)
    ''', (sender, receiver, file_name, encrypted_aes_key + encrypted_file_data))
    conn.commit()
    conn.close()
    st.success(f"File '{file_name}' sent to {receiver} successfully.")

# Listing received files
def list_received_files(username):
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()
    cursor.execute('''
    SELECT id, sender, filename, file_data FROM files WHERE receiver = ?
    ''', (username,))
    files = cursor.fetchall()
    conn.close()

    if files:
        for file_id, sender, file_name, encrypted_data in files:
            st.write(f"File from {sender}: {file_name}")

            encrypted_aes_key = encrypted_data[:256]  # RSA-encrypted AES key
            encrypted_file_data = encrypted_data[256:]

            aes_key_iv = decrypt_file_with_rsa(encrypted_aes_key, st.session_state.private_key)
            aes_key, aes_iv = aes_key_iv[:32], aes_key_iv[32:]

            decrypted_data = decrypt_file_with_aes(encrypted_file_data, aes_key, aes_iv)

            st.download_button(label=f"Download {file_name}",
                            data=decrypted_data,
                            file_name=file_name,
                            mime="application/octet-stream",
                            key=f"download_button_{file_id}")
    else:
        st.write("No files received yet.")

# File sharing interface
def file_sharing_interface(username):
    st.subheader("File Sharing Interface")
    tabs = st.tabs(["Send File", "Received Files"])

    with tabs[0]:
        st.write("### Send File")
        recipient = st.text_input("Recipient Username", key="recipient_username")
        file_to_send = st.file_uploader("Choose a file to send", type=["txt", "pdf", "jpg", "png", "docx"], key="file_uploader")

        if file_to_send and recipient:
            file_data = file_to_send.read()
            file_name = file_to_send.name
            if st.button("Send File", key="send_file_button"):
                send_file(username, recipient, file_name, file_data)

    with tabs[1]:
        st.write("### Received Files")
        list_received_files(username)

# Main function
def main():
    st.title("Secure File Sharing App")

    # Session state to track login status
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    # Login and registration interface
    if not st.session_state.logged_in:
        st.subheader("Login or Register")

        tabs = st.tabs(["Login", "Register"])

        with tabs[0]:
            st.write("### Login")
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            if st.button("Login", key="login_button"):
                login_user(username, password)

        with tabs[1]:
            st.write("### Register")
            new_username = st.text_input("New Username", key="register_username")
            new_password = st.text_input("New Password", type="password", key="register_password")
            if st.button("Register", key="register_button"):
                register_user(new_username, new_password)

    # If logged in, show file sharing interface
    if st.session_state.logged_in:
        st.success(f"Welcome, {st.session_state.username}!")
        file_sharing_interface(st.session_state.username)

if __name__ == '__main__':
    main()
