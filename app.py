import streamlit as st
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
        aes_key BLOB NOT NULL
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

def get_user_aes_key(username):
    # Retrieve the AES key for the given username
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()
    cursor.execute('SELECT aes_key FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def register_user(username, password):
    # Connect to the database
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()

    # Hash the password with the correct method
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    # Generate a random AES key (32 bytes for AES-256)
    aes_key = os.urandom(32)

    try:
        # Insert user data into the table
        cursor.execute('''
        INSERT INTO users (username, password_hash, aes_key)
        VALUES (?, ?, ?)
        ''', (username, password_hash, aes_key))

        # Commit the changes
        conn.commit()
        st.success(f"User {username} registered successfully.")
    except sqlite3.IntegrityError:
        st.error("Username already exists.")
    finally:
        # Close the connection
        conn.close()

def login_user(username, password):
    # Connect to the database
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()

    # Retrieve user data based on the username
    cursor.execute('''
    SELECT password_hash, aes_key FROM users WHERE username = ?
    ''', (username,))
    result = cursor.fetchone()

    if result:
        stored_password_hash, aes_key = result
        # Verify the password
        if check_password_hash(stored_password_hash, password):
            st.success("Login successful.")
            # Store login state and AES key in session state
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.aes_key = aes_key
            return aes_key
        else:
            st.error("Incorrect password.")
    else:
        st.error("User not found.")

    # Close the connection
    conn.close()
    return None

def encrypt_file(file_data, aes_key):
    # Encrypt the file data using AES
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce + tag + ciphertext  # Concatenate nonce, tag, and ciphertext

def decrypt_file(encrypted_data, aes_key):
    # Decrypt the file data using AES
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def send_file(sender, receiver, file_name, file_data):
    # Get the AES key of the receiver
    receiver_aes_key = get_user_aes_key(receiver)
    if not receiver_aes_key:
        st.error("Recipient not found.")
        return

    # Encrypt the file with the receiver's AES key
    encrypted_file_data = encrypt_file(file_data, receiver_aes_key)

    # Save the file to the database
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO files (sender, receiver, filename, file_data)
    VALUES (?, ?, ?, ?)
    ''', (sender, receiver, file_name, encrypted_file_data))
    conn.commit()
    conn.close()
    st.success(f"File '{file_name}' sent to {receiver} successfully.")

def list_received_files(username):
    # Retrieve files sent to the logged-in user
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()
    cursor.execute('''
    SELECT id, sender, filename FROM files WHERE receiver = ?
    ''', (username,))
    files = cursor.fetchall()
    conn.close()
    return files

def get_file_data(file_id):
    # Retrieve file data based on file ID
    conn = sqlite3.connect('file_sharing_app.db')
    cursor = conn.cursor()
    cursor.execute('SELECT filename, file_data FROM files WHERE id = ?', (file_id,))
    result = cursor.fetchone()
    conn.close()
    return result

def file_sharing_interface(username, aes_key):
    st.subheader("File Sharing Interface")
    tabs = st.tabs(["Send File", "Received Files"])

    with tabs[0]:  # Send File tab
        st.write("### Send File")
        recipient = st.text_input("Recipient Username", key="recipient_username")
        file_to_send = st.file_uploader("Choose a file to send", type=["txt", "pdf", "jpg", "png", "docx"], key="file_uploader")

        if file_to_send and recipient:
            file_data = file_to_send.read()
            file_name = file_to_send.name

            if st.button("Send File", key="send_file_button"):
                send_file(username, recipient, file_name, file_data)

    with tabs[1]:  # Received Files tab
        st.write("### Received Files")

        # Retrieve files that were sent to the logged-in user
        files = list_received_files(username)
        if files:
            for file_id, sender, file_name in files:
                st.write(f"File from {sender}: {file_name}")
                
                # Button to download the file
                if st.button(f"Download {file_name}", key=f"download_button_{file_id}"):
                    # Fetch the encrypted file from the database
                    file_name, encrypted_data = get_file_data(file_id)

                    # Decrypt the file using the receiver's AES key
                    decrypted_data = decrypt_file(encrypted_data, aes_key)

                    # Provide the file as a downloadable button
                    st.download_button(label=f"Download {file_name}",
                                    data=decrypted_data,
                                    file_name=file_name,
                                    mime="application/octet-stream")
        else:
            st.write("No files received yet.")

def main():
    st.title("Secure File Sharing App")
    
    # Initialize session state for login
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'aes_key' not in st.session_state:
        st.session_state.aes_key = None

    menu = ["Register", "Login"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Register":
        st.subheader("Create a New Account")
        username = st.text_input("Username", key="register_username")
        password = st.text_input("Password", type="password", key="register_password")
        if st.button("Register", key="register_button"):
            if username and password:
                register_user(username, password)
            else:
                st.warning("Please enter both username and password")

    elif choice == "Login" and not st.session_state.logged_in:
        st.subheader("Login to Your Account")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login", key="login_button"):
            if username and password:
                aes_key = login_user(username, password)
                if aes_key:
                    st.session_state.logged_in = True
                    #st.experimental_rerun()
            else:
                st.warning("Please enter both username and password")

    # If logged in, display the file sharing interface only once
    if st.session_state.logged_in:
        file_sharing_interface(st.session_state.username, st.session_state.aes_key)

if __name__ == '__main__':
    main()
