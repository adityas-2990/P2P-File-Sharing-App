import sqlite3
import pandas as pd
import streamlit as st

# Path to the database
db_path = 'file_sharing_app.db'

def show_all_users():
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Retrieve all contents of the 'users' table
        cursor.execute("SELECT id, username, password_hash, private_key, public_key FROM users")
        users = cursor.fetchall()

        if users:
            # Create a pandas DataFrame to display in Streamlit
            users_df = pd.DataFrame(users, columns=["User ID", "Username", "Password Hash", "Private Key (truncated)", "Public Key (truncated)"])
            users_df["Private Key (truncated)"] = users_df["Private Key (truncated)"].apply(lambda x: x[:50].decode('utf-8', errors='ignore') + '...')  # Decode bytes to string
            users_df["Public Key (truncated)"] = users_df["Public Key (truncated)"].apply(lambda x: x[:50].decode('utf-8', errors='ignore') + '...')  # Decode bytes to string

            st.write("### Users Table")
            st.dataframe(users_df)  # Display the DataFrame in a table format
        else:
            st.write("No users found in the database.")
        
        conn.close()
    except sqlite3.Error as e:
        st.error(f"Database access error: {e}")

def show_all_files():
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Retrieve all contents of the 'files' table
        cursor.execute("SELECT id, sender, receiver, filename, file_data FROM files")
        files = cursor.fetchall()

        if files:
            # Create a pandas DataFrame to display in Streamlit
            files_df = pd.DataFrame(files, columns=["File ID", "Sender", "Receiver", "Filename", "File Data (truncated)"])
            files_df["File Data (truncated)"] = files_df["File Data (truncated)"].apply(lambda x: x[:50].decode('utf-8', errors='ignore') + '...')  # Decode bytes to string

            st.write("### Files Table")
            st.dataframe(files_df)  # Display the DataFrame in a table format
        else:
            st.write("No files found in the database.")
        
        conn.close()
    except sqlite3.Error as e:
        st.error(f"Database access error: {e}")

# Main Streamlit app logic
def main():
    st.title("Database Content Viewer")

    # Sidebar options
    option = st.sidebar.selectbox("Select Table to View", ["Users", "Files"])

    if option == "Users":
        show_all_users()  # Show the users table
    elif option == "Files":
        show_all_files()  # Show the files table

if __name__ == "__main__":
    main()
