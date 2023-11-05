# streamlit_app.py
import streamlit as st
import pandas as pd
from cryptography.fernet import Fernet
import hashlib

# Function to create a hash of a row
def create_row_hash(row):
    row_str = ''.join(str(cell) for cell in row)
    return hashlib.sha256(row_str.encode()).hexdigest()

# Load the patient data from the CSV file
def load_patient_data():
    try:
        data = pd.read_csv("patient_data.csv")
    except FileNotFoundError:
        data = pd.DataFrame(columns=["patient_id", "age", "weight", "height", "hash"])
    return data

# Load the patient IDs and their corresponding hashes from the CSV file
def load_patient_hashes():
    try:
        patient_hashes = pd.read_csv("patient_hashes.csv")
    except FileNotFoundError:
        patient_hashes = pd.DataFrame(columns=["patient_id", "hash"])
    return patient_hashes

# Function to add a new patient to the CSV file
def add_patient():
    patient_id = st.text_input("Enter patient ID:")
    age = st.text_input("Enter age:")
    weight = st.text_input("Enter weight:")
    height = st.text_input("Enter height:")

    if st.button("Add Patient"):
        # Create a new row for the patient
        new_patient = [patient_id, age, weight, height, '']

        # Load the existing patient data
        data = load_patient_data()

        # Calculate the hash of the new row
        new_hash = create_row_hash(new_patient)
        new_patient[-1] = new_hash

        # Append the new patient to the data using pandas.concat
        data = pd.concat([data, pd.DataFrame([new_patient], columns=data.columns)], ignore_index=True)

        # Save the updated data to the CSV file
        data.to_csv("patient_data.csv", index=False)
        st.success("Patient added successfully.")

        # Load the patient hashes
        patient_hashes = load_patient_hashes()

        # Check if the patient ID is in the patient_hashes
        if patient_id in patient_hashes['patient_id'].values:
            # Update the hash in patient_hashes
            patient_hashes.loc[patient_hashes['patient_id'] == patient_id, 'hash'] = new_hash
        else:
            # Add a new row for the patient in patient_hashes
            new_patient_hash = pd.DataFrame({'patient_id': [patient_id], 'hash': [new_hash]})
            patient_hashes = pd.concat([patient_hashes, new_patient_hash], ignore_index=True)

        # Save the updated patient hashes
        patient_hashes.to_csv("patient_hashes.csv", index=False)

# Function to check data integrity
def check_data_integrity():
    data = load_patient_data()
    patient_hashes = load_patient_hashes()
    compromised_rows = []
    for index, row in data.iterrows():
        expected_hash = create_row_hash(row[:-1])
        if row['hash'] != expected_hash:
            compromised_rows.append(row['patient_id'])

    if len(compromised_rows) == 0:
        st.success("Data integrity is intact. No unauthorized changes detected.")
    else:
        st.warning("Data integrity has been compromised in the following rows:")
        st.write(compromised_rows)

# Function to encrypt and save columns in a separate CSV file
def encrypt_and_save_columns():
    # Generate a Fernet key for encryption
    key = Fernet.generate_key()

    # Save and securely store this key for decryption
    with open("fernet_key.key", "wb") as key_file:
        key_file.write(key)

    # Load the patient data
    data = load_patient_data()

    # Define the columns to be encrypted
    columns_to_encrypt = ["age", "weight", "height"]

    # Create a Fernet cipher with the key
    cipher = Fernet(key)

    # Encrypt specified columns
    for col in columns_to_encrypt:
        data[col] = data[col].apply(lambda x: cipher.encrypt(str(x).encode()).decode())

    # Save the encrypted data to a separate CSV file
    data[["patient_id"] + columns_to_encrypt].to_csv("encrypted_patient_data.csv", index=False)
    st.success("Columns encrypted and saved successfully.")

def main():
    st.title("Patient Data Management")

    menu = st.sidebar.selectbox("Menu", ["Add New Patient", "Check Data Integrity", "Encrypt and Save Columns"])

    if menu == "Add New Patient":
        add_patient()
    elif menu == "Check Data Integrity":
        check_data_integrity()
    elif menu == "Encrypt and Save Columns":
        encrypt_and_save_columns()

if __name__ == "__main__":
    main()