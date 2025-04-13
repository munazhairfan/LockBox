import streamlit as st
import hashlib,time,json,string,random,os
from cryptography.fernet import Fernet

salt = b'supersecretsalt123'

fernet_key_path = "fernet.key"
if not os.path.exists(fernet_key_path):
    # First run — generate and save the key
    key = Fernet.generate_key()
    with open(fernet_key_path, "wb") as f:
        f.write(key)
else:
    # Key already exists — load it
    with open(fernet_key_path, "rb") as f:
        key = f.read()

# Now initialize the cipher with the loaded key
cipher = Fernet(key)

stored_data = {}
with open("stored_data.json","r") as f:
    stored_data = json.load(f)

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 1
failed_attempts = st.session_state.failed_attempts
if "choice" not in st.session_state:
    st.session_state.choice = "Home" 
if "locked_time" not in st.session_state:
    st.session_state.locked_time = 10
locked_time = st.session_state.locked_time

# Function to hash passkey
def hash_passkey(passkey):
    # return hashlib.sha256(passkey.encode()).hexdigest()
    derived_passkey = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return derived_passkey.hex()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()


# Function to decrypt data
def decrypt_data(user, passkey):
    hashed_passkey = hash_passkey(passkey)

    if user not in stored_data:
        st.error("This user does not exist.")
        st.session_state.failed_attempts += 1
        return None
    else:
        try:
            # text = stored_data[user]["encrypted_text"]
            stored_encrypted_text = stored_data[user]["encrypted_text"]
            stored_hash_passkey = stored_data[user]["passkey"]

            if hashed_passkey == stored_hash_passkey:

                failed_attempts = 0
                st.session_state.failed_attempts = failed_attempts
                return cipher.decrypt(stored_encrypted_text.encode()).decode()
        except Exception as e:
            st.error("Something went wrong")
            st.write(e)
    
    st.session_state.failed_attempts += 1
    return None

# Streamlit UI
st.set_page_config(page_title="LockBox",page_icon="🔓")
st.title("🔒 Secure Data Encryption System")
st.markdown(
    """
    <style>
    .stApp {
        --s: 49px; /* control the size*/
        --c1: #b5d2e8;
        --c2: #ffffff;
        --c3: #e5f2ff;
        
        --_g: var(--c3) 0 120deg,#0000 0;
        background:
            conic-gradient(from -60deg at 50% calc(100%/3),var(--_g)),
            conic-gradient(from 120deg at 50% calc(200%/3),var(--_g)),
            conic-gradient(from  60deg at calc(200%/3),var(--c3) 60deg,var(--c2) 0 120deg,#0000 0),
            conic-gradient(from 180deg at calc(100%/3),var(--c1) 60deg,var(--_g)),
            linear-gradient(90deg,var(--c1)   calc(100%/6),var(--c2) 0 50%,
                                var(--c1) 0 calc(500%/6),var(--c2) 0);
        background-size: calc(1.732*var(--s)) var(--s);
        }
            /* Style all buttons */
        .stButton > button {
            background-color: #4CAF50; /* Green background */
            color: white;              /* White text */
            border: none;              /* No border */
            padding: 0.5em 1.2em;      /* Padding */
            text-align: center;
            font-size: 16px;
            margin: 5px;
            border-radius: 8px;        /* Rounded corners */
            transition: 0.3s;
        }
    
    </style>
    """,
    unsafe_allow_html=True
)

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.choice))
st.session_state.choice = choice

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    username = st.text_input("Enter your username:")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and username:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data.update({f"{username}":{"encrypted_text": encrypted_text, "passkey": hashed_passkey}})
            with open("stored_data.json","w") as f:
                json.dump(stored_data,f,indent=4)

            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    my_container = st.empty()
        
    def lock():

        global locked_time
        while locked_time:

            time.sleep(1)
            locked_time -= 1
            st.session_state.locked_time = locked_time
            my_container.info(f"⏱ Locked Out. Try again after {locked_time} seconds.")

        st.session_state.locked_time = 10
        st.rerun()

    with my_container.container():
        username = st.text_input("Enter your username:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if passkey and username:
                decrypted_text = decrypt_data(username, passkey)

                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:

                    st.error(f"❌ Incorrect details! Attempts remaining: {3 - failed_attempts}")
                    
                    if failed_attempts >= 3:
                        st.session_state.choice = "Login"
                        st.rerun()  
                                  
                    lock()
            else:
                st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    st.toast("🔒 Too many failed attempts! Redirected to Login Page.")
    if "master_key" not in st.session_state:
        key = random.sample(string.ascii_uppercase, 2) + \
              random.sample(string.ascii_lowercase, 2) + \
              random.sample(string.digits, 3)
        random.shuffle(key)
        st.session_state.master_key = "".join(key)

    # Shows the master key in the sidebar
    st.sidebar.info(f"Your **Master Password** is `{st.session_state.master_key}`")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):

        if login_pass == st.session_state.master_key: 
            failed_attempts = 0
            del st.session_state.master_key
            st.session_state.failed_attempts = failed_attempts
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.session_state.choice = "Retrieve Data"
            st.rerun()
        else:
            st.error("❌ Incorrect password!")
