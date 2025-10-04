import streamlit as st
from supabase import create_client, Client
from composio import Composio
import os
import json

# --- Page Setup ---
st.set_page_config(page_title="Admin Tool", page_icon="🛡️", layout="wide")
st.title("🛡️ Compliance Admin Tool")

# --- Supabase Config ---
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- Composio Config ---
COMPOSIO_API_KEY = st.secrets["COMPOSIO_API_KEY"]
AUTH_CONFIG_ID = st.secrets["COMPOSIO_AUTH_CONFIG_ID"]

composio_client = Composio(api_key=COMPOSIO_API_KEY)

# --- Session State ---
if "user" not in st.session_state:
    st.session_state.user = None
if "connected_account_id" not in st.session_state:
    st.session_state.connected_account_id = None

# --- Auth Functions ---
def signup(email, password):
    auth = supabase.auth.sign_up({"email": email, "password": password})
    if "user" in auth and auth["user"]:
        st.success("✅ Signup successful. Please log in.")
    else:
        st.error("Signup failed. Try a different email.")

def login(email, password):
    auth = supabase.auth.sign_in_with_password({"email": email, "password": password})
    if auth and "user" in auth and auth["user"]:
        st.session_state.user = auth["user"]
        st.success(f"✅ Logged in as {auth['user']['email']}")
    else:
        st.error("Login failed.")

def logout():
    st.session_state.user = None
    st.session_state.connected_account_id = None
    st.success("Logged out.")

# --- Save Connected Account ---
def save_connected_account(user_id, provider, connected_account_id, payload):
    supabase.table("connected_accounts").insert({
        "user_id": user_id,
        "provider": provider,
        "connected_account_id": connected_account_id,
        "token_payload": payload
    }).execute()

# --- Fetch Connected Accounts ---
def get_connected_accounts(user_id):
    res = supabase.table("connected_accounts").select("*").eq("user_id", user_id).execute()
    return res.data if res.data else []

def remove_connected_account(account_id):
    supabase.table("connected_accounts").delete().eq("id", account_id).execute()
    st.success("Account removed.")

# --- Composio Connect ---
def connect_account(provider, user_id):
    try:
        conn_req = composio_client.connected_accounts.initiate(
            user_id=user_id,
            auth_config_id=AUTH_CONFIG_ID,
            callback_url="https://your-app.streamlit.app/"  # replace with deployed URL
        )
        st.markdown(f"[🔗 Connect {provider}]({conn_req.redirect_url})")
    except Exception as e:
        st.error(f"Connection Error: {e}")

# --- Callback Handling ---
query_params = st.query_params
if "connected_account_id" in query_params:
    connected_id = query_params["connected_account_id"]
    if st.session_state.user:
        save_connected_account(
            st.session_state.user["id"],
            "generic",
            connected_id,
            {"info": "Saved without encryption"}
        )
        st.success("✅ Account connected and saved to Supabase!")
    st.query_params.clear()

# --- UI ---
if not st.session_state.user:
    tab1, tab2 = st.tabs(["🔑 Login", "🆕 Signup"])
    with tab1:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_pw")
        if st.button("Login"):
            login(email, password)
    with tab2:
        email = st.text_input("Email", key="signup_email")
        password = st.text_input("Password", type="password", key="signup_pw")
        if st.button("Signup"):
            signup(email, password)
else:
    st.sidebar.success(f"Logged in as {st.session_state.user['email']}")
    if st.sidebar.button("Logout"):
        logout()

    st.header("🔗 Connect Your Accounts")

    providers = ["gmail", "slack", "jira", "notion", "hubspot", "freshdesk", "linkedin", "outlook", "teams"]
    for provider in providers:
        connect_account(provider, st.session_state.user["id"])

    st.divider()
    st.subheader("📂 Your Connected Accounts")

    accounts = get_connected_accounts(st.session_state.user["id"])
    if accounts:
        for acc in accounts:
            st.json(acc)
            if st.button(f"Remove {acc['provider']}", key=f"rm_{acc['id']}"):
                remove_connected_account(acc["id"])
    else:
        st.info("No accounts connected yet.")
