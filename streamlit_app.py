import os
import streamlit as st
from supabase import create_client
from composio import Composio

# --- Page Setup ---
st.set_page_config(page_title="Composio Admin", layout="wide", page_icon="⚙️")
st.title("⚙️ Composio Admin Dashboard")

# --- Load Environment Variables ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
COMPOSIO_API_KEY = os.environ.get("COMPOSIO_API_KEY")

if not (SUPABASE_URL and SUPABASE_KEY and COMPOSIO_API_KEY):
    st.error("❌ Missing required environment variables: SUPABASE_URL, SUPABASE_KEY, COMPOSIO_API_KEY")
    st.stop()

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
composio = Composio(api_key=COMPOSIO_API_KEY)

# --- Authentication (Sign Up / Sign In) ---
if "user_session" not in st.session_state:
    st.session_state.user_session = None

st.sidebar.header("🔑 Authentication")
mode = st.sidebar.radio("Choose mode", ["Sign In", "Sign Up"])
email = st.sidebar.text_input("Email")
password = st.sidebar.text_input("Password", type="password")

if st.sidebar.button("Submit"):
    if not email or not password:
        st.sidebar.error("Provide email & password")
    else:
        try:
            if mode == "Sign Up":
                resp = supabase.auth.sign_up({"email": email, "password": password})
                if resp.user:
                    st.sidebar.success("✅ Sign-up successful. Check email if confirmation required.")
                else:
                    st.sidebar.error("❌ Sign-up failed.")
            else:
                resp = supabase.auth.sign_in_with_password({"email": email, "password": password})
                if resp and resp.user:
                    st.session_state.user_session = {
                        "user": resp.user.model_dump(),
                        "access_token": resp.session.access_token if resp.session else None,
                    }
                    st.sidebar.success(f"✅ Signed in as {resp.user.email}")
                else:
                    st.sidebar.error("❌ Sign-in failed.")
        except Exception as e:
            st.sidebar.error(f"Auth error: {e}")

if not st.session_state.user_session:
    st.info("👆 Please sign in to continue.")
    st.stop()

user_id = st.session_state.user_session["user"]["id"]

# --- Callback handling (Composio redirect) ---
st.sidebar.header("🔄 Callback Handler")
callback_code = st.sidebar.text_input("Paste 'code' from Composio redirect URL here")
provider = st.sidebar.text_input("Provider (e.g., gmail, slack)")

if st.sidebar.button("Save Callback"):
    if not callback_code or not provider:
        st.sidebar.error("Need both code and provider")
    else:
        try:
            # In real use, you'd exchange callback_code for tokens via Composio API
            fake_payload = {"code": callback_code, "provider": provider}
            supabase.table("connected_accounts").insert({
                "user_id": user_id,
                "provider": provider,
                "connected_account_id": f"{provider}_dummy",
                "token_payload": fake_payload
            }).execute()
            st.sidebar.success("✅ Connected account saved.")
        except Exception as e:
            st.sidebar.error(f"Save error: {e}")

# --- Account Management ---
st.subheader("🔗 Manage Connected Accounts")

# List accounts
accounts = supabase.table("connected_accounts").select("*").eq("user_id", user_id).execute()
if accounts.data:
    for acc in accounts.data:
        st.json(acc)
        if st.button(f"❌ Disconnect {acc['provider']} ({acc['id']})"):
            supabase.table("connected_accounts").delete().eq("id", acc["id"]).execute()
            st.success(f"Disconnected {acc['provider']}")
            st.rerun()
else:
    st.info("No connected accounts yet.")

# Manual Import
st.subheader("📥 Manual Import")
provider = st.text_input("Provider name (e.g. notion, jira)")
token_json = st.text_area("Paste token payload (JSON)")
if st.button("Import Account"):
    if not provider or not token_json.strip():
        st.error("Need provider and payload")
    else:
        try:
            import json
            payload = json.loads(token_json)
            supabase.table("connected_accounts").insert({
                "user_id": user_id,
                "provider": provider,
                "connected_account_id": f"{provider}_manual",
                "token_payload": payload
            }).execute()
            st.success("✅ Account imported.")
            st.rerun()
        except Exception as e:
            st.error(f"Import failed: {e}")
