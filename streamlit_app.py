"""
Single-file Streamlit admin app that handles:
 - Supabase auth (sign-up / sign-in)
 - Initiate Composio connect flows for many providers
 - Receive Composio redirect callbacks (handled inside Streamlit by reading query params when app is opened with callback URL)
 - Save connected account metadata and encrypted token payload into Supabase
 - Manual token import (encrypted)
 - List / disconnect connected accounts

USAGE:
 - Set the following keys in Streamlit secrets or environment variables:
   SUPABASE_URL, SUPABASE_KEY, COMPOSIO_API_KEY, COMPOSIO_AUTH_CONFIG_ID, ENCRYPTION_KEY (32 url-safe base64), BACKEND_CALLBACK_BASE (optional)
 - Deploy this single file as your Streamlit app. Use the app URL as the callback URL for Composio connect flows (or provide BACKEND_CALLBACK_BASE if different).

IMPORTANT:
 - This file handles the Composio callback by detecting query parameters on app load. Make sure the Composio auth callback_url points to your Streamlit app URL.
 - For production, enable HTTPS and restrict Supabase Service Role key usage. The example uses the admin key for simplification; consider using serverless function for callback in high-security environments.
"""

import streamlit as st
from supabase import create_client, Client
from composio import Composio
from cryptography.fernet import Fernet
import json
import time
from typing import Optional

# ----------------- Page setup -----------------
st.set_page_config(page_title="Admin Console — Composio Connect", layout="wide")
st.title("🔐 Composio Admin (Single-file Streamlit)")

# ----------------- Load secrets -----------------
SUPABASE_URL = st.secrets.get("SUPABASE_URL")
SUPABASE_KEY = st.secrets.get("SUPABASE_KEY")
COMPOSIO_API_KEY = st.secrets.get("COMPOSIO_API_KEY")
COMPOSIO_AUTH_CONFIG_ID = st.secrets.get("COMPOSIO_AUTH_CONFIG_ID")
ENCRYPTION_KEY = st.secrets.get("ENCRYPTION_KEY")
# Optional: if you want callback to point to a custom domain rather than Streamlit app URL
BACKEND_CALLBACK_BASE = st.secrets.get("BACKEND_CALLBACK_BASE")

required = [SUPABASE_URL, SUPABASE_KEY, COMPOSIO_API_KEY, COMPOSIO_AUTH_CONFIG_ID, ENCRYPTION_KEY]
if not all(required):
    st.error("Missing required secrets. Please set SUPABASE_URL, SUPABASE_KEY, COMPOSIO_API_KEY, COMPOSIO_AUTH_CONFIG_ID and ENCRYPTION_KEY in Streamlit secrets.")
    st.stop()

# Validate ENCRYPTION_KEY length by trying to create Fernet
try:
    fernet = Fernet(ENCRYPTION_KEY)
except Exception as e:
    st.error(f"Invalid ENCRYPTION_KEY for Fernet: {e}. Generate with Fernet.generate_key().decode() and store in secrets.")
    st.stop()

# ----------------- Clients -----------------
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
composio = Composio(api_key=COMPOSIO_API_KEY)

# ----------------- Session state defaults -----------------
for k, v in [
    ("user_session", None),
    ("draft", ""),
    ("show_form", False),
    ("connected_account_id", None),
]:
    if k not in st.session_state:
        st.session_state[k] = v

# ----------------- Helper functions -----------------
def encrypt(plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    return fernet.decrypt(ciphertext.encode()).decode()


def save_connected_account_to_db(owner_id: str, provider: str, connected_account_id: str, payload: dict):
    """Encrypts payload and inserts into `connected_accounts` table."""
    try:
        token_encrypted = encrypt(json.dumps(payload))
        row = {
            "owner_id": owner_id,
            "provider": provider,
            "connected_account_id": connected_account_id,
            "token_encrypted": token_encrypted,
            "metadata": payload.get("metadata") if isinstance(payload, dict) else None,
        }
        supabase.table("connected_accounts").insert(row).execute()
        return True
    except Exception as e:
        st.error(f"Failed to save connected account to DB: {e}")
        return False

# ----------------- Detect Composio callback -----------------
# Composio will redirect the user to the callback URL you provided; if that callback is this Streamlit app URL
# then the query params will be available when the page loads. We detect them and store connected account details.

query_params = st.experimental_get_query_params()
if query_params:
    # If these params exist, show them and try to persist
    st.sidebar.markdown("### Callback detected")
    st.sidebar.write(query_params)

    # Expected minimal params: connected_account_id and maybe metadata
    connected_account_id = query_params.get("connected_account_id", [None])[0] or query_params.get("connectedAccountId", [None])[0]
    owner_id = query_params.get("owner_id", [None])[0] or query_params.get("ownerId", [None])[0]
    provider = query_params.get("provider", [None])[0] or (query_params.get("metadata_provider", [None])[0] if query_params.get("metadata_provider") else None)

    if connected_account_id and owner_id:
        st.sidebar.success("Callback looks valid — fetching full connected account from Composio...")
        # Try to fetch the connected account details via Composio SDK
        try:
            acct = composio.connected_accounts.get(connected_account_id)
            # acct is likely a dict-like object
            payload = acct if isinstance(acct, dict) else acct.__dict__
        except Exception:
            # If SDK doesn't support get or fails, save the raw query params
            payload = {k: v for k, v in query_params.items()}

        saved = save_connected_account_to_db(owner_id=owner_id, provider=provider or payload.get("metadata", {}).get("provider") if isinstance(payload, dict) else provider, connected_account_id=connected_account_id, payload=payload)
        if saved:
            st.sidebar.success("Connected account saved to Supabase.")
        else:
            st.sidebar.error("Failed to save connected account. Check logs.")

        # Clear query params in UI to avoid duplicate processing
        # Note: Streamlit cannot change the browser URL directly; instruct user to click a link to clear.
        st.sidebar.info("You can now navigate away or remove query params manually from the URL to avoid duplicate processing.")

# ----------------- Auth UI (sidebar) -----------------
st.sidebar.header("Account")
mode = st.sidebar.radio("Mode", ["Sign In", "Sign Up"]) 
email = st.sidebar.text_input("Email")
password = st.sidebar.text_input("Password", type="password")

if st.sidebar.button("Submit"):
    if not email or not password:
        st.sidebar.error("Provide email & password")
    else:
        try:
            if mode == "Sign Up":
                resp = supabase.auth.sign_up({"email": email, "password": password})
                st.sidebar.success("Sign-up initiated. Check your email if confirmation is required.")
            else:
                resp = supabase.auth.sign_in_with_password({"email": email, "password": password})
                # Supabase Python client returns a dict with 'access_token' and 'user'
                if resp and (resp.get("access_token") or resp.get("user")):
                    st.session_state.user_session = resp
                    st.sidebar.success("Signed in")
                else:
                    st.sidebar.error("Sign-in failed")
        except Exception as e:
            st.sidebar.error(f"Auth error: {e}")

# If previously signed in via session_state
if st.session_state.get("user_session"):
    user_session = st.session_state.get("user_session")
else:
    user_session = None

if not user_session:
    st.info("Please sign in via the sidebar to manage connections.")
    st.stop()

# Extract user id
user = user_session.get("user") if isinstance(user_session, dict) else None
user_id = None
if user and isinstance(user, dict):
    user_id = user.get("id")
# fallback: try access token as id (not ideal) — recommended to use user.id
if not user_id:
    user_id = user_session.get("user_id") or user_session.get("access_token")

st.markdown(f"**Signed in as:** `{email}`  •  `user_id: {user_id}`")

# ----------------- Providers list -----------------
PROVIDERS = [
    ("gmail", "Gmail"),
    ("outlook", "Outlook / Office365"),
    ("slack", "Slack"),
    ("teams", "Microsoft Teams"),
    ("atlassian", "Atlassian"),
    ("notion", "Notion"),
    ("hubspot", "HubSpot"),
    ("freshdesk", "Freshdesk"),
    ("jira", "Jira"),
    ("linkedin", "LinkedIn"),
]

# ----------------- Connected accounts (list) -----------------
st.header("Connected Accounts")
try:
    res = supabase.table("connected_accounts").select("id, owner_id, provider, connected_account_id, created_at, metadata").eq("owner_id", user_id).execute()
    rows = res.data or []
except Exception as e:
    st.error(f"Failed to fetch connected accounts: {e}")
    rows = []

if not rows:
    st.info("No connected accounts saved for this user yet.")
else:
    for r in rows:
        c1, c2, c3, c4 = st.columns([2,2,2,1])
        c1.write(r.get("provider"))
        c2.write(r.get("connected_account_id"))
        c3.write(r.get("created_at"))
        if c4.button("Disconnect", key=f"disc_{r.get('id')}"):
            try:
                supabase.table("connected_accounts").delete().eq("id", r.get("id")).execute()
                st.experimental_rerun()
            except Exception as e:
                st.error(f"Failed to disconnect: {e}")

st.markdown("---")

# ----------------- Initiate Composio connect flow -----------------
st.header("Add / Configure a Provider")
provider = st.selectbox("Provider", [p[1] for p in PROVIDERS])
prov_key = [p[0] for p in PROVIDERS][[p[1] for p in PROVIDERS].index(provider)]
account_label = st.text_input("Account label (optional)")

if st.button("Start Connect Flow"):
    try:
        # Build callback URL that returns to this same Streamlit app
        if BACKEND_CALLBACK_BASE:
            callback_url = f"{BACKEND_CALLBACK_BASE}/?owner_id={user_id}&provider={prov_key}"
        else:
            # Use current page URL as callback. Streamlit does not expose a direct runtime URL - instruct user to copy app URL.
            app_url = st.experimental_get_query_params().get("__app_url", [""])[0]
            # Fallback: instruct user to replace with their deployed app URL.
            callback_url = st.text_input("Enter the public callback URL for this app (the full URL of this Streamlit app):")
            if not callback_url:
                st.error("Enter the public callback URL of your deployed Streamlit app. This is required for the OAuth redirect.")
                st.stop()
            # append params
            callback_url = f"{callback_url}?owner_id={user_id}&provider={prov_key}"

        conn_req = composio.connected_accounts.initiate(
            user_id=user_id,
            auth_config_id=COMPOSIO_AUTH_CONFIG_ID,
            callback_url=callback_url,
            metadata={"provider": prov_key, "label": account_label},
        )
        st.success("Connection initiated. Click the link below to authenticate the provider.")
        st.markdown(f"[Open authentication]({conn_req.redirect_url})")
        st.info("After completing provider authentication, Composio will redirect to the callback URL and this Streamlit app will detect the query params and store the connected account.")
    except Exception as e:
        st.error(f"Failed to initiate connection: {e}")

st.markdown("---")

# ----------------- Manual token import -----------------
st.header("Manual Token Import (for testing)")
st.info("Paste the raw token / payload from a provider (or the connected account JSON). It will be encrypted and stored.")
with st.form("manual_token_form"):
    prov = st.selectbox("Provider (manual)", [p[1] for p in PROVIDERS], key="manual_provider")
    prov_key = [p[0] for p in PROVIDERS][[p[1] for p in PROVIDERS].index(prov)]
    token = st.text_area("Raw token / JSON payload")
    submit = st.form_submit_button("Save token")
    if submit:
        if not token.strip():
            st.error("Provide token payload")
        else:
            payload = None
            try:
                payload = json.loads(token)
            except Exception:
                # allow non-json tokens; wrap in dict
                payload = {"raw": token}
            encrypted = encrypt(json.dumps(payload))
            try:
                supabase.table("connected_accounts").insert({
                    "owner_id": user_id,
                    "provider": prov_key,
                    "connected_account_id": f"manual-{int(time.time())}",
                    "token_encrypted": encrypted,
                    "metadata": payload.get("metadata") if isinstance(payload, dict) else None,
                }).execute()
                st.success("Token saved (encrypted) into Supabase")
                st.experimental_rerun()
            except Exception as e:
                st.error(f"Failed to save token: {e}")

st.markdown("---")

# ----------------- Developer utilities -----------------
st.header("Developer / Admin Utilities")
if st.checkbox("Show raw connected_accounts rows (debug)"):
    try:
        all_rows = supabase.table("connected_accounts").select("*").eq("owner_id", user_id).execute().data
        st.write(all_rows)
    except Exception as e:
        st.error(f"Failed to fetch rows: {e}")

st.markdown("---")

st.info("Next: I can provide the SQL schema and RLS policies for the `connected_accounts` table. Ask me to 'give SQL schema + RLS' and I'll paste ready-to-run SQL for Supabase.")
