# streamlit_app.py
import streamlit as st
import json
import time
from cryptography.fernet import Fernet
from supabase import create_client, Client
from composio import Composio
from typing import Any, Dict, Optional

# ---------------- Page & secrets ----------------
st.set_page_config(page_title="Composio Admin (Single-file)", layout="wide", page_icon="🔐")
st.title("🔐 Composio Admin Console")

# Load secrets (prefer st.secrets in Streamlit Cloud; fallback to env)
SUPABASE_URL = st.secrets.get("SUPABASE_URL") or st.experimental_getenv("SUPABASE_URL")
SUPABASE_KEY = st.secrets.get("SUPABASE_KEY") or st.experimental_getenv("SUPABASE_KEY")
COMPOSIO_API_KEY = st.secrets.get("COMPOSIO_API_KEY") or st.experimental_getenv("COMPOSIO_API_KEY")
COMPOSIO_AUTH_CONFIG_ID = st.secrets.get("COMPOSIO_AUTH_CONFIG_ID") or st.experimental_getenv("COMPOSIO_AUTH_CONFIG_ID")
ENCRYPTION_KEY = st.secrets.get("ENCRYPTION_KEY") or st.experimental_getenv("ENCRYPTION_KEY")
APP_PUBLIC_CALLBACK_URL = st.secrets.get("APP_PUBLIC_CALLBACK_URL") or st.experimental_getenv("APP_PUBLIC_CALLBACK_URL")

required = [SUPABASE_URL, SUPABASE_KEY, COMPOSIO_API_KEY, COMPOSIO_AUTH_CONFIG_ID, ENCRYPTION_KEY, APP_PUBLIC_CALLBACK_URL]
if not all(required):
    st.error(
        "Missing required secrets. Ensure SUPABASE_URL, SUPABASE_KEY, COMPOSIO_API_KEY, "
        "COMPOSIO_AUTH_CONFIG_ID, ENCRYPTION_KEY, and APP_PUBLIC_CALLBACK_URL are set."
    )
    st.stop()

# init clients
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    st.error(f"Failed to init Supabase client: {e}")
    st.stop()

try:
    composio = Composio(api_key=COMPOSIO_API_KEY)
except Exception as e:
    st.error(f"Failed to init Composio client: {e}")
    st.stop()

# init encryption
try:
    fernet = Fernet(ENCRYPTION_KEY)
except Exception as e:
    st.error(f"Invalid ENCRYPTION_KEY: {e}. Generate via Fernet.generate_key().decode() and store it.")
    st.stop()

# ---------------- Session defaults ----------------
if "user_session" not in st.session_state:
    st.session_state["user_session"] = None

# ---------------- Utility funcs ----------------
def encrypt_obj(obj: Any) -> str:
    return fernet.encrypt(json.dumps(obj).encode()).decode()

def decrypt_obj(token: str) -> Any:
    return json.loads(fernet.decrypt(token.encode()).decode())

def save_connected_account(owner_id: str, provider: str, connected_account_id: str, payload: Dict[str, Any]) -> bool:
    try:
        token_encrypted = encrypt_obj(payload)
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
        st.error(f"DB insert error: {e}")
        return False

def fetch_connected_accounts(owner_id: str):
    try:
        r = supabase.table("connected_accounts").select("id, owner_id, provider, connected_account_id, created_at, metadata").eq("owner_id", owner_id).execute()
        return r.data or []
    except Exception as e:
        st.error(f"DB fetch error: {e}")
        return []

def delete_connected_account(row_id: str):
    try:
        supabase.table("connected_accounts").delete().eq("id", row_id).execute()
        return True
    except Exception as e:
        st.error(f"DB delete error: {e}")
        return False

# ---------------- Auth UI (sidebar) ----------------
st.sidebar.header("Account (Supabase Auth)")
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
                # The python client returns an object with .user property
                if getattr(resp, "user", None):
                    st.sidebar.success("Signup started. Check email for confirmation if enabled.")
                elif isinstance(resp, dict) and resp.get("user"):
                    st.sidebar.success("Signup started. Check email for confirmation if enabled.")
                else:
                    st.sidebar.error("Signup failed. Check Supabase logs.")
            else:
                resp = supabase.auth.sign_in_with_password({"email": email, "password": password})
                # handle both SDK shapes: object with .user / .session OR dict with keys
                user_obj = None
                access_token = None
                if hasattr(resp, "user") and resp.user:
                    try:
                        # convert pydantic model to dict if needed
                        user_obj = resp.user.model_dump() if hasattr(resp.user, "model_dump") else dict(resp.user)
                    except Exception:
                        user_obj = resp.user
                    access_token = getattr(resp.session, "access_token", None) if getattr(resp, "session", None) else None
                elif isinstance(resp, dict):
                    user_obj = resp.get("user")
                    session = resp.get("session") or resp.get("access_token")
                    access_token = session if isinstance(session, str) else (session.get("access_token") if session else None)

                if user_obj:
                    st.session_state["user_session"] = {"user": user_obj, "access_token": access_token}
                    st.sidebar.success(f"Signed in as {user_obj.get('email')}")
                else:
                    st.sidebar.error("Sign-in failed. Check credentials or Supabase settings.")
        except Exception as e:
            st.sidebar.error(f"Auth error: {e}")

# stop if not signed in
if not st.session_state["user_session"]:
    st.info("Please sign in using the sidebar to manage provider connections.")
    st.stop()

# extract user id
user = st.session_state["user_session"]["user"]
user_id = user.get("id") or user.get("user_id") or None
if not user_id:
    st.error("Unable to determine signed-in user_id from Supabase auth response.")
    st.stop()

st.markdown(f"**Signed in as:** `{user.get('email')}`  •  `user_id: {user_id}`")

# ---------------- Composio callback detection ----------------
# Composio will redirect to a public URL (APP_PUBLIC_CALLBACK_URL). We expect query params in the URL:
# e.g. ?connected_account_id=xxx&owner_id=<user_id>&provider=gmail
query_params = st.experimental_get_query_params()
if query_params:
    st.sidebar.markdown("### Callback detected")
    st.sidebar.write(query_params)
    connected_account_id = (query_params.get("connected_account_id") or query_params.get("connectedAccountId") or [None])[0]
    owner_id_param = (query_params.get("owner_id") or query_params.get("ownerId") or [None])[0]
    provider_param = (query_params.get("provider") or [None])[0]

    if connected_account_id and owner_id_param:
        st.sidebar.success("Callback looks valid — attempting to fetch connected-account info via Composio SDK...")
        try:
            # SDK may have `.get` — try it; fallback to saving query params only
            acct = None
            try:
                acct = composio.connected_accounts.get(connected_account_id)
                payload = acct if isinstance(acct, dict) else (acct.__dict__ if hasattr(acct, "__dict__") else json.loads(json.dumps(acct)))
            except Exception:
                payload = {k: v for k, v in query_params.items()}

            saved = save_connected_account(owner_id_param, provider_param or payload.get("metadata", {}).get("provider") if isinstance(payload, dict) else provider_param, connected_account_id, payload)
            if saved:
                st.sidebar.success("Connected account saved.")
            else:
                st.sidebar.error("Failed to persist connected account.")
        except Exception as e:
            st.sidebar.error(f"Callback handling error: {e}")

        st.sidebar.info("Remove query params from URL or navigate away to prevent duplicate processing.")

# ---------------- Providers list & initiating connect ----------------
st.header("Add / Configure a Provider")
providers = ["gmail", "outlook", "slack", "teams", "atlassian", "notion", "hubspot", "freshdesk", "jira", "linkedin"]
provider_sel = st.selectbox("Provider", providers)
label = st.text_input("Account label (optional)")

if st.button("Start Composio Connect Flow"):
    try:
        # build callback URL -> Composio will redirect to this URL after auth; we add owner_id & provider so the app can persist
        callback_url = f"{APP_PUBLIC_CALLBACK_URL}?owner_id={user_id}&provider={provider_sel}"
        conn_req = composio.connected_accounts.initiate(
            user_id=user_id,
            auth_config_id=COMPOSIO_AUTH_CONFIG_ID,
            callback_url=callback_url,
            metadata={"provider": provider_sel, "label": label},
        )
        st.success("Connection initiated. Click the link below to authenticate the provider.")
        st.markdown(f"[Open authentication]({conn_req.redirect_url})")
        st.info("After authentication finishes, Composio will redirect back to the callback URL and this app will detect query params and save the connected account.")
    except Exception as e:
        st.error(f"Failed to initiate Composio flow: {e}")

st.markdown("---")

# ---------------- Manual token import (encrypted) ----------------
st.header("Manual Token Import (encrypted)")
st.info("Paste a raw provider payload (JSON). It will be encrypted before saving.")
with st.form("manual_token"):
    prov_manual = st.selectbox("Provider (manual)", providers, key="manual_prov")
    token_payload_text = st.text_area("Token payload (JSON)")
    submit = st.form_submit_button("Save token")
    if submit:
        if not token_payload_text.strip():
            st.error("Provide token payload")
        else:
            try:
                payload_obj = json.loads(token_payload_text)
            except Exception:
                payload_obj = {"raw": token_payload_text}

            ok = save_connected_account(owner_id=user_id, provider=prov_manual, connected_account_id=f"manual-{int(time.time())}", payload=payload_obj)
            if ok:
                st.success("Token saved (encrypted) into Supabase.")
            else:
                st.error("Failed to save token.")

st.markdown("---")

# ---------------- Connected accounts listing ----------------
st.header("Connected Accounts")
rows = fetch_connected_accounts(user_id)
if not rows:
    st.info("No connected accounts found.")
else:
    for r in rows:
        cols = st.columns([2, 3, 2, 1])
        cols[0].write(r.get("provider"))
        cols[1].write(r.get("connected_account_id"))
        cols[2].write(r.get("created_at"))
        if cols[3].button("Disconnect", key=f"disc_{r.get('id')}"):
            ok = delete_connected_account(r.get("id"))
            if ok:
                st.success("Disconnected.")
                st.experimental_rerun()

# ---------------- Developer utilities ----------------
st.markdown("---")
st.header("Developer / Debug")
if st.checkbox("Show raw rows for this user"):
    all_rows = fetch_connected_accounts(user_id)
    for rr in all_rows:
        # show decrypted payload (safe since user is authenticated)
        try:
            decrypted = decrypt_obj(rr.get("token_encrypted")) if rr.get("token_encrypted") else None
        except Exception:
            decrypted = "<decryption failed>"
        st.write({"row": rr, "decrypted_payload": decrypted})

st.info("SQL schema + RLS for Supabase is provided below (run in your DB).")
