import os
import time
import json
import hmac
import base64
import hashlib
import logging
import requests
import azure.functions as func
from azure.data.tables import TableServiceClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# === ENVIRONMENT CONFIG ===
PODIUM_CLIENT_ID = os.getenv("PODIUM_CLIENT_ID")
PODIUM_CLIENT_SECRET = os.getenv("PODIUM_CLIENT_SECRET")
PODIUM_REDIRECT_URI = os.getenv("PODIUM_REDIRECT_URI")
KEY_VAULT_URL = os.getenv("KEY_VAULT_URL")
WEBHOOK_SECRET_NAME = os.getenv("WEBHOOK_SECRET_NAME")
VM_ENDPOINTS = json.loads(os.getenv("VM_ACCESS_ENDPOINTS", "{}"))

TABLE_NAME = "podiumTokens"
PARTITION_KEY = "tokens"
ROUTING_TABLE = "vmRoutingTable"

# === HELPERS ===
def _get_table_client(name):
    conn_str = os.environ["AzureWebJobsStorage"]
    service = TableServiceClient.from_connection_string(conn_str)
    return service.get_table_client(name)

def save_token(org_uid, access_token, refresh_token, expires_in):
    table = _get_table_client(TABLE_NAME)
    expires_at = int(time.time()) + expires_in - 60
    entity = {
        "PartitionKey": PARTITION_KEY,
        "RowKey": org_uid,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at
    }
    table.upsert_entity(entity)

def get_token(org_uid):
    table = _get_table_client(TABLE_NAME)
    entity = table.get_entity(partition_key=PARTITION_KEY, row_key=org_uid)
    current_time = int(time.time())
    if current_time < entity["expires_at"]:
        return entity["access_token"]

    res = requests.post("https://api.podium.com/oauth/token", json={
        "client_id": PODIUM_CLIENT_ID,
        "client_secret": PODIUM_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": entity["refresh_token"]
    })
    token_data = res.json()
    save_token(org_uid, token_data["access_token"], token_data["refresh_token"], token_data.get("expires_in", 3600))
    return token_data["access_token"]

# === ROUTES ===
app = func.FunctionApp()

@app.function_name(name="oauth_authorize")
@app.route(route="oauth-authorize", auth_level=func.AuthLevel.ANONYMOUS)
def oauth_authorize(req: func.HttpRequest) -> func.HttpResponse:
    state = req.params.get("state", "defaultState")
    url = (
        f"https://api.podium.com/oauth/authorize?client_id={PODIUM_CLIENT_ID}"
        f"&redirect_uri={PODIUM_REDIRECT_URI}&response_type=code&scope=read_payments%20write_payments&state={state}"
    )
    return func.HttpResponse(status_code=302, headers={"Location": url})

@app.function_name(name="oauth_callback")
@app.route(route="oauth-callback", auth_level=func.AuthLevel.ANONYMOUS)
def oauth_callback(req: func.HttpRequest) -> func.HttpResponse:
    try:
        code = req.params.get("code")
        state = req.params.get("state", "defaultOrg")
        if not code:
            return func.HttpResponse("Missing code", status_code=400)

        res = requests.post("https://api.podium.com/oauth/token", json={
            "client_id": PODIUM_CLIENT_ID,
            "client_secret": PODIUM_CLIENT_SECRET,
            "redirect_uri": PODIUM_REDIRECT_URI,
            "grant_type": "authorization_code",
            "code": code
        })
        token_data = res.json()
        save_token(state, token_data["access_token"], token_data["refresh_token"], token_data.get("expires_in", 3600))
        return func.HttpResponse("Authorization successful! You may close this window.")
    except Exception as e:
        return func.HttpResponse(f"OAuth callback failed: {str(e)}", status_code=500)

@app.function_name(name="podium_router")
@app.route(route="podium-router", auth_level=func.AuthLevel.FUNCTION)
def podium_router(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
        vm_id = body.get("vm_id")
        action = body.get("action")
        payload = body.get("payload")
        if not vm_id or not action or not payload:
            return func.HttpResponse("Missing fields", status_code=400)
        token = get_token(vm_id)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        url = f"https://api.podium.com/v4/{action.replace('_', '/')}"
        post_actions = ["invoices", "refund_invoice", "cancel_invoice"]
        if action in post_actions:
            response = requests.post(url, json=payload, headers=headers)
        else:
            response = requests.get(url, headers=headers, params=payload)
        #response = requests.post(url, json=payload, headers=headers) if action.startswith("create") else requests.get(url, headers=headers)
        return func.HttpResponse(json.dumps(response.json()), mimetype="application/json")
    except Exception as e:
        return func.HttpResponse(str(e), status_code=500)

@app.function_name(name="podium_webhook")
@app.route(route="podium-webhook", auth_level=func.AuthLevel.ANONYMOUS)
def podium_webhook(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_body()
        sig = req.headers.get("x-podium-signature")
        credential = DefaultAzureCredential()
        secret = SecretClient(vault_url=KEY_VAULT_URL, credential=credential).get_secret(WEBHOOK_SECRET_NAME).value
        expected_sig = base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()
        if not hmac.compare_digest(sig, expected_sig):
            return func.HttpResponse("Invalid signature", status_code=403)

        event = json.loads(body)
        org_uid = event.get("organizationUid")
        table = _get_table_client(ROUTING_TABLE)
        entity = table.get_entity(partition_key="routing", row_key=org_uid)
        vm_url = entity["vm_url"]
        res = requests.post(vm_url, json=event)
        return func.HttpResponse("Event forwarded", status_code=200)
    except Exception as e:
        logging.error(str(e))
        return func.HttpResponse("Webhook error", status_code=500)
