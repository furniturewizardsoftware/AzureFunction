import os
import time
import requests
from azure.data.tables import TableServiceClient

# Azure Table Setup
TABLE_NAME = "podiumTokens"
PARTITION_KEY = "tokens"

def _get_table_client():
    conn_str = os.environ["AzureWebJobsStorage"]
    service = TableServiceClient.from_connection_string(conn_str)
    return service.get_table_client(TABLE_NAME)

# Save or update token in Azure Table
def save_token(org_uid, access_token, refresh_token, expires_in):
    table = _get_table_client()
    expires_at = int(time.time()) + expires_in - 60  # 1 min buffer

    entity = {
        "PartitionKey": PARTITION_KEY,
        "RowKey": org_uid,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at
    }

    table.upsert_entity(entity)

# Retrieve and refresh token if needed
def get_token(org_uid):
    table = _get_table_client()

    try:
        entity = table.get_entity(partition_key=PARTITION_KEY, row_key=org_uid)
    except Exception:
        raise Exception(f"No token found for org_uid={org_uid}")

    current_time = int(time.time())
    if current_time < entity["expires_at"]:
        return entity["access_token"]

    # Refresh token if expired
    res = requests.post("https://api.podium.com/oauth/token", json={
        "client_id": os.environ["PODIUM_CLIENT_ID"],
        "client_secret": os.environ["PODIUM_CLIENT_SECRET"],
        "grant_type": "refresh_token",
        "refresh_token": entity["refresh_token"]
    })

    token_data = res.json()
    if "access_token" not in token_data:
        raise Exception(f"Failed to refresh token: {token_data}")

    # Save updated token
    save_token(
        org_uid=org_uid,
        access_token=token_data["access_token"],
        refresh_token=token_data["refresh_token"],
        expires_in=token_data.get("expires_in", 3600)
    )

    return token_data["access_token"]
