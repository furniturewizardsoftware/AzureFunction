import hmac
import hashlib
import base64
import json
import logging
import os
import azure.functions as func
import requests
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.data.tables import TableServiceClient

# ------------------------------------------------
#  Load Podium Webhook Secret from Azure Key Vault
# ------------------------------------------------
def get_webhook_secret():
    vault_url = os.environ["KEY_VAULT_URL"]
    secret_name = os.environ["WEBHOOK_SECRET_NAME"]
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    return client.get_secret(secret_name).value

# ------------------------------------------------
#  Validate the HMAC-SHA256 signature
# ------------------------------------------------
def is_valid_signature(body, received_sig, secret):
    expected_sig = base64.b64encode(
        hmac.new(secret.encode(), body, hashlib.sha256).digest()
    ).decode()
    return hmac.compare_digest(expected_sig, received_sig)

# ------------------------------------------------
#  Lookup VM URL by Org UID from Azure Table Storage
# ------------------------------------------------
def get_vm_url_by_org(org_uid):
    try:
        conn_str = os.environ["AzureWebJobsStorage"]
        table_name = "vmRoutingTable"

        service = TableServiceClient.from_connection_string(conn_str)
        table_client = service.get_table_client(table_name)

        entity = table_client.get_entity(partition_key="routing", row_key=org_uid)
        return entity.get("vm_url")
    except Exception as e:
        logging.warning(f"VM mapping not found for org_uid={org_uid}: {str(e)}")
        return None

# ------------------------------------------------
#  Azure Function to Handle Webhook Events
# ------------------------------------------------
@app.function_name(name="podium_webhook")
@app.route(route="podium-webhook", auth_level=func.AuthLevel.ANONYMOUS)
def podium_webhook(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Raw body + headers
        body = req.get_body()
        received_sig = req.headers.get("x-podium-signature")

        # 1. Validate webhook signature
        secret = get_webhook_secret()
        if not is_valid_signature(body, received_sig, secret):
            logging.warning("Invalid signature")
            return func.HttpResponse("Invalid signature", status_code=403)

        # 2. Parse webhook event
        event = json.loads(body)
        event_type = event.get("eventType")
        org_uid = event.get("organizationUid")

        logging.info(f"Received Podium webhook: {event_type} for org: {org_uid}")

        # 3. Route to VM
        vm_url = get_vm_url_by_org(org_uid)
        if not vm_url:
            return func.HttpResponse(f"No VM mapping for org {org_uid}", status_code=404)

        # 4. Forward event to VM
        response = requests.post(vm_url, json=event)
        response.raise_for_status()

        return func.HttpResponse("Webhook received and forwarded", status_code=200)

    except Exception as e:
        logging.error(f"Webhook error: {str(e)}")
        return func.HttpResponse(f"Webhook processing error", status_code=500)
