import logging
import os
import json
import azure.functions as func
import requests
import time

# -------------------------------
# Load environment variables
# -------------------------------
PODIUM_CLIENT_ID = os.getenv("PODIUM_CLIENT_ID")
PODIUM_CLIENT_SECRET = os.getenv("PODIUM_CLIENT_SECRET")
VM_ENDPOINTS = json.loads(os.getenv("VM_ACCESS_ENDPOINTS", "{}"))

# -------------------------------
# Token cache for efficiency
# -------------------------------
cached_token = None
cached_token_expiry = 0

def get_podium_token():
    global cached_token, cached_token_expiry
    current_time = time.time()

    # If token is still valid, reuse it
    if cached_token and current_time < cached_token_expiry:
        return cached_token

    # Request new token from Podium
    res = requests.post("https://api.podium.com/oauth/token", json={
        "client_id": PODIUM_CLIENT_ID,
        "client_secret": PODIUM_CLIENT_SECRET,
        "grant_type": "client_credentials"
    })
    res.raise_for_status()
    token_data = res.json()
    cached_token = token_data["access_token"]
    cached_token_expiry = current_time + token_data.get("expires_in", 3600) - 60  # buffer of 60s

    return cached_token

# -------------------------------
# API Router: Maps actions to endpoints
# -------------------------------
def route_action(action, token, payload):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # 1. INVOICES
    if action == "create_invoice":
        return requests.post("https://api.podium.com/v4/invoices", json=payload, headers=headers).json()

    elif action == "get_invoice":
        uid = payload["uid"]
        location_uid = payload["locationUid"]
        return requests.get(f"https://api.podium.com/v4/invoices/{uid}?locationUid={location_uid}", headers=headers).json()

    elif action == "get_all_invoices":
        base_url = "https://api.podium.com/v4/invoices"
        params = "&".join([f"{k}={v}" for k, v in payload.items()])
        return requests.get(f"{base_url}?{params}", headers=headers).json()

    elif action == "cancel_invoice":
        uid = payload["uid"]
        body = {
            "locationUid": payload["locationUid"],
            "note": payload["note"]
        }
        return requests.post(f"https://api.podium.com/v4/invoices/{uid}/cancel", json=body, headers=headers).json()

    elif action == "refund_invoice":
        uid = payload["uid"]
        refund_body = {
            "amount": payload["amount"],
            "locationUid": payload["locationUid"],
            "note": payload["note"],
            "paymentUid": payload["paymentUid"],
            "reason": payload["reason"]
        }
        return requests.post(f"https://api.podium.com/v4/invoices/{uid}/refund", json=refund_body, headers=headers).json()

    # 2. PAYMENTS
    elif action == "get_payment":
        uid = payload["uid"]
        return requests.get(f"https://api.podium.com/v4/payments/{uid}", headers=headers).json()

    # 3. READERS
    elif action == "get_reader":
        uid = payload["uid"]
        return requests.get(f"https://api.podium.com/v4/readers/{uid}", headers=headers).json()

    # 4. REFUNDS
    elif action == "create_manual_refund":
        return requests.post("https://api.podium.com/v4/refunds", json=payload, headers=headers).json()

    elif action == "get_refund":
        uid = payload["uid"]
        location_uid = payload["locationUid"]
        return requests.get(f"https://api.podium.com/v4/refunds/{uid}?locationUid={location_uid}", headers=headers).json()

    else:
        raise Exception(f"Unsupported action: {action}")

# -------------------------------
# (Optional) Log results to VM endpoint
# -------------------------------
def send_to_vm(vm_id, data):
    if vm_id not in VM_ENDPOINTS:
        raise Exception(f"No endpoint for VM ID: {vm_id}")
    res = requests.post(VM_ENDPOINTS[vm_id], json=data)
    res.raise_for_status()
    return res.json()

# -------------------------------
# Azure Function Entry Point
# -------------------------------
@app.function_name(name="podium_router")
@app.route(route="podium-router", auth_level=func.AuthLevel.FUNCTION)
def podium_router(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Parse JSON body
        body = req.get_json()
        vm_id = body.get("vm_id")
        action = body.get("action")
        payload = body.get("payload")

        if not vm_id or not action or not payload:
            return func.HttpResponse("Missing vm_id, action, or payload", status_code=400)

        # Get Podium Access Token
        token = get_podium_token()

        # Route to appropriate Podium endpoint
        result = route_action(action, token, payload)

        # Log to VM (optional)
        try:
            send_to_vm(vm_id, {
                "action": action,
                "payload": payload,
                "result": result
            })
        except Exception as log_err:
            logging.warning(f"Log to VM failed: {str(log_err)}")

        return func.HttpResponse(json.dumps(result), mimetype="application/json")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(str(e), status_code=500)
