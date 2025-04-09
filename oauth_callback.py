import os
import json
import time
import logging
import requests
import azure.functions as func
import token_utils

# Temporary in-memory store 
TOKEN_STORE = {}  # { org_uid: { access_token, refresh_token, expires_at } }

@app.function_name(name="oauth_callback")
@app.route(route="oauth-callback", auth_level=func.AuthLevel.ANONYMOUS)
def oauth_callback(req: func.HttpRequest) -> func.HttpResponse:
    try:
        code = req.params.get("code")
        state = req.params.get("state", "defaultOrg")  # can be org_uid

        if not code:
            return func.HttpResponse("No code provided", status_code=400)

        token_url = "https://api.podium.com/oauth/token"
        res = requests.post(token_url, json={
            "client_id": os.environ["PODIUM_CLIENT_ID"],
            "client_secret": os.environ["PODIUM_CLIENT_SECRET"],
            "redirect_uri": os.environ["PODIUM_REDIRECT_URI"],
            "grant_type": "authorization_code",
            "code": code
        })

        token_data = res.json()
        if "access_token" not in token_data:
            logging.error(f"Token exchange failed: {token_data}")
            return func.HttpResponse("Token exchange failed", status_code=500)

        # Store in memory (replace with secure DB later)
        TOKEN_STORE[state] = {
            "access_token": token_data["access_token"],
            "refresh_token": token_data["refresh_token"],
            "expires_at": int(time.time()) + token_data.get("expires_in", 3600)
        }
        token_utils.save_token(
            org_uid=state,
            access_token=token_data["access_token"],
            refresh_token=token_data["refresh_token"],
            expires_in=token_data.get("expires_in", 3600)
            )

        logging.info(f"Authorized org: {state}")
        return func.HttpResponse("Authorization successful! You may close this window.")

    except Exception as e:
        logging.error(f"OAuth callback error: {str(e)}")
        return func.HttpResponse("OAuth callback failed", status_code=500)
