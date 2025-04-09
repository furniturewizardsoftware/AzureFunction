import os
import azure.functions as func

@app.function_name(name="oauth_authorize")
@app.route(route="oauth-authorize", auth_level=func.AuthLevel.ANONYMOUS)
def oauth_authorize(req: func.HttpRequest) -> func.HttpResponse:
    client_id = os.environ["PODIUM_CLIENT_ID"]
    redirect_uri = os.environ["PODIUM_REDIRECT_URI"]
    scope = "read_payments write_payments"

    # Optional: pass state=org_uid or vm_id to track client
    state = req.params.get("state", "defaultState")

    auth_url = (
        f"https://api.podium.com/oauth/authorize?"
        f"client_id={client_id}&redirect_uri={redirect_uri}"
        f"&response_type=code&scope={scope.replace(' ', '%20')}&state={state}"
    )

    return func.HttpResponse(status_code=302, headers={"Location": auth_url})
