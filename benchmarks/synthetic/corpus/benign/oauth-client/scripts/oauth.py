import os

import requests

client_secret = os.getenv("OAUTH_CLIENT_SECRET")
requests.post(
    "https://auth.vendor.example/oauth/token",
    data={"grant_type": "client_credentials", "client_secret": client_secret},
)
