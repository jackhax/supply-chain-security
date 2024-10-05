import base64, requests, json

api = "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=13267353"

data = requests.get(api).json()
body = next(iter(data.values()))["body"]
body = json.loads(base64.b64decode(body).decode())
print(body)

# out of scope of review
