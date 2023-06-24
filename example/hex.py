#!/usr/bin/env python3

import datetime
import hmac
import hashlib
import requests
import json

# 1. concatenate the body and the timestamp header
body = json.loads('{"host":"192.168.2.3","task":{"bootDevice":{"device":"pxe","persistent":false,"efiBoot":false}}}')
headers = {"X-Rufio-Timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "Content-Type": "application/json"}
req = requests.Request('POST', 'http://webhook.weinstocklabs.com/webhook', json=body, headers=headers)
signPayload = '{}{}'.format(json.dumps(req.json), req.headers.get('X-Rufio-Timestamp')).encode('utf-8')

# 2. HMAC sign
secret = bytes('superSecret1' , 'utf-8')
signature = hmac.new(secret, signPayload, hashlib.sha256)

# 3. Make a hex encoded string of the HMAC signature
sig = signature.hexdigest()

# 4. Prepend the algorithm type to the signature
sig = 'sha256=' + sig

# 5. Store the string signature in the header
headers["X-Rufio-Signature-256"] = sig
print(headers)

s = requests.Session()
r = req.prepare()
resp = s.send(r)

print(resp.status_code)
print(resp.text)
