# captain

Library for securely sending webhooks. Captain supports the following methods and options for sending webhooks. All payloads will be sent as JSON.


- https
  - with user specified certificates
  - signed (HMAC256, HMAC512)
  - customizable signature payload
- http (should only be used for development proposes)
  - signed (HMAC256, HMAC512)
  - customizable signature payload


## Run a webhook listener

```bash
./webhook -verbose -hooks example/webhook.yaml -urlprefix "" -verbose -debug -hotreload

# With TLS
./webhook -verbose -hooks example/webhook.yaml -urlprefix "" -verbose -debug -hotreload -secure -key key.pem -cert cert.pem

# POST to http://localhost:9000/webhook
# See TestAddSignature for an example of how to sign a request
```
