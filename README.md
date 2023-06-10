# captain

Library for securely sending webhooks. Captain supports the following methods and options for sending webhooks. All payloads will be sent as JSON.


- https
  - with user specified certificates
  - unsigned or signed (hmac)
  - timestamped
  - custom user-agent
- http (should only be used for development proposes)
  - unsigned or signed (hmac)
  - timestamped
  - custom user-agent


## Run a webhook listener

```bash
./webhook -verbose -hooks example/webhook.yaml -urlprefix "" -verbose -debug -hotreload

# POST to http://localhost:9000/webhook
# See TestAddSignature for an example of how to sign a request
```
