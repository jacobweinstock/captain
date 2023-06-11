# captain

Library for securely sending webhooks. Captain supports the following methods and options for sending webhooks. All payloads will be sent as JSON.


- https
  - with user specified certificates
  - signed (HMAC256, HMAC512)
  - customizable signature payload
- http (should only be used for development proposes)
  - signed (HMAC256, HMAC512)
  - customizable signature payload


## Local development

```bash
# Run a webhook listener
make run

# POST to https://localhost/webhook
# See TestAddSignature for an example of how to sign a request
```
