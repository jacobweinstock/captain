# captain

Library for securely sending webhooks. Captain supports the following methods and options for sending webhooks. All payloads will be sent as JSON.


- https
  - with user specified certificates
  - unsigned or signed (hmac)
  - timestamped
  - basic authentication
- http (should only be used for development proposes)
  - unsigned or signed (hmac)
