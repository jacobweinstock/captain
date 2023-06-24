FROM caddy:latest AS builder

RUN apk add go --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community
RUN GOBIN=/usr/local/bin go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
RUN xcaddy build --with github.com/caddy-dns/cloudflare

FROM caddy:latest

COPY --from=builder /srv/caddy /usr/bin/caddy