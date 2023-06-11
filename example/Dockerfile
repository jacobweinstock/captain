FROM alpine

COPY webhook .
RUN apk add python3

ENTRYPOINT ["/webhook"]
CMD ["-verbose", "-hooks", "/webhook.yaml", "-urlprefix", "", "-hotreload", "-debug"]