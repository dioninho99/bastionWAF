ARG BUILDER_IMAGE=golang:1.26-alpine
FROM ${BUILDER_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /out/data && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bastion ./cmd/bastion

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=10001:10001 /out/data /data
COPY --from=build /out/bastion /usr/local/bin/bastion
USER 10001:10001
ENV BASTION_DATA_DIR=/data BASTION_ADMIN_ADDR=0.0.0.0:9090
EXPOSE 8080 8443 9090
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["/usr/local/bin/bastion", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/bastion"]
