FROM cgr.dev/chainguard/go@sha256:7b3335e0f1b05c0dfcb241c52734135f87ca823ead64597eb33160085ed33501 AS builder
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /app
COPY . /app

RUN go mod tidy && \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:c97b5efe4aeb84e438afa743e69ccf2fc4a23ec847f6c3c68efc3edd9fad683c
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /app

COPY --from=builder /app/main .

ENV ARANGO_HOST=localhost
ENV ARANGO_USER=root
ENV ARANGO_PASS=rootpassword
ENV ARANGO_PORT=8529
ENV GITHUB_APP_ID=2695570
ENV GITHUB_CLIENT_ID=Iv23liVE3QJYlS6BGQRa

EXPOSE 8080

ENTRYPOINT [ "/app/main", "process-workflow" ]
