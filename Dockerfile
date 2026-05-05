FROM cgr.dev/chainguard/go@sha256:61036c7909f82ff97ef1736be37128d40360fd3468c773508d95b903a1fff274 AS builder
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
