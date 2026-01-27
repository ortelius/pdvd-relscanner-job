FROM cgr.dev/chainguard/go@sha256:552969bb3988f3db46a00880e912402aeb1d394dc26257f688ee5103ef39d16b AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main .

FROM cgr.dev/chainguard/git:latest

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
