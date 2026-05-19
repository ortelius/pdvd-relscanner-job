FROM cgr.dev/chainguard/go@sha256:df86b3248633e832d12c3f1777b9e1e03d40f654ab5bd81be3e1a271999d2931 AS builder
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /app
COPY . /app

RUN go mod tidy && \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:d7aa809c1ae88f97cd727d6f5f91e4edab579a14f86f52fd0dd8c658c854286d
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
