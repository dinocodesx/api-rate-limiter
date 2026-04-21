FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/rate-limiter ./cmd/server

FROM alpine:3.22
RUN adduser -D -g '' appuser
USER appuser
WORKDIR /app
COPY --from=builder /bin/rate-limiter /usr/local/bin/rate-limiter
EXPOSE 8081
CMD ["/usr/local/bin/rate-limiter"]
