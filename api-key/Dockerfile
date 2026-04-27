FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/api-key ./cmd/server

FROM alpine:3.22
RUN adduser -D -g '' appuser
USER appuser
WORKDIR /app
COPY --from=builder /bin/api-key /usr/local/bin/api-key
EXPOSE 8080
CMD ["/usr/local/bin/api-key"]
