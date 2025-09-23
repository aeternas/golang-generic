# syntax=docker/dockerfile:1

FROM golang:1.22 AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o service1 ./cmd/service1

FROM gcr.io/distroless/base-debian12
WORKDIR /app

COPY --from=builder /src/service1 ./service1
EXPOSE 8082

CMD ["./service1"]
