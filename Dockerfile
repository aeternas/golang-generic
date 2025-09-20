# syntax=docker/dockerfile:1

FROM golang:1.22 AS builder
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server ./...

FROM gcr.io/distroless/base-debian12
WORKDIR /app

COPY --from=builder /src/server ./server
EXPOSE 8080

CMD ["./server"]
