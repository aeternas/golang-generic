# golang-generic

This repository contains a minimal HTTP service written in Go. The service exposes two endpoints:

- `GET /` – returns a short JSON payload describing the service status.
- `GET /healthz` – returns `204 No Content`, which is useful for health checks.

## Running locally

1. Ensure you have Go 1.21 or newer installed.
2. Clone the repository and change into its directory.
3. Start the service:

   ```bash
   go run .
   ```

By default the server listens on port `8080`. Set the `PORT` environment variable to change the listen port, for example `PORT=9090 go run .`.

### Testing the endpoints

Once the server is running you can query it with `curl` or any HTTP client:

```bash
curl http://localhost:8080/
# {"status":"ok","message":"golang-generic service is running"}

curl -i http://localhost:8080/healthz
# HTTP/1.1 204 No Content
```

## Containerization with Docker

A multi-stage Dockerfile is included so you can build a compact container image for the service.

### Build the image

```bash
docker build -t golang-generic .
```

### Run the container locally

```bash
docker run --rm -p 8080:8080 golang-generic
```

The container exposes port `8080`. Override the port by passing the `PORT` environment variable when you start the container, for example:

```bash
docker run --rm -e PORT=9090 -p 9090:9090 golang-generic
```

This environment cannot host public services, but the resulting image can be deployed to any container platform or your own infrastructure.
