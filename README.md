# golang-generic

This repository contains a minimal HTTP service written in Go. The service exposes two endpoints:

- `GET /` – returns a short JSON payload describing the service status.
- `GET /healthz` – returns `204 No Content`, which is useful for health checks.

## Getting started

1. Ensure you have Go 1.21 or newer installed.
2. Clone the repository and change into its directory.
3. Run the service:

```bash
go run .
```

By default the server listens on port `8080`. Set the `PORT` environment variable to change the listen port, e.g. `PORT=9090 go run .`.

### Testing the endpoints

Once the server is running you can query it with `curl` or any HTTP client:

```bash
curl http://localhost:8080/
# {"status":"ok","message":"golang-generic service is running"}

curl -i http://localhost:8080/healthz
# HTTP/1.1 204 No Content
```

## Deployment

The development environment for this exercise does not provide a publicly accessible network endpoint, so the service cannot be hosted for external access from a web browser. However, the project is ready to be deployed anywhere Go applications can run (for example Fly.io, Render, Railway, or a small VM). Deploying it typically involves building the binary with `go build .` and running it on a server that exposes the chosen port to the internet.

### Automated deployment with GitHub Actions (Fly.io)

This repository includes a GitHub Actions workflow (`.github/workflows/deploy.yml`) and a Fly.io application definition (`fly.toml`) so you can automatically deploy the service to Fly.io from your own GitHub account.

1. [Create a Fly.io account](https://fly.io) and install the `flyctl` CLI locally.
2. Create a new Fly.io application for the service:

   ```bash
   flyctl apps create <your-app-name>
   ```

3. Update `fly.toml` and replace the placeholder `app` value (`golang-generic-placeholder`) with `<your-app-name>`.
4. Generate a Fly.io access token and add it to your repository secrets as `FLY_API_TOKEN`:

   ```bash
   flyctl auth token
   ```

5. Add your Fly.io application name as the `FLY_APP_NAME` repository secret.
6. Commit and push the changes (including the updated `fly.toml`) to GitHub.

Every push to the `main` branch (or a manual “Run workflow” dispatch) will now:

- check out the repository,
- run `go test ./...`, and
- deploy the latest version of the service to Fly.io using the Docker image defined in `Dockerfile`.

If you prefer to deploy manually, you can run the same `flyctl deploy` command locally after logging in with `flyctl auth login`.

### Container image

The included `Dockerfile` builds a minimal Linux container image for the service. To build and run it locally:

```bash
docker build -t golang-generic .
docker run --rm -p 8080:8080 golang-generic
```
