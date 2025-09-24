# golang-generic

This repository now contains two small HTTP services that can be deployed independently or together:

- **service1 (S1)** – the original public service. It still exposes health information and now also proxies data from S2.
- **service2 (S2)** – a companion service that exposes protected resources. One endpoint requires HTTP Basic authentication while another one is secured by a Keycloak-issued token.

Both services are written in Go and are ready to be built into separate container images.

## Service overview

### Service1 (S1)

| Endpoint | Description |
| --- | --- |
| `GET /` | Returns a JSON payload describing the service status. |
| `GET /healthz` | Returns `204 No Content` for health checking. |
| `GET /s2/secure-data` | Invokes the secure endpoint on S2 using the configured Basic Auth credentials and returns the upstream response alongside S1 metadata. |
| `GET /keycloak-greeting` | Requires a Keycloak Bearer token and returns a greeting payload containing token details. |

#### Configuration

Service1 is configured through environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8082` | Listen port. |
| `S2_BASE_URL` | _(required for `/s2/secure-data`)_ | Base URL of service2, e.g. `http://localhost:8081`. |
| `S2_BASIC_USER` | _(required)_ | Username for S2's Basic Auth endpoint. |
| `S2_BASIC_PASSWORD` | _(required)_ | Password for S2's Basic Auth endpoint. |
| `S2_SECURE_PATH` | `/secure-data` | Path to S2's Basic Auth endpoint. |
| `S2_REQUEST_TIMEOUT` | `5s` | Timeout used when calling S2. |
| `KEYCLOAK_ISSUER_URL` | _(required for `/keycloak-greeting`)_ | Issuer URL for the Keycloak realm, e.g. `http://localhost:8080/realms/demo`. |
| `KEYCLOAK_CLIENT_ID` | _(required for `/keycloak-greeting`)_ | Client ID that must appear in the token audience claim. |
| `KEYCLOAK_JWKS_URL` | `${KEYCLOAK_ISSUER_URL}/protocol/openid-connect/certs` | Optional override for the JWKS endpoint. |
| `KEYCLOAK_ISSUER_ALIASES` | _(optional)_ | Comma-separated list of additional issuer URLs accepted during token validation. |

Run S1 locally:

```bash
go run ./cmd/service1
```

#### Keycloak-protected greeting

If the Keycloak environment variables are supplied, Service1 exposes `GET /keycloak-greeting`. The handler validates the Bearer
token, then returns a JSON document containing the subject, preferred username, token lifetime and audience. Requests without a
valid token receive `401 Unauthorized`.

For example, after obtaining an access token (see the [Keycloak realm container](#keycloak-realm-container) section below):

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8082/keycloak-greeting
```

### Service2 (S2)

| Endpoint | Authentication | Description |
| --- | --- | --- |
| `GET /` | None | Returns status information for S2. |
| `GET /healthz` | None | Returns `204 No Content`. |
| `GET /secure-data` | HTTP Basic (`demo-user` / `demo-pass`) | Returns a JSON payload with sample protected data. |
| `GET /keycloak-data` | Bearer token (Keycloak) | Validates a Keycloak JWT and echoes selected claims.

#### Basic authentication

The credentials are intentionally hard-coded for demonstration purposes:

- Username: `demo-user`
- Password: `demo-pass`

#### Keycloak integration

S2 validates RSA-signed JWTs issued by Keycloak. Provide the following environment variables to enable the `/keycloak-data` endpoint:

| Variable | Default | Purpose |
| --- | --- | --- |
| `KEYCLOAK_ISSUER_URL` | _(required)_ | Issuer URL for your Keycloak realm, e.g. `http://localhost:8080/realms/demo`. |
| `KEYCLOAK_CLIENT_ID` | _(required)_ | Client ID configured in that realm. The token's audience must include this value. |
| `KEYCLOAK_JWKS_URL` | `${KEYCLOAK_ISSUER_URL}/protocol/openid-connect/certs` | Optional override for the JWKS endpoint that exposes the signing keys. |
| `KEYCLOAK_ISSUER_ALIASES` | _(optional)_ | Comma-separated list of additional issuer URLs accepted during token validation. |

At startup the service downloads the JWKS set once and caches the RSA keys. Tokens are validated by checking:

- the signature using the key identified by `kid`;
- the `iss` (issuer) claim;
- the `aud` (audience) claim contains the configured client ID; and
- the token has not expired.

The handler returns a JSON payload containing basic details such as the subject, audience, issuer, preferred username and token lifetime.

> When using the bundled Keycloak container, set `KEYCLOAK_ISSUER_URL=http://localhost:8080/realms/demo` and `KEYCLOAK_CLIENT_ID=service-client`.

If the URL used to obtain tokens differs from the one the services use to reach Keycloak (for example `http://localhost:8080/realms/demo` for token requests versus `http://keycloak:8080/realms/demo` inside a Docker network), supply the public value via `KEYCLOAK_ISSUER_ALIASES` so both issuers are trusted during validation.

Run S2 locally:

```bash
go run ./cmd/service2
```

To access the protected endpoints with `curl`:

```bash
# Basic Auth protected endpoint
curl -u demo-user:demo-pass http://localhost:8081/secure-data

# Keycloak protected endpoint (use the $TOKEN from the Keycloak section)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/keycloak-data
```

### Calling S2 from S1

Once both services are running and the S2 credentials are configured in S1, you can retrieve data through S1:

```bash
export S2_BASE_URL=http://localhost:8081
export S2_BASIC_USER=demo-user
export S2_BASIC_PASSWORD=demo-pass

go run ./cmd/service1

# In a separate terminal
go run ./cmd/service2

# Request proxied data
curl http://localhost:8082/s2/secure-data
```

S1 responds with a JSON document that includes the original payload returned by S2.

## Keycloak realm container

The repository now includes `Dockerfile.keycloak`, which produces a ready-to-run Keycloak server with a sample realm:

- Realm: `demo`
- Client ID: `service-client` (public client with password grant enabled)
- Demo user: `kc-user` / `kc-pass`
- Admin console: `admin` / `admin`

Build and run the image locally:

```bash
docker build -f Dockerfile.keycloak -t demo-keycloak .
docker run --rm -p 8080:8080 --name keycloak demo-keycloak
```

Once the container is healthy you can obtain a token for the demo user (requires `jq` to extract the value):

```bash
TOKEN=$(curl -s -X POST "http://localhost:8080/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=service-client" \
  -d "username=kc-user" \
  -d "password=kc-pass" | jq -r '.access_token')
```

Export the Keycloak variables before starting S1 or S2 so they validate the issued tokens:

```bash
export KEYCLOAK_ISSUER_URL=http://localhost:8080/realms/demo
export KEYCLOAK_CLIENT_ID=service-client
```

### User Storage SPI example

The Keycloak container image now bundles a custom **User Storage SPI** provider that delegates password checks to Service2's
Basic Auth endpoint. The provider is packaged from the Maven project under `keycloak/user-storage-s2` and copied into Keycloak
at build time.

When the realm import runs, a new component named **Service2 Basic Auth** is created. The component accepts three configuration
properties:

| Property | Description | Default |
| --- | --- | --- |
| `s2BaseUrl` | Base URL used to contact Service2. | `http://service2:8081` |
| `s2Endpoint` | Relative path of the Basic Auth protected endpoint. | `/secure-data` |
| `s2TimeoutMillis` | Timeout (in milliseconds) for validation requests. | `2000` |

To test the integration locally:

1. Start Service2 so it is reachable by Keycloak. When running Keycloak via Docker, place both containers on the same network
   and keep Service2 available as `http://service2:8081` or adjust the component configuration in the Keycloak admin console.
2. Build and run the Keycloak image with `docker build -f Dockerfile.keycloak -t demo-keycloak .` followed by
   `docker run --rm -p 8080:8080 --name keycloak demo-keycloak`.
3. Authenticate against Keycloak with the Service2 Basic Auth credentials, e.g. obtain a token using
   `demo-user` / `demo-pass` as the username and password.

During authentication Keycloak issues a Basic Auth request to Service2's secure endpoint. A `200 OK` response marks the
credentials as valid while other responses (or timeouts) reject the login attempt.

The JWKS endpoint is automatically derived from the issuer but can be overridden via `KEYCLOAK_JWKS_URL` if required.

## Containerization

Each service has its own multi-stage Dockerfile and can be built separately:

```bash
# Service1 image
docker build -t service1 .

# Service2 image
docker build -f Dockerfile.service2 -t service2 .

# Keycloak realm image
docker build -f Dockerfile.keycloak -t demo-keycloak .
```

Run the containers locally (assuming Docker networking between them):

```bash
# Start Keycloak
docker run --rm -p 8080:8080 --name keycloak demo-keycloak

# Start S2 (links to Keycloak for JWKS retrieval)
docker run --rm \
  -e PORT=8081 \
  -e KEYCLOAK_ISSUER_URL=http://keycloak:8080/realms/demo \
  -e KEYCLOAK_ISSUER_ALIASES=http://localhost:8080/realms/demo \
  -e KEYCLOAK_CLIENT_ID=service-client \
  -p 8081:8081 \
  --link keycloak:keycloak \
  --name service2 service2

# In another terminal configure S1 to reach S2 and Keycloak through Docker's network bridge
docker run --rm \
  -e PORT=8082 \
  -e S2_BASE_URL=http://service2:8081 \
  -e S2_BASIC_USER=demo-user \
  -e S2_BASIC_PASSWORD=demo-pass \
  -e KEYCLOAK_ISSUER_URL=http://keycloak:8080/realms/demo \
  -e KEYCLOAK_ISSUER_ALIASES=http://localhost:8080/realms/demo \
  -e KEYCLOAK_CLIENT_ID=service-client \
  --link service2:service2 \
  --link keycloak:keycloak \
  -p 8082:8082 service1
```

> **Note:** This environment cannot host long-running services, but the images produced by the Dockerfiles are ready for deployment to your own infrastructure.

## Fly.io configuration

`fly.toml` continues to target Service1 using the root `Dockerfile`. If you deploy Service2 separately, supply the alternative Dockerfile or create an additional Fly.io application.
