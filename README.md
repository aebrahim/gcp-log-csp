# gcp-log-csp

A minimal [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) (CSP) report collector that logs violations as [Google Cloud Platform structured logs](https://cloud.google.com/logging/docs/structured-logging). Designed to run on [Cloud Run](https://cloud.google.com/run).

## Design Goals

- **Minimal attack surface** — written in Rust and deployed in a `scratch` Docker container with no OS, shell, or extra libraries.
- **Performant** — async I/O with `axum` / `tokio`.
- **Simple** — one binary, zero configuration beyond an optional `PORT` environment variable.

## Endpoints

| Method | Path          | Description                              |
|--------|---------------|------------------------------------------|
| POST   | `/csp-report` | Accepts CSP violation reports            |
| GET    | `/health`     | Health check (returns `200 OK`)          |

### Accepted Content Types

The `/csp-report` endpoint accepts these content types:

- `application/csp-report` — legacy `report-uri` directive format
- `application/reports+json` — Reporting API v1 format
- `application/json` — generic JSON

## Configuration

| Variable | Default | Description          |
|----------|---------|----------------------|
| `PORT`   | `8080`  | Port to listen on    |

## Usage

### Run Locally

```bash
cargo run
```

### Docker

```bash
docker build -t gcp-log-csp .
docker run -p 8080:8080 gcp-log-csp
```

### Deploy to Cloud Run

```bash
# Build and push to Google Artifact Registry
docker build -t us-docker.pkg.dev/PROJECT/REPO/gcp-log-csp:latest .
docker push us-docker.pkg.dev/PROJECT/REPO/gcp-log-csp:latest

# Deploy
gcloud run deploy gcp-log-csp \
  --image us-docker.pkg.dev/PROJECT/REPO/gcp-log-csp:latest \
  --allow-unauthenticated
```

### CSP Header Example

Point your CSP reporting to the deployed service:

```
Content-Security-Policy: default-src 'self'; report-uri https://YOUR-SERVICE-URL/csp-report
```

Or with the newer Reporting API:

```
Content-Security-Policy: default-src 'self'; report-to csp-endpoint
Reporting-Endpoints: csp-endpoint="https://YOUR-SERVICE-URL/csp-report"
```

## Development

```bash
# Format
cargo fmt

# Lint
cargo clippy -- -D warnings

# Test
cargo test

# Build release
cargo build --release
```

## License

[MIT](LICENSE)
