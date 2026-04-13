use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;

/// Maximum request body size: 1 MB
const MAX_BODY_SIZE: usize = 1_048_576;

/// Build the application router.
pub fn app() -> Router {
    Router::new()
        .route("/csp-report", post(handle_csp_report))
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
}

/// Health check endpoint.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Handle incoming CSP violation reports.
///
/// Accepts both the legacy `report-uri` format (`application/csp-report`)
/// and the newer Reporting API format (`application/reports+json`).
/// The report is logged as a GCP structured log entry to stdout.
async fn handle_csp_report(headers: HeaderMap, body: Bytes) -> StatusCode {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Only accept JSON-like content types used by CSP reporting.
    if !is_accepted_content_type(content_type) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE;
    }

    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(parsed) => {
            let log_entry = serde_json::json!({
                "severity": "WARNING",
                "message": "CSP violation report received",
                "csp-report": parsed
            });
            println!("{log_entry}");
        }
        Err(_) => {
            let log_entry = serde_json::json!({
                "severity": "WARNING",
                "message": "CSP report received with invalid JSON body",
                "raw-body": String::from_utf8_lossy(&body)
            });
            println!("{log_entry}");
            return StatusCode::BAD_REQUEST;
        }
    }

    StatusCode::NO_CONTENT
}

/// Check whether the content type is one used by CSP reporting mechanisms.
fn is_accepted_content_type(ct: &str) -> bool {
    let ct_lower = ct.to_ascii_lowercase();
    ct_lower.starts_with("application/csp-report")
        || ct_lower.starts_with("application/json")
        || ct_lower.starts_with("application/reports+json")
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind to address");

    eprintln!("Listening on {addr}");
    axum::serve(listener, app()).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn health_returns_ok() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn csp_report_uri_format() {
        let body = serde_json::json!({
            "csp-report": {
                "document-uri": "https://example.com",
                "violated-directive": "script-src 'self'",
                "blocked-uri": "https://evil.com/script.js",
                "original-policy": "script-src 'self'; report-uri /csp-report"
            }
        });

        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/csp-report")
                    .header("content-type", "application/csp-report")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn csp_report_to_format() {
        let body = serde_json::json!([{
            "type": "csp-violation",
            "age": 10,
            "url": "https://example.com/page",
            "user_agent": "Mozilla/5.0",
            "body": {
                "documentURL": "https://example.com/page",
                "blockedURL": "https://evil.com/script.js",
                "effectiveDirective": "script-src-elem",
                "originalPolicy": "script-src 'self'; report-to csp-endpoint"
            }
        }]);

        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/csp-report")
                    .header("content-type", "application/reports+json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn csp_report_with_application_json() {
        let body = serde_json::json!({"test": true});

        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/csp-report")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn csp_report_rejects_wrong_content_type() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/csp-report")
                    .header("content-type", "text/plain")
                    .body(Body::from("not json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn csp_report_rejects_invalid_json() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/csp-report")
                    .header("content-type", "application/csp-report")
                    .body(Body::from("this is not json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn csp_report_rejects_get_method() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/csp-report")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn csp_report_rejects_oversized_body() {
        // Create a body larger than MAX_BODY_SIZE (1 MB)
        let large_body = vec![b'{'; MAX_BODY_SIZE + 1];

        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/csp-report")
                    .header("content-type", "application/csp-report")
                    .body(Body::from(large_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn health_returns_empty_body() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }
}
