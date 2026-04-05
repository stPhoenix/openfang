//! Production middleware for the OpenFang API server.
//!
//! Provides:
//! - Request ID generation and propagation
//! - Per-endpoint structured request logging
//! - In-memory rate limiting (per IP)

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use std::time::Instant;
use tracing::info;

/// Request ID header name (standard).
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Middleware: inject a unique request ID and log the request/response.
pub async fn request_logging(request: Request<Body>, next: Next) -> Response<Body> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = request.method().clone();
    let uri = request.uri().path().to_string();
    let start = Instant::now();

    let mut response = next.run(request).await;

    let elapsed = start.elapsed();
    let status = response.status().as_u16();

    info!(
        request_id = %request_id,
        method = %method,
        path = %uri,
        status = status,
        latency_ms = elapsed.as_millis() as u64,
        "API request"
    );

    // Inject the request ID into the response
    if let Ok(header_val) = request_id.parse() {
        response.headers_mut().insert(REQUEST_ID_HEADER, header_val);
    }

    response
}

/// Authentication state passed to the auth middleware.
#[derive(Clone)]
pub struct AuthState {
    pub api_key: String,
    /// SHA-256 hash of the API key. When set, token auth compares against this
    /// hash instead of the plaintext `api_key`.
    pub api_key_hash: Option<String>,
    pub auth_enabled: bool,
    pub session_secret: String,
    pub require_auth_for_reads: bool,
}

/// Bearer token authentication middleware.
///
/// When `api_key` is non-empty (after trimming), requests to non-public
/// endpoints must include `Authorization: Bearer <api_key>`.
/// If the key is empty or whitespace-only, auth is disabled entirely
/// (public/local development mode).
///
/// When dashboard auth is enabled, session cookies are also accepted.
pub async fn auth(
    axum::extract::State(auth_state): axum::extract::State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    // SECURITY: Capture method early for method-aware public endpoint checks.
    let method = request.method().clone();

    // Shutdown is loopback-only (CLI on same machine) — skip token auth
    let path = request.uri().path();
    if path == "/api/shutdown" {
        let is_loopback = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip().is_loopback())
            .unwrap_or(false); // SECURITY: default-deny — unknown origin is NOT loopback
        if is_loopback {
            return next.run(request).await;
        }
    }

    // Public endpoints that don't require auth.
    // SECURITY: POST/PUT/DELETE to any endpoint ALWAYS requires auth to prevent
    // unauthenticated writes (cron job creation, skill install, etc.).
    let is_get = method == axum::http::Method::GET;

    // Tier 1: Always public — health, auth, static assets, A2A protocol.
    // These remain public even when require_auth_for_reads is enabled.
    let is_always_public = path == "/"
        || path == "/logo.png"
        || path == "/favicon.ico"
        || (path == "/.well-known/agent.json" && is_get)
        || (path.starts_with("/a2a/") && is_get)
        || path == "/api/health"
        || path == "/api/health/detail"
        || path == "/api/status"
        || path == "/api/version"
        || (path == "/api/config/schema" && is_get)
        || path.starts_with("/api/providers/github-copilot/oauth/")
        || path == "/api/auth/login"
        || path == "/api/auth/logout"
        || (path == "/api/auth/check" && is_get);

    if is_always_public {
        return next.run(request).await;
    }

    // Tier 2: Dashboard read endpoints — public unless require_auth_for_reads
    // is enabled. Allows the SPA to render before login in permissive mode.
    // SECURITY: /api/agents is GET-only (listing). POST (spawn) requires auth.
    if !auth_state.require_auth_for_reads {
        let is_dashboard_public = is_get
            && (path == "/api/agents"
            || path == "/api/profiles"
            || path == "/api/config"
            || path.starts_with("/api/uploads/")
            || path == "/api/models"
            || path == "/api/models/aliases"
            || path == "/api/providers"
            || path == "/api/budget"
            || path == "/api/budget/agents"
            || path.starts_with("/api/budget/agents/")
            || path == "/api/network/status"
            || path == "/api/a2a/agents"
            || path == "/api/approvals"
            || path.starts_with("/api/approvals/")
            || path == "/api/channels"
            || path == "/api/hands"
            || path == "/api/hands/active"
            || path.starts_with("/api/hands/")
            || path == "/api/skills"
            || path == "/api/sessions"
            || path == "/api/integrations"
            || path == "/api/integrations/available"
            || path == "/api/integrations/health"
            || path == "/api/workflows"
            || path == "/api/logs/stream"  // SSE stream, read-only
            || path.starts_with("/api/cron/"));
        if is_dashboard_public {
            return next.run(request).await;
        }
    }

    // If no API key configured (empty, whitespace-only, or missing), skip auth
    // entirely. Users who don't set api_key accept that all endpoints are open.
    // To secure the dashboard, set a non-empty api_key in config.toml.
    let api_key_trimmed = auth_state.api_key.trim().to_string();
    if api_key_trimmed.is_empty() && !auth_state.auth_enabled {
        return next.run(request).await;
    }
    let api_key = api_key_trimmed.as_str();

    // Check Authorization: Bearer <token> header, then fallback to X-API-Key
    let bearer_token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let api_token = bearer_token.or_else(|| {
        request
            .headers()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
    });

    // SECURITY: Use constant-time comparison to prevent timing attacks.
    let header_auth = api_token.map(|token| {
        verify_api_token(token, api_key, auth_state.api_key_hash.as_deref())
    });

    // Also check ?token= query parameter (for EventSource/SSE clients that
    // cannot set custom headers, same approach as WebSocket auth).
    let query_token = request
        .uri()
        .query()
        .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("token=")));

    // SECURITY: Use constant-time comparison to prevent timing attacks.
    let query_auth = query_token.map(|token| {
        verify_api_token(token, api_key, auth_state.api_key_hash.as_deref())
    });

    // Accept if either auth method matches
    if header_auth == Some(true) || query_auth == Some(true) {
        return next.run(request).await;
    }

    // Check session cookie (dashboard login sessions)
    if auth_state.auth_enabled {
        if let Some(token) = extract_session_cookie(&request) {
            if crate::session_auth::verify_session_token(&token, &auth_state.session_secret)
                .is_some()
            {
                return next.run(request).await;
            }
        }
    }

    // Determine error message: was a credential provided but wrong, or missing entirely?
    let credential_provided = header_auth.is_some() || query_auth.is_some();
    let error_msg = if credential_provided {
        "Invalid API key"
    } else {
        "Missing Authorization: Bearer <api_key> header"
    };

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("www-authenticate", "Bearer")
        .body(Body::from(
            serde_json::json!({"error": error_msg}).to_string(),
        ))
        .unwrap_or_default()
}

/// Extract the `openfang_session` cookie value from a request.
fn extract_session_cookie(request: &Request<Body>) -> Option<String> {
    request
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                c.trim()
                    .strip_prefix("openfang_session=")
                    .map(|v| v.to_string())
            })
        })
}

/// Verify a provided API token against the configured key.
/// When `api_key_hash` is set, SHA-256 hashes the token and compares against the stored hash.
/// Otherwise, compares the plaintext token directly. Both paths use constant-time comparison.
fn verify_api_token(token: &str, plaintext_key: &str, api_key_hash: Option<&str>) -> bool {
    use subtle::ConstantTimeEq;
    if let Some(stored_hash) = api_key_hash {
        // Hash-based: SHA-256 the provided token, compare to stored hash.
        use sha2::{Digest, Sha256};
        let computed = hex::encode(Sha256::digest(token.as_bytes()));
        if computed.len() != stored_hash.len() {
            return false;
        }
        computed.as_bytes().ct_eq(stored_hash.as_bytes()).into()
    } else {
        // Plaintext comparison (existing behavior).
        if token.len() != plaintext_key.len() {
            return false;
        }
        token.as_bytes().ct_eq(plaintext_key.as_bytes()).into()
    }
}

/// Security headers middleware — applied to ALL API responses.
pub async fn security_headers(request: Request<Body>, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
    // The dashboard handler (webchat_page) sets its own nonce-based CSP.
    // For all other responses (API endpoints), apply a strict default.
    if !headers.contains_key("content-security-policy") {
        headers.insert(
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'"
                .parse()
                .unwrap(),
        );
    }
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "cache-control",
        "no-store, no-cache, must-revalidate".parse().unwrap(),
    );
    headers.insert(
        "strict-transport-security",
        "max-age=63072000; includeSubDomains".parse().unwrap(),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use tower::ServiceExt;

    #[test]
    fn test_request_id_header_constant() {
        assert_eq!(REQUEST_ID_HEADER, "x-request-id");
    }

    /// Helper: build a minimal router with auth middleware and a catch-all 200 handler.
    fn test_router(auth_state: AuthState) -> Router {
        async fn ok() -> &'static str {
            "ok"
        }
        Router::new()
            .route("/api/health", get(ok))
            .route("/api/agents", get(ok))
            .route("/api/budget", get(ok))
            .route("/api/auth/check", get(ok))
            .layer(axum::middleware::from_fn_with_state(auth_state, auth))
    }

    fn strict_auth_state() -> AuthState {
        AuthState {
            api_key: "test-secret".to_string(),
            api_key_hash: None,
            auth_enabled: false,
            session_secret: String::new(),
            require_auth_for_reads: true,
        }
    }

    fn permissive_auth_state() -> AuthState {
        AuthState {
            api_key: "test-secret".to_string(),
            api_key_hash: None,
            auth_enabled: false,
            session_secret: String::new(),
            require_auth_for_reads: false,
        }
    }

    #[tokio::test]
    async fn strict_mode_blocks_dashboard_reads() {
        let app = test_router(strict_auth_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/agents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn strict_mode_allows_health() {
        let app = test_router(strict_auth_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn strict_mode_allows_auth_check() {
        let app = test_router(strict_auth_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/auth/check")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn strict_mode_blocks_budget() {
        let app = test_router(strict_auth_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/budget")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn strict_mode_allows_with_bearer_token() {
        let app = test_router(strict_auth_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/agents")
                    .header("Authorization", "Bearer test-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn permissive_mode_allows_dashboard_reads() {
        let app = test_router(permissive_auth_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/agents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
