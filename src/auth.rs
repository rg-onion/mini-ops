use axum::{
    extract::Request,
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};

pub async fn auth_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = std::env::var("AUTH_TOKEN").expect("CRITICAL: AUTH_TOKEN must be set in env or .env file");

    let auth_header = request.headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    match auth_header {
        Some(auth_header) if auth_header_is_valid(auth_header, &token) => Ok(next.run(request).await),
        _ => {
            let uri = request.uri();
            if uri.path().contains("/logs") {
                tracing::warn!("Log stream auth failed for path: {}", uri.path());
            }
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

fn auth_header_is_valid(header: &str, expected_token: &str) -> bool {
    // Expected format: "Bearer <token>"
    if let Some(provided_token) = header.strip_prefix("Bearer ") {
        return constant_time_eq(provided_token, expected_token);
    }
    false
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
