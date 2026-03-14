use axum::{
    extract::Request,
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};
use std::sync::OnceLock;

static AUTH_TOKEN: OnceLock<String> = OnceLock::new();

/// Инициализирует токен аутентификации. Вызывается один раз из main до старта сервера.
pub fn init_token(token: String) {
    AUTH_TOKEN.set(token).expect("CRITICAL: AUTH_TOKEN already initialized");
}

pub async fn auth_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = AUTH_TOKEN.get().expect("CRITICAL: AUTH_TOKEN not initialized — call auth::init_token() before serving");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_same() {
        assert!(constant_time_eq("abc123", "abc123"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq("abc123", "abc124"));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "x"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_auth_header_valid() {
        assert!(auth_header_is_valid("Bearer mytoken123", "mytoken123"));
    }

    #[test]
    fn test_auth_header_invalid_token() {
        assert!(!auth_header_is_valid("Bearer wrong", "mytoken123"));
    }

    #[test]
    fn test_auth_header_missing_bearer() {
        assert!(!auth_header_is_valid("mytoken123", "mytoken123"));
        assert!(!auth_header_is_valid("Token mytoken123", "mytoken123"));
    }
}
