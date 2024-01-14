use crate::server::routes::TokenParams;

use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn test_userinfo() {
    let config = Config::default();
    let server = Server::new(config);
    let router = router(server).unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/userinfo")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_options_user_info() {
    let config = Config::default();
    let server = Server::new(config);
    let router = router(server).unwrap();

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/userinfo")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_jwk() {
    let mut config = Config::default();
    config.rsa_pem = Some(include_str!("../../do-not-use.pem").to_string());
    let server = Server::new(config);
    let router = router(server).unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/jwk")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_realm_jwk() {
    let mut config = Config::default();
    config.rsa_pem = Some(include_str!("../../do-not-use.pem").to_string());
    let server = Server::new(config);
    let router = router(server).unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/default/jwk")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_openid_configuration() {
    let mut config = Config::default();
    config.ext_hostname = "https://example.com".to_string();
    let server = Server::new(config);
    let router = router(server).unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/openid-configuration")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_authorize() {
    let mut config = Config::default();
    config.ext_hostname = "https://example.com".to_string();
    let server = Server::new(config);
    let router = router(server).unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/oauth-authorization-server/authorize")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_token() {
    let mut config = Config::default();
    config.ext_hostname = "https://example.com".to_string();
    let server = Server::new(config);
    let router = router(server).unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/token?code=123456")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_post_token() {
    let mut config = Config::default();
    config.ext_hostname = "https://example.com".to_string();
    let server = Server::new(config);
    let router = router(server).unwrap();

    let token_params = TokenParams {
        code: "123456".to_string(),
    };
    let json_body = serde_json::to_string(&token_params).unwrap();

    // Construct the request
    let req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/json") // Set the content type to application/json
        .body(Body::from(json_body))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}