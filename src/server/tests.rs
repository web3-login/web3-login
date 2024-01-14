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

mod authorize_tests {
    use std::collections::HashMap;

    use crate::{
        config::Config,
        server::{router, Server},
    };
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use tower::ServiceExt;
    use url::Url;

    #[tokio::test]
    async fn test_authorize_redirect() {
        let mut config = Config::default();

        config.ext_hostname = "http://localhost:8000".to_string();
        config.frontend_host = "http://localhost:8081".to_string();
        config.chain_id.insert("default".into(), 42);
        config.node_provider.insert(
            "default".into(),
            "https://kovan.infura.io/v3/43".parse().unwrap(),
        );
        config.chain_id.insert("kovan".into(), 42);
        config.node_provider.insert(
            "kovan".into(),
            "https://kovan.infura.io/v3/43".parse().unwrap(),
        );
        // Configure other necessary settings for your config
        let server = Server::new(config);
        let app = router(server).unwrap();

        let client_id = "0xa0d4E5CdD89330ef9d0d1071247909882f0562eA";
        let uri = format!(
            "/authorize?client_id={}&realm=kovan&redirect_uri=unused",
            client_id
        );

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);

        let location_header = response.headers().get(http::header::LOCATION).unwrap();
        let location = location_header.to_str().unwrap();
        let response_url = Url::parse(location).unwrap();

        let params: HashMap<String, String> = response_url
            .query()
            .map(|v| {
                url::form_urlencoded::parse(v.as_bytes())
                    .into_owned()
                    .collect()
            })
            .unwrap_or_else(HashMap::new);

        assert_eq!(params.get("realm"), Some(&"kovan".to_string()));
        assert_eq!(params.get("chain_id"), Some(&"kovan".to_string()));
        assert_eq!(params.get("contract"), Some(&client_id.to_string()));
    }
}
