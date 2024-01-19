use crate::server::routes::TokenParams;

use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

fn test_config() -> Config {
    let mut config = Config::default();
    config.rsa_pem = Some(include_str!("../../do-not-use.pem").to_string());
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
    config.chain_id.insert("okt".into(), 65);
    config.node_provider.insert(
        "okt".into(),
        "https://exchaintestrpc.okex.org".parse().unwrap(),
    );
    config
}

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
    use super::*;
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
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

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

    #[tokio::test]
    async fn account_valid_signature() {
        let client_id = "foo";
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        let config = test_config();

        let server = Server::new(config);
        let app = router(server).unwrap();

        let uri = format!(
            "/account/authorize?client_id={}&redirect_uri=https://example.com&nonce={}&account={}&signature={}", client_id, nonce, account, signature);

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    #[ignore = "does not stop"]
    #[tokio::test]
    async fn test_wrong_redirect_uri() {
        let client_id = "foo";
        let contract = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4";
        let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
        let nonce = "dotzxrenodo".to_string();
        let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

        let config = test_config();

        let server = Server::new(config);
        let app = router(server).unwrap();

        let uri = format!(
            "/authorize?client_id={}&realm=okt&redirect_uri=wrong_uri&nonce={}&contract={}&account={}&signature={}",
            client_id, nonce, contract, account, signature
        );

        let request = Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get("Location").unwrap(),
            "/400.html?message=wrong%20redirect%20uri"
        );
    }

    mod account_scope {

        use super::*;
        use http_body_util::BodyExt;
        use serde_json::Value;

        #[tokio::test]
        async fn test_jwk() {
            let config = test_config();

            let server = Server::new(config);
            let app = router(server).unwrap();

            let uri = format!("/account/default/jwk");

            let request = Request::builder()
                .method(http::Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body: Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["keys"].is_array(), true);
        }

        #[tokio::test]
        async fn test_openid_configuration() {
            let config = test_config();

            let server = Server::new(config);
            let app = router(server).unwrap();

            let uri = format!("/account/.well-known/openid-configuration");

            let request = Request::builder()
                .method(http::Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body: Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["issuer"], "http://localhost:8000/account");
        }

        #[tokio::test]
        async fn test_oauth_authorization_server() {
            let config = test_config();

            let server = Server::new(config);
            let app = router(server).unwrap();

            let uri = format!("/account/.well-known/oauth-authorization-server/authorize");

            let request = Request::builder()
                .method(http::Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body: Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["issuer"], "http://localhost:8000/account");
            assert_eq!(
                body["authorization_endpoint"],
                "http://localhost:8000/account/authorize"
            );
        }

        #[tokio::test]
        async fn test_account_valid_signature() {
            let client_id = "foo";
            let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
            let nonce = "dotzxrenodo".to_string();
            let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

            let config = test_config();
            let server = Server::new(config);
            let app = router(server).unwrap();

            let uri = format!(
                "/account/authorize?client_id={}&redirect_uri=https://example.com&nonce={}&account={}&signature={}",
                client_id, nonce, account, signature);

            let request = Request::builder()
                .method(http::Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();

            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        }
    }

    mod nft_scope {
        use super::*;

        #[tokio::test]
        async fn test_redirect() {
            let client_id = "0xa0d4E5CdD89330ef9d0d1071247909882f0562eA";

            let config = test_config();
            let server = Server::new(config);
            let app = router(server).unwrap();

            let uri = format!(
                "/nft/authorize?client_id={}&realm=kovan&redirect_uri=unused",
                client_id
            );

            let request = Request::builder()
                .method(http::Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

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

        #[tokio::test]
        async fn test_wrong_redirect_uri() {
            let client_id = "foo";
            let contract = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4";

            // Somehow this is not working, but it works in web3.rs tests
            let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
            let account = "0x9c9E8eAbD947658bDb713E0d3eBfe56860abdb8D".to_string();

            let nonce = "dotzxrenodo".to_string();
            let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();

            let config = test_config();
            let server = Server::new(config);
            let app = router(server).unwrap();

            let uri = format!(
                "/nft/authorize?client_id={}&realm=okt&redirect_uri=wrong_uri&nonce={}&contract={}&account={}&signature={}",
                client_id, nonce, contract, account, signature
            );

            let request = Request::builder()
                .method(http::Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
            assert_eq!(
                response.headers().get("Location").unwrap(),
                "/400.html?message=wrong%20redirect%20uri"
            );
        }

        #[tokio::test]
        async fn test_st_ate() {
            let client_id = "foo";
            let contract = "0x886B6781CD7dF75d8440Aba84216b2671AEFf9A4";

            // Somehow this is not working, but it works in web3.rs tests
            let account = "0x9c9e8eabd947658bdb713e0d3ebfe56860abdb8d".to_string();
            let account = "0x9c9E8eAbD947658bDb713E0d3eBfe56860abdb8D".to_string();

            let nonce = "dotzxrenodo".to_string();
            let signature = "0x87b709d1e84aab056cf089af31e8d7c891d6f363663ff3eeb4bbb4c4e0602b2e3edf117fe548626b8d83e3b2c530cb55e2baff29ca54dbd495bb45764d9aa44c1c".to_string();
            let state = "state".to_string();

            let config = test_config();
            let server = Server::new(config);
            let app = router(server).unwrap();

            let uri = format!(
                "/nft/authorize?client_id={}&realm=okt&redirect_uri=https://example.com&nonce={}&contract={}&account={}&signature={}&state={}",
                client_id, nonce, contract, account, signature, state
            );

            let request = Request::builder()
                .method(http::Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

            let location_header = response.headers().get(http::header::LOCATION).unwrap();
            let location = location_header.to_str().unwrap();
            let response_url = Url::parse(location).unwrap();
            println!("{:?}", response_url);

            let params: HashMap<String, String> = response_url
                .query()
                .map(|v| {
                    url::form_urlencoded::parse(v.as_bytes())
                        .into_owned()
                        .collect()
                })
                .unwrap_or_else(HashMap::new);

            assert_eq!(params.get("state"), Some(&state));
        }
    }
}
