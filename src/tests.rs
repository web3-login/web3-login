
#[cfg(test)]
mod client_test {
    use crate::rocket;
    use rocket::http::Status;
    use rocket::local::blocking::Client;

    #[test]
    fn hello_world() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
    }
}

#[cfg(test)]
mod config_test {
    use crate::rocket;
    use rocket::http::Status;
    use rocket::local::blocking::Client;
    use serde_json::Value;

    #[test]
    fn test_provider() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/providers").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let userinfo = response.into_json::<Value>().unwrap();
        
        assert_eq!(userinfo.get("kovan").unwrap().as_str().unwrap(), "https://kovan.infura.io/v3/43");
        
    }
}
