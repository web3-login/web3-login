use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

#[derive(Debug)]
pub struct Bearer(pub String);

#[derive(Debug)]
pub enum BearerError {
    Missing,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Bearer {
    type Error = BearerError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match req.headers().get_one("Authorization") {
            None => Outcome::Error((Status::BadRequest, BearerError::Missing)),
            Some(token) => Outcome::Success(Bearer(token.to_string().replace("Bearer ", ""))),
        }
    }
}
