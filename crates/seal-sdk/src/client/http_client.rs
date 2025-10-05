use async_trait::async_trait;
use std::collections::HashMap;

pub struct PostResponse {
    pub status: u16,
    pub text: String,
}

impl PostResponse {
    pub fn is_success(&self) -> bool {
        let status = self.status;

        status >= 200 && status < 300
    }
}

#[async_trait]
pub trait HttpClient: Sync {
    type PostError;

    async fn post<S: ToString + Send + Sync>(
        &self,
        url: &str,
        headers: HashMap<String, String>,
        body: S
    ) -> Result<PostResponse, Self::PostError>;
}

#[cfg(feature = "reqwest")]
mod reqwest {
    use crate::client::error::ReqwestError;
    use crate::client::http_client::{HttpClient, PostResponse};
    use async_trait::async_trait;
    use http::{HeaderMap, HeaderName, HeaderValue};
    use reqwest::Body;
    use std::collections::HashMap;
    use std::str::FromStr;

    #[async_trait]
    impl HttpClient for reqwest::Client {
        type PostError = ReqwestError;

        async fn post<S: ToString + Send + Sync>(
            &self,
            url: &str,
            headers: HashMap<String, String>,
            body: S
        ) -> Result<PostResponse, Self::PostError> {
            let mut header_map = HeaderMap::new();

            for (key, value) in headers {
                header_map.insert(HeaderName::from_str(&key)?, HeaderValue::from_str(&value)?);
            }
            let response = self.post(url)
                .headers(header_map)
                .body(Body::from(body.to_string()))
                .send()
                .await?;

            let status = response.status().as_u16();
            let text = response.text().await?;

            let response = PostResponse {
                status,
                text,
            };

            Ok(response)
        }
    }
}