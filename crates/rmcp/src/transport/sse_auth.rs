use std::sync::Arc;
use std::time::Duration;

use futures::{Future, Sink, Stream, StreamExt, future::BoxFuture, stream::BoxStream};
use futures::sink::SinkExt as FuturesSinkExt;
use reqwest::{
    Client as HttpClient, IntoUrl, Url,
    header::{ACCEPT, AUTHORIZATION, HeaderValue},
};
use sse_stream::{Error as SseError, Sse, SseStream};
use thiserror::Error;

use crate::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use super::auth::{AuthorizationManager, AuthError};
use super::sse::{SseTransportError, SseClient, SseTransport, SseTransportRetryConfig};

// SSE MIME 类型
const MIME_TYPE: &str = "text/event-stream";
const HEADER_LAST_EVENT_ID: &str = "Last-Event-ID";

/// 支持 OAuth 授权的 SSE 客户端
#[derive(Clone)]
pub struct AuthorizedSseClient {
    http_client: HttpClient,
    sse_url: Url,
    auth_manager: Arc<AuthorizationManager>,
    retry_config: SseTransportRetryConfig,
}

impl AuthorizedSseClient {
    /// 创建新的授权 SSE 客户端
    pub fn new<U>(
        url: U,
        auth_manager: Arc<AuthorizationManager>,
        retry_config: Option<SseTransportRetryConfig>,
    ) -> Result<Self, SseTransportError<reqwest::Error>>
    where
        U: IntoUrl,
    {
        let url = url.into_url().map_err(SseTransportError::from)?;
        Ok(Self {
            http_client: HttpClient::default(),
            sse_url: url,
            auth_manager,
            retry_config: retry_config.unwrap_or_default(),
        })
    }

    /// 使用自定义 HTTP 客户端创建授权 SSE 客户端
    pub async fn new_with_client<U>(
        url: U,
        client: HttpClient,
        auth_manager: Arc<AuthorizationManager>,
        retry_config: Option<SseTransportRetryConfig>,
    ) -> Result<Self, SseTransportError<reqwest::Error>>
    where
        U: IntoUrl,
    {
        let url = url.into_url().map_err(SseTransportError::from)?;
        Ok(Self {
            http_client: client,
            sse_url: url,
            auth_manager,
            retry_config: retry_config.unwrap_or_default(),
        })
    }

    /// 获取访问令牌，支持重试
    async fn get_token_with_retry(&self) -> Result<String, SseTransportError<reqwest::Error>> {
        let mut retries = 0;
        let max_retries = self.retry_config.max_times;
        let base_delay = self.retry_config.min_duration;

        loop {
            match self.auth_manager.get_access_token().await {
                Ok(token) => return Ok(token),
                Err(AuthError::AuthorizationRequired) => {
                    return Err(SseTransportError::Io(std::io::Error::new(std::io::ErrorKind::Other, "Authorization required")));
                }
                Err(e) => {
                    if retries >= max_retries.unwrap_or(0) {
                        return Err(SseTransportError::Io(std::io::Error::new(std::io::ErrorKind::Other, "Authorization required")));
                    }
                    retries += 1;
                    // todo 需要优化
                    let delay = base_delay.as_millis();
                    tokio::time::sleep(Duration::from_millis(delay as u64)).await;
                }
            }
        }
    }
}

impl SseClient<reqwest::Error> for AuthorizedSseClient {
    fn connect(&self, last_event_id: Option<String>) -> BoxFuture<'static, Result<BoxStream<'static, Result<Sse, SseError>>, SseTransportError<reqwest::Error>>> {
        let client = self.http_client.clone();
        let sse_url = self.sse_url.as_ref().to_string();
        let last_event_id = last_event_id.clone();
        let auth_manager = self.auth_manager.clone();
        
        let fut = async move {
            // 获取访问令牌
            let token = auth_manager.get_access_token().await?;
                
            // 构建请求
            let mut request_builder = client.get(&sse_url)
                .header(ACCEPT, MIME_TYPE)
                .header(AUTHORIZATION, format!("Bearer {}", token));
                
            if let Some(last_event_id) = last_event_id {
                request_builder = request_builder.header(HEADER_LAST_EVENT_ID, last_event_id);
            }
            
            let response = request_builder.send().await?;
            let response = response.error_for_status()?;
            
            match response.headers().get(reqwest::header::CONTENT_TYPE) {
                Some(ct) => {
                    if !ct.as_bytes().starts_with(MIME_TYPE.as_bytes()) {
                        return Err(SseTransportError::UnexpectedContentType(Some(ct.clone())));
                    }
                }
                None => {
                    return Err(SseTransportError::UnexpectedContentType(None));
                }
            }
            
            let event_stream = SseStream::from_byte_stream(response.bytes_stream()).boxed();
            Ok(event_stream)
        };
        
        Box::pin(fut)
    }

    fn post(
        &self,
        session_id: &str,
        message: ClientJsonRpcMessage,
    ) -> BoxFuture<'static, Result<(), SseTransportError<reqwest::Error>>> {
        let client = self.http_client.clone();
        let sse_url = self.sse_url.clone();
        let session_id = session_id.to_string();
        let auth_manager = self.auth_manager.clone();
        
        Box::pin(async move {
            // 获取访问令牌
            let token = auth_manager.get_access_token().await
                .map_err(|e| SseTransportError::<reqwest::Error>::from(e))?;
            
            let uri = sse_url.join(&session_id).map_err(SseTransportError::from)?;
            let request_builder = client.post(uri.as_ref())
                .header(AUTHORIZATION, format!("Bearer {}", token))
                .json(&message);
                
            request_builder
                .send()
                .await
                .and_then(|resp| resp.error_for_status())
                .map_err(SseTransportError::from)
                .map(drop)
        })
    }
}

impl From<AuthError> for SseTransportError<reqwest::Error> {
    fn from(err: AuthError) -> Self {
        SseTransportError::Io(std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))
    }
}

/// 创建带授权的 SSE 传输
pub async fn create_authorized_transport<U>(
    url: U,
    auth_manager: Arc<AuthorizationManager>,
    retry_config: Option<SseTransportRetryConfig>,
) -> Result<SseTransport<AuthorizedSseClient, reqwest::Error>, SseTransportError<reqwest::Error>>
where
    U: IntoUrl,
{
    let client = AuthorizedSseClient::new(url, auth_manager, retry_config)?;
    SseTransport::start_with_client(client).await
} 