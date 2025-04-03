use std::sync::Arc;
use std::time::Duration;
use futures::future::BoxFuture;
use oauth2::basic::BasicTokenType;
use oauth2::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, TokenResponse, Scope, AuthUrl, TokenUrl, RefreshToken, 
    StandardTokenResponse, TokenType, AccessToken, EmptyExtraTokenFields,
    basic::BasicClient, reqwest::http_client, RefreshTokenRequest, AuthorizationRequest
};
use reqwest::{Client as HttpClient, header::AUTHORIZATION, StatusCode, Url, IntoUrl};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{self, Instant};

/// 错误定义
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("OAuth authorization required")]
    AuthorizationRequired,
    
    #[error("OAuth authorization failed: {0}")]
    AuthorizationFailed(String),
    
    #[error("OAuth token exchange failed: {0}")]
    TokenExchangeFailed(String),
    
    #[error("OAuth token refresh failed: {0}")]
    TokenRefreshFailed(String),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    
    #[error("OAuth error: {0}")]
    OAuthError(String),
    
    #[error("Metadata error: {0}")]
    MetadataError(String),
    
    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),
    
    #[error("No authorization support detected")]
    NoAuthorizationSupport,
    
    #[error("Internal error: {0}")]
    InternalError(String),
    
    #[error("Invalid token type: {0}")]
    InvalidTokenType(String),
    
    #[error("Token expired")]
    TokenExpired,
    
    #[error("Invalid scope: {0}")]
    InvalidScope(String),
    
    #[error("Registration failed: {0}")]
    RegistrationFailed(String),
}

/// 授权元数据，用于服务器发现
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizationMetadata {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
    pub issuer: Option<String>,
    pub jwks_uri: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
}

/// OAuth2 客户端配置
#[derive(Debug, Clone)]
pub struct OAuthClientConfig {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// 授权管理器
pub struct AuthorizationManager {
    http_client: HttpClient,
    metadata: Option<AuthorizationMetadata>,
    oauth_client: Option<BasicClient>,
    credentials: RwLock<Option<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>>,
    pkce_verifier: RwLock<Option<PkceCodeVerifier>>,
    base_url: Url,
}

impl AuthorizationManager {
    /// 创建新的授权管理器
    pub async fn new<U: IntoUrl>(base_url: U) -> Result<Self, AuthError> {
        let base_url = base_url.into_url()?;
        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AuthError::InternalError(e.to_string()))?;
            
        let mut manager = Self {
            http_client,
            metadata: None,
            oauth_client: None,
            credentials: RwLock::new(None),
            pkce_verifier: RwLock::new(None),
            base_url,
        };
        
        // 尝试发现授权服务器元数据
        if let Ok(metadata) = manager.discover_metadata().await {
            manager.metadata = Some(metadata);
        }
        
        Ok(manager)
    }
    
    /// 发现授权服务器元数据
    pub async fn discover_metadata(&self) -> Result<AuthorizationMetadata, AuthError> {
        // 按照规范，元数据应该位于 "/.well-known/oauth-authorization-server"
        let mut discovery_url = self.base_url.clone();
        discovery_url.set_path("/.well-known/oauth-authorization-server");
        
        let response = self.http_client
            .get(discovery_url)
            .header("MCP-Protocol-Version", "2024-11-05")
            .send()
            .await?;
            
        if response.status() == StatusCode::OK {
            let metadata = response.json::<AuthorizationMetadata>().await
                .map_err(|e| AuthError::MetadataError(format!("Failed to parse metadata: {}", e)))?;
            Ok(metadata)
        } else {
            // 回退到默认端点
            let mut auth_base = self.base_url.clone();
            // 丢弃路径部分，只保留 scheme, host, port
            auth_base.set_path("");
            
            Ok(AuthorizationMetadata {
                authorization_endpoint: format!("{}/authorize", auth_base),
                token_endpoint: format!("{}/token", auth_base),
                registration_endpoint: Some(format!("{}/register", auth_base)),
                issuer: None,
                jwks_uri: None,
                scopes_supported: None,
            })
        }
    }
    
    /// 使用客户端凭据配置 OAuth 客户端
    pub fn configure_client(&mut self, config: OAuthClientConfig) -> Result<(), AuthError> {
        if self.metadata.is_none() {
            return Err(AuthError::NoAuthorizationSupport);
        }
        
        let metadata = self.metadata.as_ref().unwrap();
        
        let auth_url = AuthUrl::new(metadata.authorization_endpoint.clone())
            .map_err(|e| AuthError::OAuthError(format!("Invalid authorization URL: {}", e)))?;
            
        let token_url = TokenUrl::new(metadata.token_endpoint.clone())
            .map_err(|e| AuthError::OAuthError(format!("Invalid token URL: {}", e)))?;
            
        let client_id = ClientId::new(config.client_id);
        let redirect_url = RedirectUrl::new(config.redirect_uri)
            .map_err(|e| AuthError::OAuthError(format!("Invalid redirect URL: {}", e)))?;
            
        let mut client_builder = BasicClient::new(client_id.clone(), None, auth_url.clone(), Some(token_url.clone()))
            .set_redirect_uri(redirect_url.clone());
            
        if let Some(secret) = config.client_secret {
            client_builder = BasicClient::new(client_id, Some(ClientSecret::new(secret)), auth_url, Some(token_url))
                .set_redirect_uri(redirect_url);
        }
        
        self.oauth_client = Some(client_builder);
        Ok(())
    }
    
    /// 动态注册客户端
    pub async fn register_client(&mut self, name: &str, redirect_uri: &str) -> Result<OAuthClientConfig, AuthError> {
        if self.metadata.is_none() {
            return Err(AuthError::NoAuthorizationSupport);
        }
        
        let metadata = self.metadata.as_ref().unwrap();
        let registration_url = metadata.registration_endpoint.as_ref()
            .ok_or_else(|| AuthError::NoAuthorizationSupport)?;
            
        // 准备注册请求
        let registration_request = serde_json::json!({
            "client_name": name,
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none", // 公共客户端
            "response_types": ["code"],
        });
        
        let response = self.http_client
            .post(registration_url)
            .json(&registration_request)
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(AuthError::OAuthError(format!(
                "Client registration failed: HTTP {}", response.status()
            )));
        }
        
        #[derive(Deserialize)]
        struct RegistrationResponse {
            client_id: String,
            client_secret: Option<String>,
        }
        
        let reg_response = response.json::<RegistrationResponse>().await
            .map_err(|e| AuthError::OAuthError(format!("Failed to parse registration response: {}", e)))?;
            
        let config = OAuthClientConfig {
            client_id: reg_response.client_id,
            client_secret: reg_response.client_secret,
            redirect_uri: redirect_uri.to_string(),
            scopes: vec![],
        };
        
        self.configure_client(config.clone())?;
        Ok(config)
    }
    
    /// 生成授权 URL
    pub async fn get_authorization_url(&self, scopes: &[&str]) -> Result<String, AuthError> {
        let oauth_client = self.oauth_client.as_ref()
            .ok_or_else(|| AuthError::InternalError("OAuth client not configured".to_string()))?;
            
        // 生成 PKCE 挑战
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        
        // 构建授权请求
        let mut auth_request = oauth_client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge);
            
        // 添加请求的作用域
        for scope in scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.to_string()));
        }
        
        let (auth_url, _csrf_token) = auth_request.url();

        // 存储 PKCE 验证器以供后续使用
        *self.pkce_verifier.write().await = Some(pkce_verifier);
        
        Ok(auth_url.to_string())
    }
    
    /// 使用授权码交换访问令牌
    pub async fn exchange_code_for_token(&self, code: &str) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, AuthError> {
        let oauth_client = self.oauth_client.as_ref()
            .ok_or_else(|| AuthError::InternalError("OAuth client not configured".to_string()))?;
            
        let pkce_verifier = self.pkce_verifier.write().await.take().unwrap();
        
        // 交换令牌
        let token_result = oauth_client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(pkce_verifier)
            .request(http_client)
            .map_err(|e| AuthError::TokenExchangeFailed(e.to_string()))?;
            
        // 存储凭据
        *self.credentials.write().await = Some(token_result.clone());
        
        Ok(token_result)
    }
    
    /// 获取访问令牌，如果过期则自动刷新
    pub async fn get_access_token(&self) -> Result<String, AuthError> {
        let credentials = self.credentials.read().await;
        
        if let Some(creds) = credentials.as_ref() {
            // 检查令牌是否过期
            if let Some(expires_in) = creds.expires_in() {
                if expires_in <= Duration::from_secs(0) {
                    // TODO
                    // 令牌已过期，尝试刷新
                    drop(credentials); // 释放锁
                    let new_creds = self.refresh_token().await?;
                    return Ok(new_creds.access_token().secret().to_string());
                }
            }
            
            Ok(creds.access_token().secret().to_string())
        } else {
            Err(AuthError::AuthorizationRequired)
        }
    }
    
    /// 刷新访问令牌
    pub async fn refresh_token(&self) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, AuthError> {
        let oauth_client = self.oauth_client.as_ref()
            .ok_or_else(|| AuthError::InternalError("OAuth client not configured".to_string()))?;
            
        let current_credentials = self.credentials.read().await.clone()
            .ok_or_else(|| AuthError::AuthorizationRequired)?;
            
        let refresh_token = current_credentials.refresh_token()
            .ok_or_else(|| AuthError::TokenRefreshFailed("No refresh token available".to_string()))?;
            
        // 刷新令牌
        let token_result = oauth_client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.secret().to_string()))
            .request(http_client)
            .map_err(|e| AuthError::TokenRefreshFailed(e.to_string()))?;
            
        
        // 存储新凭据
        *self.credentials.write().await = Some(token_result.clone());
        
        Ok(token_result)
    }
    
    /// 准备请求，添加授权头
    pub async fn prepare_request(&self, mut request: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder, AuthError> {
        let token = self.get_access_token().await?;
        Ok(request.header(AUTHORIZATION, format!("Bearer {}", token)))
    }
    
    /// 处理响应，检查是否需要重新授权
    pub async fn handle_response(&self, response: reqwest::Response) -> Result<reqwest::Response, AuthError> {
        if response.status() == StatusCode::UNAUTHORIZED {
            // 401 Unauthorized，需要重新授权
            Err(AuthError::AuthorizationRequired)
        } else {
            Ok(response)
        }
    }
}

/// OAuth2 授权会话，用于引导用户完成授权流程
pub struct AuthorizationSession {
    pub auth_manager: Arc<Mutex<AuthorizationManager>>,
    pub auth_url: String,
    pub redirect_uri: String,
    pub pkce_verifier: PkceCodeVerifier,
}

impl AuthorizationSession {
    /// 创建新的授权会话
    pub async fn new(
        auth_manager: Arc<Mutex<AuthorizationManager>>, 
        scopes: &[&str],
        redirect_uri: &str,
    ) -> Result<Self, AuthError> {
        // 设置重定向 URI
        let config = OAuthClientConfig {
            client_id: "mcp-client".to_string(), // 临时 ID，将通过动态注册更新
            client_secret: None,
            redirect_uri: redirect_uri.to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        };
        
        // 尝试动态注册客户端
        let config = match auth_manager.lock().await.register_client("MCP Client", redirect_uri).await {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Dynamic registration failed: {}", e);
                // 回退到默认配置
                config
            }
        };
        
        let auth_url= auth_manager.lock().await.get_authorization_url(scopes).await?;
        let pkce_verifier = auth_manager.lock().await.pkce_verifier.write().await.take().unwrap();
        Ok(Self {
            auth_manager,
            auth_url,
            redirect_uri: redirect_uri.to_string(),
            pkce_verifier,
        })
    }
    
    /// 获取授权 URL
    pub fn get_authorization_url(&self) -> &str {
        &self.auth_url
    }
    
    /// 处理授权码回调
    pub async fn handle_callback(&self, code: &str) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, AuthError> {
        self.auth_manager.lock().await.exchange_code_for_token(code).await
    }
}

/// HTTP 客户端扩展，自动添加授权头
pub struct AuthorizedHttpClient {
    auth_manager: Arc<AuthorizationManager>,
    inner_client: HttpClient,
}

impl AuthorizedHttpClient {
    /// 创建新的授权 HTTP 客户端
    pub fn new(auth_manager: Arc<AuthorizationManager>, client: Option<HttpClient>) -> Self {
        let inner_client = client.unwrap_or_else(|| HttpClient::new());
        Self {
            auth_manager,
            inner_client,
        }
    }
    
    /// 发送带授权的请求
    pub async fn request<U: IntoUrl>(&self, method: reqwest::Method, url: U) -> Result<reqwest::RequestBuilder, AuthError> {
        let request = self.inner_client.request(method, url);
        self.auth_manager.prepare_request(request).await
    }
    
    /// 发送 GET 请求
    pub async fn get<U: IntoUrl>(&self, url: U) -> Result<reqwest::Response, AuthError> {
        let request = self.request(reqwest::Method::GET, url).await?;
        let response = request.send().await?;
        self.auth_manager.handle_response(response).await
    }
    
    /// 发送 POST 请求
    pub async fn post<U: IntoUrl>(&self, url: U) -> Result<reqwest::RequestBuilder, AuthError> {
        self.request(reqwest::Method::POST, url).await
    }
} 