use std::{sync::Arc, time::Duration};
use anyhow::Result;
use rmcp::{
    model::{ClientInfo, PaginatedRequestParamInner}, transport::{
        auth::{AuthError, AuthorizationManager, AuthorizationSession, AuthorizedHttpClient}, create_authorized_transport, sse::SseTransportRetryConfig
    }, RoleClient, ServiceExt
};
use tokio::io::{AsyncWriteExt, BufWriter, AsyncReadExt};
use url::Url;
use std::sync::Mutex;


#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志
    tracing_subscriber::fmt::init();
    
    // 服务器 URL
    let server_url = std::env::var("MCP_SERVER_URL")
        .unwrap_or_else(|_| "http://localhost:3000/mcp".to_string());
    
    // 配置重试策略
    let retry_config = SseTransportRetryConfig {
        max_times: Some(3),
        min_duration: Duration::from_secs(1),
    };
    
    // 初始化授权管理器
    let auth_manager = Arc::new(Mutex::new(AuthorizationManager::new(&server_url).await?));
    
    // 创建授权会话
    let session = AuthorizationSession::new(
        auth_manager.clone(),
        &["mcp"], // 请求的作用域
        "http://localhost:8080/callback", // 重定向 URI
    ).await?;
    
    // 输出授权 URL
    let mut output = BufWriter::new(tokio::io::stdout());
    output.write_all(b"please open the following URL in your browser:\n").await?;
    output.write_all(session.get_authorization_url().as_bytes()).await?;
    output.write_all(b"\n\nplease input the authorization code:\n").await?;
    output.flush().await?;
    
    // 读取授权码
    let mut auth_code = String::new();
    tokio::io::stdin().read_line(&mut auth_code).await?;
    let auth_code = auth_code.trim();
    
    // 交换访问令牌
    let credentials = session.handle_callback(auth_code).await?;

    
    // 创建授权 SSE 传输，使用重试配置
    let transport = create_authorized_transport(
        &server_url,
        Arc::clone(&auth_manager),
        Some(retry_config),
    ).await?;
    
    // 创建客户端
    let client_service = ClientInfo::default();
    let client = client_service.serve(transport).await?;
    
    // 测试 API 请求
    let tools = client.peer().list_all_tools().await?;
    tracing::info!("Available tools: {tools:#?}");
    
    // 获取提示列表
    let prompts = client.peer().list_all_prompts().await?;
    tracing::info!("Available prompts: {prompts:#?}");
    
    // 获取资源列表
    let resources = client.peer().list_all_resources().await?;
    tracing::info!("Available resources: {resources:#?}");

    
    Ok(())
} 