# Model Context Protocol OAuth 授权

本文档描述了 Model Context Protocol (MCP) 的 OAuth 2.1 授权实现，按照 [MCP 2025-03-26 授权规范](https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/) 实现。

## 功能特性

- 完整支持 OAuth 2.1 授权流程
- 支持 PKCE 增强安全性
- 支持授权服务器元数据发现
- 支持动态客户端注册
- 支持令牌自动刷新
- 带授权的 SSE 传输实现

## 使用方法

### 1. 启用功能

在 Cargo.toml 中启用 auth 特性：

```toml
[dependencies]
rmcp = { version = "0.1", features = ["auth", "transport-sse"] }
```

### 2. 创建授权管理器

```rust
use std::sync::Arc;
use rmcp::transport::auth::AuthorizationManager;

async fn main() -> anyhow::Result<()> {
    // 创建授权管理器
    let auth_manager = Arc::new(AuthorizationManager::new("https://api.example.com/mcp").await?);
    
    Ok(())
}
```

### 3. 创建授权会话并获取授权

```rust
use rmcp::transport::auth::AuthorizationSession;

async fn get_authorization(auth_manager: Arc<AuthorizationManager>) -> anyhow::Result<()> {
    // 创建授权会话
    let session = AuthorizationSession::new(
        auth_manager.clone(),
        &["mcp"], // 请求的作用域
        "http://localhost:8080/callback", // 重定向 URI
    ).await?;
    
    // 获取授权 URL 并引导用户打开
    let auth_url = session.get_authorization_url();
    println!("请在浏览器中打开以下 URL 进行授权：\n{}", auth_url);
    
    // 处理回调 - 在实际应用中，这通常在回调服务器中完成
    let auth_code = "用户授权后从浏览器获取的授权码";
    let credentials = session.handle_callback(auth_code).await?;
    
    println!("授权成功，访问令牌：{}", credentials.access_token);
    
    Ok(())
}
```

### 4. 使用授权的 SSE 传输

```rust
use rmcp::{ServiceExt, model::ClientInfo, transport::create_authorized_transport};

async fn connect_with_auth(auth_manager: Arc<AuthorizationManager>) -> anyhow::Result<()> {
    // 创建授权的 SSE 传输
    let transport = create_authorized_transport(
        "https://api.example.com/mcp",
        auth_manager.clone()
    ).await?;
    
    // 创建客户端
    let client_service = ClientInfo::default();
    let client = client_service.serve(transport).await?;
    
    // 使用客户端调用 API
    let tools = client.peer().list_all_tools().await?;
    
    for tool in tools {
        println!("工具: {} - {}", tool.name, tool.description);
    }
    
    Ok(())
}
```

### 5. 使用授权的 HTTP 客户端

```rust
use rmcp::transport::auth::AuthorizedHttpClient;

async fn make_authorized_request(auth_manager: Arc<AuthorizationManager>) -> anyhow::Result<()> {
    // 创建授权的 HTTP 客户端
    let client = AuthorizedHttpClient::new(auth_manager, None);
    
    // 发送带授权的请求
    let response = client.get("https://api.example.com/resources").await?;
    let resources = response.json::<Vec<Resource>>().await?;
    
    println!("资源数量: {}", resources.len());
    
    Ok(())
}
```

## 完整示例

请参考 `examples/oauth_client.rs` 了解完整的使用示例。

## 运行示例

```bash
# 设置服务器 URL (可选)
export MCP_SERVER_URL=https://api.example.com/mcp

# 运行示例
cargo run --bin oauth-client
```

## 授权流程说明

1. **元数据发现**：客户端尝试从 `/.well-known/oauth-authorization-server` 获取授权服务器元数据
2. **客户端注册**：如果支持，客户端会动态注册自己
3. **授权请求**：使用 PKCE 构建授权 URL 并引导用户访问
4. **授权码交换**：用户授权后，使用授权码交换访问令牌
5. **使用令牌**：使用访问令牌进行 API 调用
6. **令牌刷新**：当访问令牌过期时，自动使用刷新令牌获取新的访问令牌

## 安全考虑

- 所有的令牌都安全存储在内存中
- 实现了 PKCE 以防止授权码拦截攻击
- 支持令牌自动刷新，减少用户干预
- 仅接受 HTTPS 连接或安全的本地回调 URI

## 故障排除

如果遇到授权问题，请检查以下事项：

1. 确保服务器支持 OAuth 2.1 授权
2. 确保回调 URI 与服务器允许的重定向 URI 匹配
3. 检查网络连接和防火墙设置
4. 验证服务器是否支持元数据发现或动态客户端注册

## 参考资料

- [MCP 授权规范](https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/)
- [OAuth 2.1 规范草案](https://oauth.net/2.1/)
- [RFC 8414: OAuth 2.0 授权服务器元数据](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 7591: OAuth 2.0 动态客户端注册协议](https://datatracker.ietf.org/doc/html/rfc7591) 