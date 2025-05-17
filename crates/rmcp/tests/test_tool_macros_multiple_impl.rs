//cargo test --test test_tool_macros_multiple_impl --features "client server" -- --nocapture

use rmcp::{
    ServerHandler, Peer, RoleServer, ServiceExt,
    handler::server::tool::ToolCallContext,
    model::{CallToolRequestParam, CallToolResult, ClientInfo, ServerCapabilities, ServerInfo},
    tool,
};
use std::{borrow::Cow, sync::Arc};
use rmcp_macros::tool_extend;

// 定义测试结构体
#[derive(Debug, Clone, Default)]
pub struct TestService;

// 第一个impl块，定义第一个工具
#[tool(tool_box)]
impl TestService {
    /// 加法工具
    #[tool(description = "Add two numbers")]
    fn add(&self, #[tool(param)] a: i32, #[tool(param)] b: i32) -> String {
        format!("{} + {} = {}", a, b, a + b)
    }
}

// 第二个impl块，定义第二个工具
#[tool_extend(tool_box = tool_box)]
impl TestService {
    #[tool(description = "Subtract two numbers")]
    fn subtract(&self, #[tool(param)] a: i32, #[tool(param)] b: i32) -> String {
        format!("{} - {} = {}", a, b, a - b)
    }
}

// 实现ServerHandler特性
#[tool(tool_box)]
impl ServerHandler for TestService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("A test service with multiple impl blocks".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::test]
async fn test_multiple_tool_box_impls() {
    let service = TestService::default();
    
}