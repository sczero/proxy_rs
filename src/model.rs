use std::collections::HashMap;

use argh::FromArgs;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};


pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

#[derive(Default, Debug, FromArgs)]
/// cmd 参数
pub struct Param {
    /// 配置文件地址
    #[argh(option)]
    pub config_file: String,
}

#[derive(Default, Debug, Deserialize)]
/// json config
pub struct ServerConfig {
    /// 绑定地址
    pub bind_addr: String,
    /// 认证账号
    pub username: Option<String>,
    /// 认证密码
    pub password: Option<String>,
    /// 是否开启https
    pub tls_enable: bool,
    /// 证书（Certificate）
    pub tls_cert: Option<String>,
    /// 私钥（Private Key）
    pub tls_key: Option<String>,
}

#[derive(Default, Debug)]
pub struct ProxyHeader {
    pub method: String,
    pub url: String,
    pub protocol: String,
    pub proxy_headers: HashMap<String, String>,
    pub normal_headers: HashMap<String, String>,
}
