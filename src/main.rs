use std::error::Error;
use std::fs::File;
use std::io;
use std::str::FromStr;
use std::sync::Arc;

use base64::prelude::*;
use reqwest::{Client, Method, Url};
use rustls_pemfile::{certs, rsa_private_keys};
use tokio::io::{
    AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, split,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{rustls, TlsAcceptor};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::model::Param;

mod model;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //解析env
    let Param { config_file }: Param = argh::from_env();
    let file = File::open(config_file)?;
    let content = io::read_to_string(file)?;
    let config: model::ServerConfig = serde_json::from_str(&content)?;
    let tls_acceptor: Option<TlsAcceptor> = if config.tls_enable {
        let certs = load_certs(config.tls_cert.as_ref().unwrap())?;
        let key = load_keys(config.tls_key.as_ref().unwrap())?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)))
    } else {
        None
    };

    let auth = if let Some(username) = &config.username {
        if let Some(password) = &config.password {
            Some(
                "Basic ".to_string()
                    + &BASE64_STANDARD.encode(format!("{}:{}", username, password)),
            )
        } else {
            panic!("password is required");
        }
    } else {
        None
    };

    let outbound_http_client = Client::new();
    let inbound_server_addr = &config.bind_addr;
    let inbound_server = TcpListener::bind(inbound_server_addr).await?;
    println!("listen on {}", inbound_server_addr);
    loop {
        match inbound_server.accept().await {
            Ok((inbound_socket, addr)) => {
                println!("accept ok, addr:{}", addr);
                let outbound_http_client = outbound_http_client.clone();
                let tls_acceptor = tls_acceptor.clone();
                let auth = auth.clone();
                tokio::spawn(async move {
                    match handle_inbound(inbound_socket, tls_acceptor, outbound_http_client, auth)
                        .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("handle_inbound error,{}", e);
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("listener.accept error,{}", e)
            }
        };
    }
}

fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut io::BufReader::new(File::open(path)?)).collect()
}

fn load_keys(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    rsa_private_keys(&mut io::BufReader::new(File::open(path)?))
        .next()
        .unwrap()
        .map(Into::into)
}

async fn handle_inbound(
    inbound_socket: TcpStream,
    tls_acceptor: Option<TlsAcceptor>,
    outbound_http_client: Client,
    auth: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let inbound_socket: Box<dyn model::AsyncReadWrite> = if let Some(tls_acceptor) = tls_acceptor {
        let tls_stream = tls_acceptor.accept(inbound_socket).await?;
        Box::new(tls_stream)
    } else {
        Box::new(inbound_socket)
    };
    let (inbound_reader, mut inbound_writer) = split(inbound_socket);
    let mut inbound_reader = BufReader::new(inbound_reader);
    //构造ProxyHeader
    let mut inbound_header = model::ProxyHeader::default();
    let mut line = String::new();
    let _ = inbound_reader.read_line(&mut line).await?;
    let split = line.split(" ").collect::<Vec<&str>>();
    if split.len() != 3 {
        return Err("first line split error".into());
    }
    inbound_header.method = split[0].to_string();
    inbound_header.url = split[1].to_string();
    inbound_header.protocol = split[2].replace("\r\n", "").to_string();
    loop {
        let mut line = String::new();
        let _ = inbound_reader.read_line(&mut line).await?;

        if line == "\r\n" {
            break;
        }
        if let Some(index) = line.find(":") {
            let key = line[..index].to_string();
            let value = line[index + 2..line.len() - 2].to_string();
            if key.starts_with("Proxy-") {
                inbound_header.proxy_headers.insert(key, value);
            } else {
                inbound_header.normal_headers.insert(key, value);
            }
        };
    }
    //校验身份
    if let Some(auth) = auth {
        if let Some(proxy_auth) = inbound_header.proxy_headers.get("Proxy-Authorization") {
            if proxy_auth != &auth {
                inbound_writer
                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await?;
                return Ok(());
            }
        } else {
            inbound_writer
                .write(b"HTTP/1.1 407 Proxy Authentication Required\r\n")
                .await?;
            inbound_writer
                .write(b"Proxy-Authenticate: Basic realm=\"proxy\"\r\n")
                .await?;
            inbound_writer.write(b"\r\n").await?;
            inbound_writer.flush().await?;
            return Ok(());
        }
    }

    if inbound_header.method == "CONNECT" {
        let outbound_stream = TcpStream::connect(inbound_header.url).await?;
        inbound_writer
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        let (mut outbound_reader, mut outbound_writer) = outbound_stream.into_split();
        tokio::spawn(
            async move { tokio::io::copy(&mut outbound_reader, &mut inbound_writer).await },
        );
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut inbound_reader, &mut outbound_writer).await;
        });
    } else {
        let mut request = outbound_http_client.request(
            Method::from_str(&inbound_header.method)?,
            Url::from_str(&inbound_header.url)?,
        );
        for (k, v) in inbound_header.normal_headers.iter() {
            request = request.header(k, v);
        }
        if let Some(val) = inbound_header.normal_headers.get("Content-Length") {
            let len: usize = val.parse()?;
            let mut request_body_bytes = vec![0; len];
            inbound_reader.read_exact(&mut request_body_bytes).await?;
            request = request.body(request_body_bytes);
        }

        let response = outbound_http_client.execute(request.build()?).await?;
        //输出响应头
        let line = format!(
            "{} {} {}\r\n",
            inbound_header.protocol,
            response.status().as_str(),
            response.status().canonical_reason().unwrap(),
        );
        inbound_writer.write(line.as_bytes()).await?;
        //输出headers
        for (key, value) in response.headers() {
            let line = format!("{}: {}\r\n", key.as_str(), value.to_str().unwrap());
            inbound_writer.write(line.as_bytes()).await?;
        }
        inbound_writer.write(b"\r\n").await?;
        //输出body
        let response_body = response.bytes().await?;
        inbound_writer.write(&response_body).await?;
        inbound_writer.flush().await?;
    }
    Ok(())
}