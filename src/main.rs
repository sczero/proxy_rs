use std::collections::HashMap;
use std::error::Error;

use bytes::{BufMut, Bytes, BytesMut};
use reqwest::Url;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::model::{Header, HeaderLine};

mod model;

//'CONNECT www.google.com:443 HTTP/1.1'
// 'Host: www.google.com:443'
// 'User-Agent: curl/7.79.1'
// 'Proxy-Connection: Keep-Alive'
// ''
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:10000").await?;
    loop {
        let (mut in_socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut byte_buf = BytesMut::with_capacity(4096);
            loop {
                let mut byte_tmp = [0u8; 1024];
                match in_socket.read(&mut byte_tmp).await {
                    Ok(n) => {
                        if n == 0 {
                            break;
                        }
                        byte_buf.put_slice(&byte_tmp[..n]);
                        let byte_buf_ref = byte_buf.as_ref();
                        //结束
                        if &byte_buf_ref[byte_buf_ref.len() - 4..] == b"\r\n\r\n" {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("读取数据出错:{}", e);
                        return;
                    }
                };
            }
            //解析头部
            let header_content = String::from_utf8(byte_buf.to_vec()).unwrap();
            let mut rows: Vec<_> = header_content
                .split("\r\n")
                .filter(|it| !it.is_empty())
                .collect();
            let mut header: Header = Header::new();
            for (idx, row) in rows.into_iter().enumerate() {
                if idx == 0 {
                    let header_line: Vec<_> = row.split(" ").collect();
                    header.line = HeaderLine {
                        method: header_line[0].to_owned(),
                        is_https: false,
                        url: header_line[1].to_owned(),
                        proto_v: header_line[2].to_owned(),
                    };
                    header.line.is_https = header.line.method == "CONNECT";
                } else {
                    let x: Vec<_> = row.split(": ").collect();
                    header.items.insert(x[0].to_owned(), x[1].to_owned());
                }
            }
            println!("{:?}", header);
            if !header.line.is_https {
                let url = Url::parse(&*header.line.url).unwrap();
                let mut out_socket = tokio::net::TcpStream::connect(format!(
                    "{}:{}",
                    url.domain().unwrap(),
                    url.port().unwrap_or(80)
                ))
                .await
                .unwrap();
                let (mut out_reader, mut out_writer) = out_socket.into_split();
                let (mut in_reader, mut in_writer) = in_socket.into_split();
                out_writer.write_all(header_content.as_ref()).await.unwrap();
                tokio::spawn(async move {
                    tokio::io::copy(&mut in_reader, &mut out_writer)
                        .await
                        .unwrap();
                });
                tokio::spawn(async move {
                    tokio::io::copy(&mut out_reader, &mut in_writer)
                        .await
                        .unwrap();
                });
            }
        });
    }
}
