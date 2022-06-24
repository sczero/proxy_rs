use std::collections::HashMap;
use std::error::Error;

use bytes::{BufMut, Bytes, BytesMut};
use reqwest::Url;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::model::{Header, HeaderLine};

mod model;

static DEBUG: bool = true;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:10000").await?;
    loop {
        let (mut in_socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut byte_buf = BytesMut::with_capacity(1024);
            loop {
                let mut byte_tmp = [0u8; 1024];
                match in_socket.read(&mut byte_tmp).await {
                    Err(_) => return,
                    Ok(n) if n == 0 => break,
                    Ok(n) => {
                        byte_buf.put_slice(&byte_tmp[..n]);
                        let byte_buf_ref = byte_buf.as_ref();
                        //结束
                        if byte_buf_ref.len() >= 4
                            && (&byte_buf_ref[byte_buf_ref.len() - 4..] == b"\r\n\r\n")
                        {
                            break;
                        }
                    }
                };
            }
            let header = Header::from(byte_buf.as_ref());
            if DEBUG {
                println!("{:?}", header);
            }
            if !header.is_https_proxy() {
                let url = Url::parse(&header.line.url).unwrap();
                let mut out_socket = TcpStream::connect(format!(
                    "{}:{}",
                    url.domain().unwrap(),
                    url.port().unwrap_or(80)
                ))
                .await
                .unwrap();
                let (mut out_reader, mut out_writer) = out_socket.into_split();
                let (mut in_reader, mut in_writer) = in_socket.into_split();
                tokio::spawn(async move {
                    out_writer.write_all(byte_buf.as_ref()).await.unwrap();
                    tokio::io::copy(&mut in_reader, &mut out_writer)
                        .await
                        .unwrap();
                });
                tokio::spawn(async move {
                    tokio::io::copy(&mut out_reader, &mut in_writer)
                        .await
                        .unwrap();
                });
            } else {
                let mut out_socket = TcpStream::connect(header.line.url)
                    .await
                    .expect("connect out error!");
                let (mut out_reader, mut out_writer) = out_socket.into_split();
                let (mut in_reader, mut in_writer) = in_socket.into_split();
                tokio::spawn(async move {
                    tokio::io::copy(&mut in_reader, &mut out_writer)
                        .await
                        .expect("in >>> proxy >>> out error!");
                });
                tokio::spawn(async move {
                    in_writer
                        .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
                        .await
                        .expect("200 OK >>>> in_writer error!");
                    tokio::io::copy(&mut out_reader, &mut in_writer)
                        .await
                        .expect("in <<< proxy <<< out error!");
                });
            }
        });
    }
}
