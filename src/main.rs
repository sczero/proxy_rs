use std::borrow::Borrow;
use std::error::Error;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

//'CONNECT www.google.com:443 HTTP/1.1'
// 'Host: www.google.com:443'
// 'User-Agent: curl/7.79.1'
// 'Proxy-Connection: Keep-Alive'
// ''
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:10000").await?;
    loop {
        let (mut socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut byte_buf = BytesMut::with_capacity(4096);
            loop {
                let mut byte_tmp = [0u8; 1024];
                match socket.read(&mut byte_tmp).await {
                    Ok(n) => {
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
            let header = String::from_utf8(byte_buf.to_vec()).unwrap();
            let rows: Vec<_> = header.split("\r\n").collect();
            let url = rows[0].split(" ")[1];
        });
    }
}
