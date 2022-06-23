use std::borrow::Borrow;
use std::error::Error;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let (in_reader, mut in_writer) = tokio::io::split(socket);
            let mut line = String::new();
            let mut in_reader_buf = BufReader::new(in_reader);
            let _ = in_reader_buf.read_line(&mut line);
            println!("{}", line);
            let split: Vec<&str> = line.split(" ").collect();
            if split[0] == "CONNECT" {
                let url = split[1];
                let (mut out_reader, mut out_writer) =
                    tokio::io::split(TcpStream::connect(url).await.unwrap());
                let msg = format!("{} 200 Connection Established\r\n\r\n", split[2]);
                println!("{}", msg);
                let _ = in_writer.write_all(msg.as_bytes()).await;
                tokio::io::copy(&mut in_reader_buf, &mut out_writer)
                    .await
                    .unwrap();
                tokio::io::copy(&mut out_reader, &mut in_writer)
                    .await
                    .unwrap();
            }
        });
    }
}
