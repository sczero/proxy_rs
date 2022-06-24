use std::collections::HashMap;

use bytes::BytesMut;

#[derive(Debug)]
pub struct HeaderLine {
    pub method: String, // CONNECT,GET,POST....
    pub url: String,    // www.baidu.com:443,http://www.baidu.com:1111/
    pub proto: String,  //HTTP/1.1
}

#[derive(Debug)]
pub struct Header {
    pub line: HeaderLine,
    pub items: HashMap<String, String>,
}

impl Header {
    pub fn new() -> Header {
        return Header {
            line: HeaderLine {
                method: "".to_string(),
                url: "".to_string(),
                proto: "".to_string(),
            },
            items: Default::default(),
        };
    }

    pub fn from(header_bytes: &[u8]) -> Header {
        let header_content: String = String::from_utf8(header_bytes.to_vec()).unwrap();
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
                    url: header_line[1].to_owned(),
                    proto: header_line[2].to_owned(),
                };
            } else {
                let x: Vec<_> = row.split(": ").collect();
                header.items.insert(x[0].to_owned(), x[1].to_owned());
            }
        }
        return header;
    }

    pub fn is_https_proxy(&self) -> bool {
        return self.line.method == "CONNECT";
    }
}
