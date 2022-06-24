use std::collections::HashMap;

#[derive(Debug)]
pub struct HeaderLine {
    pub method: String, // CONNECT,GET,POST....
    pub is_https: bool,
    pub url: String,     // www.baidu.com:443,http://www.baidu.com:1111/
    pub proto_v: String, //HTTP/1.1
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
                is_https: true,
                url: "".to_string(),
                proto_v: "".to_string(),
            },
            items: Default::default(),
        };
    }
}
