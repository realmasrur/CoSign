//! Minimal, strict HTTP/1.1: one request per connection, bounded sizes, no chunked
//! bodies, no duplicate Content-Length (request smuggling), no query strings.

use std::io::{Read, Write};

pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

const MAX_HEADER: usize = 8 * 1024;
const MAX_BODY: usize = 1 << 20;

/// On failure returns the HTTP status to send.
pub fn read_request<R: Read>(r: &mut R) -> Result<Request, u16> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEADER {
            return Err(431);
        }
        match r.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return Err(400),
        }
    }
    let head = std::str::from_utf8(&head).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().ok_or(400u16)?.split(' ');
    let (Some(method), Some(path), Some("HTTP/1.1"), None) = (first.next(), first.next(), first.next(), first.next())
    else {
        return Err(400);
    };
    if path.contains('?') || !path.starts_with('/') {
        return Err(400);
    }
    let mut len: Option<usize> = None;
    for line in lines.filter(|l| !l.is_empty()) {
        let (k, v) = line.split_once(':').ok_or(400u16)?;
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" if len.is_none() => len = Some(v.trim().parse().map_err(|_| 400u16)?),
            "content-length" | "transfer-encoding" => return Err(400),
            _ => {}
        }
    }
    let len = len.unwrap_or(0);
    if len > MAX_BODY {
        return Err(413);
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|_| 400u16)?;
    Ok(Request { method: method.to_string(), path: path.to_string(), body })
}

pub fn write_response<W: Write>(w: &mut W, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    write!(
        w,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    )?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(s: &str) -> Result<Request, u16> {
        read_request(&mut Cursor::new(s.as_bytes().to_vec()))
    }

    #[test]
    fn parses_a_valid_request() {
        let r = parse("POST /sign HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str(), r.body.as_slice()), ("POST", "/sign", &b"{}"[..]));
        assert_eq!(parse("GET /health HTTP/1.1\r\n\r\n").unwrap().body.len(), 0);
    }

    #[test]
    fn rejects_ambiguous_oversized_and_malformed_requests() {
        let bad = |s: &str| parse(s).err();
        assert_eq!(bad("POST /a HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"), Some(400));
        assert_eq!(bad("POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), Some(400));
        assert_eq!(bad("POST /a HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n"), Some(413));
        assert_eq!(bad("POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nxx"), Some(400)); // truncated
        assert_eq!(bad("GET /a?x=1 HTTP/1.1\r\n\r\n"), Some(400));
        assert_eq!(bad("GET /a HTTP/1.0\r\n\r\n"), Some(400));
        assert_eq!(bad(&format!("GET /a HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(9000))), Some(431));
    }
}
