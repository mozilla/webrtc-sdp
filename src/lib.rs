#![cfg_attr(feature="clippy", feature(plugin))]

use std::net::IpAddr;

pub mod attribute_type;
pub mod error;
pub mod media_type;
pub mod network;
pub mod unsupported_types;

use attribute_type::{SdpAttribute, parse_attribute};
use error::SdpParserError;
use media_type::{SdpMedia, SdpMediaLine, parse_media, parse_media_vector};
use network::{SdpNetType, SdpAddrType, parse_addrtype, parse_nettype, parse_unicast_addr};
use unsupported_types::{parse_email, parse_information, parse_key, parse_phone, parse_repeat, parse_uri, parse_zone};

#[derive(Clone)]
pub enum SdpBandwidthType {
    As,
    Ct,
    Tias,
    Unknown
}

#[derive(Clone)]
pub struct SdpBandwidth {
    bwtype: SdpBandwidthType,
    unknown_type: Option<String>,
    bandwidth: u64
}

#[derive(Clone)]
pub struct SdpConnection {
    nettype: SdpNetType,
    addrtype: SdpAddrType,
    addr: IpAddr,
    ttl: Option<u32>,
    amount: Option<u32>
}

#[derive(Clone)]
pub struct SdpOrigin {
    username: String,
    session_id: u64,
    session_version: u64,
    nettype: SdpNetType,
    addrtype: SdpAddrType,
    unicast_addr: IpAddr
}

#[derive(Clone)]
pub struct SdpTiming {
    start: u64,
    stop: u64
}

pub enum SdpLine {
    Attribute {value: SdpAttribute},
    Bandwidth {value: SdpBandwidth},
    Connection {value: SdpConnection},
    Email {value: String},
    Information {value: String},
    Key {value: String},
    Media {value: SdpMediaLine},
    Phone {value: String},
    Origin {value: SdpOrigin},
    Repeat {value: String},
    Session {value: String},
    Timing {value: SdpTiming},
    Uri {value: String},
    Version {value: u64},
    Zone {value: String}
}

pub struct SdpSession {
    pub version: u64,
    pub origin: SdpOrigin,
    pub session: String,
    information: Option<String>,
    uri: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    pub connection: Option<SdpConnection>,
    pub bandwidth: Vec<SdpBandwidth>,
    pub timing: Option<SdpTiming>,
    repeat: Option<String>,
    zone: Option<String>,
    key: Option<String>,
    pub attribute: Vec<SdpAttribute>,
    pub media: Vec<SdpMedia>,
}

impl SdpSession {
    pub fn new(version: u64, origin: SdpOrigin, session: String) -> SdpSession {
        SdpSession { version: version,
                     origin: origin,
                     session: session,
                     information: None,
                     uri: None,
                     email: None,
                     phone: None,
                     connection: None,
                     bandwidth: Vec::new(),
                     timing: None,
                     repeat: None,
                     zone: None,
                     key: None,
                     attribute: Vec::new(),
                     media: Vec::new()
                   }
    }

    pub fn get_version(&self) -> u64 {
        self.version
    }

    pub fn get_origin(&self) -> &SdpOrigin {
        &self.origin
    }

    pub fn get_session(&self) -> &String {
        &self.session
    }

    pub fn set_information(&mut self, i: String) {
        self.information = Some(i)
    }

    pub fn set_uri(&mut self, u: String) {
        self.uri = Some(u)
    }

    pub fn set_email(&mut self, e: String) {
        self.email = Some(e)
    }

    pub fn set_phone(&mut self, p: String) {
        self.phone = Some(p)
    }

    pub fn set_connection(&mut self, c: SdpConnection) {
        self.connection = Some(c)
    }

    pub fn add_bandwidth(&mut self, b: SdpBandwidth) {
        self.bandwidth.push(b)
    }

    pub fn set_timing(&mut self, t: SdpTiming) {
        self.timing = Some(t)
    }

    pub fn set_repeat(&mut self, r: String) {
        self.repeat = Some(r)
    }

    pub fn set_zone(&mut self, z: String) {
        self.zone = Some(z)
    }

    pub fn set_key(&mut self, k: String) {
        self.key = Some(k)
    }

    pub fn add_attribute(&mut self, a: SdpAttribute) {
        self.attribute.push(a)
    }

    pub fn add_media(&mut self, m: SdpMedia) {
        self.media.push(m)
    }

    pub fn extend_media(&mut self, v: Vec<SdpMedia>) {
        self.media.extend(v)
    }

    pub fn has_timing(&self) -> bool {
        self.timing.is_some()
    }

    pub fn has_attributes(&self) -> bool {
        !self.attribute.is_empty()
    }

    pub fn has_media(&self) -> bool {
        !self.media.is_empty()
    }
}

fn parse_session(value: &str) -> Result<SdpLine, SdpParserError> {
    println!("session: {}", value);
    Ok(SdpLine::Session {value: String::from(value)})
}

#[test]
fn test_session_works() {
    assert!(parse_session("topic").is_ok());
}


fn parse_version(value: &str) -> Result<SdpLine, SdpParserError> {
    let ver = try!(value.parse::<u64>());
    if ver != 0 {
        return Err(SdpParserError::ParserLineError {
            message: "unsupported version in v field".to_string(),
            line: value.to_string() });
    };
    println!("version: {}", ver);
    Ok(SdpLine::Version { value: ver })
}

#[test]
fn test_version_works() {
    assert!(parse_version("0").is_ok());
}

#[test]
fn test_version_unsupported_input() {
    assert!(parse_version("1").is_err());
    assert!(parse_version("11").is_err());
    assert!(parse_version("a").is_err());
}

fn parse_origin(value: &str) -> Result<SdpLine, SdpParserError> {
    let ot: Vec<&str> = value.split_whitespace().collect();
    if ot.len() != 6 {
        return Err(SdpParserError::ParserLineError {
            message: "origin field must have six tokens".to_string(),
            line: value.to_string() });
    }
    let username = ot[0];
    let session_id = try!(ot[1].parse::<u64>());
    let session_version = try!(ot[2].parse::<u64>());
    let nettype = try!(parse_nettype(ot[3]));
    let addrtype = try!(parse_addrtype(ot[4]));
    let unicast_addr = try!(parse_unicast_addr(&addrtype, ot[5]));
    let o = SdpOrigin { username: String::from(username),
                        session_id: session_id,
                        session_version: session_version,
                        nettype: nettype,
                        addrtype: addrtype,
                        unicast_addr: unicast_addr };
    println!("origin: {}, {}, {}, {}, {}, {}",
             o.username, o.session_id, o.session_version, o.nettype,
             o.addrtype, o.unicast_addr);
    Ok(SdpLine::Origin { value: o })
}

#[test]
fn test_origin_works() {
    assert!(parse_origin("mozilla 506705521068071134 0 IN IP4 0.0.0.0").is_ok());
    assert!(parse_origin("mozilla 506705521068071134 0 IN IP6 ::1").is_ok());
}

#[test]
fn test_origin_wrong_amount_of_tokens() {
    assert!(parse_origin("a b c d e").is_err());
    assert!(parse_origin("a b c d e f g").is_err());
}

#[test]
fn test_origin_unsupported_nettype() {
    assert!(parse_origin("mozilla 506705521068071134 0 UNSUPPORTED IP4 0.0.0.0").is_err());
}

#[test]
fn test_origin_unsupported_addrtpe() {
    assert!(parse_origin("mozilla 506705521068071134 0 IN IP1 0.0.0.0").is_err());
}

#[test]
fn test_origin_broken_ip_addr() {
    assert!(parse_origin("mozilla 506705521068071134 0 IN IP4 1.1.1.256").is_err());
    assert!(parse_origin("mozilla 506705521068071134 0 IN IP6 ::g").is_err());
}

#[test]
fn test_origin_addr_type_mismatch() {
    assert!(parse_origin("mozilla 506705521068071134 0 IN IP4 ::1").is_err());
}

fn parse_connection(value: &str) -> Result<SdpLine, SdpParserError> {
    let cv: Vec<&str> = value.split_whitespace().collect();
    if cv.len() != 3 {
        return Err(SdpParserError::ParserLineError {
            message: "connection attribute must have three tokens".to_string(),
            line: value.to_string() });
    }
    let nettype = try!(parse_nettype(cv[0]));
    let addrtype = try!(parse_addrtype(cv[1]));
    let mut ttl = None;
    let mut amount = None;
    let mut addr_token = cv[2];
    if addr_token.find('/') != None {
        let addr_tokens: Vec<&str> = addr_token.split('/').collect();
        if addr_tokens.len() >= 3 {
            amount = Some(try!(addr_tokens[2].parse::<u32>()));
        }
        ttl = Some(try!(addr_tokens[1].parse::<u32>()));
        addr_token = addr_tokens[0];
    }
    let addr = try!(parse_unicast_addr(&addrtype, addr_token));
    let c = SdpConnection { nettype,
                            addrtype,
                            addr,
                            ttl,
                            amount };
    println!("connection: {}, {}, {}",
             c.nettype, c.addrtype, c.addr);
    Ok(SdpLine::Connection { value: c })
}

#[test]
fn connection_works() {
    assert!(parse_connection("IN IP4 127.0.0.1").is_ok());
    assert!(parse_connection("IN IP4 127.0.0.1/10/10").is_ok());
}

#[test]
fn connection_lots_of_whitespace() {
    assert!(parse_connection("IN   IP4   127.0.0.1").is_ok());
}

#[test]
fn connection_wrong_amount_of_tokens() {
    assert!(parse_connection("IN IP4").is_err());
    assert!(parse_connection("IN IP4 0.0.0.0 foobar").is_err());
}

#[test]
fn connection_unsupported_nettype() {
    assert!(parse_connection("UNSUPPORTED IP4 0.0.0.0").is_err());
}

#[test]
fn connection_unsupported_addrtpe() {
    assert!(parse_connection("IN IP1 0.0.0.0").is_err());
}

#[test]
fn connection_broken_ip_addr() {
    assert!(parse_connection("IN IP4 1.1.1.256").is_err());
    assert!(parse_connection("IN IP6 ::g").is_err());
}

#[test]
fn connection_addr_type_mismatch() {
    assert!(parse_connection("IN IP4 ::1").is_err());
}

fn parse_bandwidth(value: &str) -> Result<SdpLine, SdpParserError> {
    let bv: Vec<&str> = value.split(':').collect();
    if bv.len() != 2 {
        return Err(SdpParserError::ParserLineError {
            message: "bandwidth attribute must have two tokens".to_string(),
            line: value.to_string() });
    }
    let mut unknown_type = None;
    let bwtype = match bv[0].to_uppercase().as_ref() {
        "AS" => SdpBandwidthType::As,
        "CT" => SdpBandwidthType::Ct,
        "TIAS" => SdpBandwidthType::Tias,
        _ => {
            unknown_type = Some(String::from(bv[0]));
            SdpBandwidthType::Unknown
        }
    };
    let bandwidth = try!(bv[1].parse::<u64>());
    let b = SdpBandwidth { bwtype,
                           unknown_type,
                           bandwidth };
    println!("bandwidth: {}, {}",
             bv[0], b.bandwidth);
    Ok(SdpLine::Bandwidth { value: b })
}

#[test]
fn bandwidth_works() {
    assert!(parse_bandwidth("AS:1").is_ok());
    assert!(parse_bandwidth("CT:123").is_ok());
    assert!(parse_bandwidth("TIAS:12345").is_ok());
}

#[test]
fn bandwidth_wrong_amount_of_tokens() {
    assert!(parse_bandwidth("TIAS").is_err());
    assert!(parse_bandwidth("TIAS:12345:xyz").is_err());
}

#[test]
fn bandwidth_unsupported_type() {
    assert!(parse_bandwidth("UNSUPPORTED:12345").is_ok());
}

fn parse_timing(value: &str) -> Result<SdpLine, SdpParserError> {
    let tv: Vec<&str> = value.split_whitespace().collect();
    if tv.len() != 2 {
        return Err(SdpParserError::ParserLineError {
            message: "timing attribute must have two tokens".to_string(),
            line: value.to_string() });
    }
    let start_time = try!(tv[0].parse::<u64>());
    let stop_time = try!(tv[1].parse::<u64>());
    let t = SdpTiming { start: start_time,
                        stop: stop_time };
    println!("timing: {}, {}", t.start, t.stop);
    Ok(SdpLine::Timing { value: t })
}

#[test]
fn test_timing_works() {
    assert!(parse_timing("0 0").is_ok());
}

#[test]
fn test_timing_non_numeric_tokens() {
    assert!(parse_timing("a 0").is_err());
    assert!(parse_timing("0 a").is_err());
}

#[test]
fn test_timing_wrong_amount_of_tokens() {
    assert!(parse_timing("0").is_err());
    assert!(parse_timing("0 0 0").is_err());
}

fn parse_sdp_line(line: &str) -> Result<SdpLine, SdpParserError> {
    if line.find('=') == None {
        return Err(SdpParserError::ParserLineError {
            message: "missing = character in line".to_string(),
            line: line.to_string() });
    }
    let v: Vec<&str> = line.splitn(2, '=').collect();
    if v.len() < 2 {
        return Err(SdpParserError::ParserLineError {
            message: "failed to split field and attribute".to_string(),
            line: line.to_string() });
    };
    let name = v[0].trim();
    if name.is_empty() || name.len() > 1 {
        return Err(SdpParserError::ParserLineError {
            message: "field name empty or too long".to_string(),
            line: line.to_string() });
    };
    let value = v[1].trim();
    if value.is_empty() {
        return Err(SdpParserError::ParserLineError {
            message: "attribute value has zero length".to_string(),
            line: line.to_string() });
    }
    match name.to_lowercase().as_ref() {
        "a" => { parse_attribute(value) },
        "b" => { parse_bandwidth(value) },
        "c" => { parse_connection(value) },
        "e" => { parse_email(value) },
        "i" => { parse_information(value) },
        "k" => { parse_key(value) },
        "m" => { parse_media(value) },
        "o" => { parse_origin(value) },
        "p" => { parse_phone(value) },
        "r" => { parse_repeat(value) },
        "s" => { parse_session(value) },
        "t" => { parse_timing(value) },
        "u" => { parse_uri(value) },
        "v" => { parse_version(value) },
        "z" => { parse_zone(value) },
        _   => { Err(SdpParserError::ParserLineError {
                    message: "unsupported sdp field".to_string(),
                    line: line.to_string() }) }
    }
}

#[test]
fn test_parse_sdp_line_works() {
    assert!(parse_sdp_line("v=0").is_ok());
}

#[test]
fn test_parse_sdp_line_empty_line() {
    assert!(parse_sdp_line("").is_err());
}

#[test]
fn test_parse_sdp_line_without_equal() {
    assert!(parse_sdp_line("abcd").is_err());
    assert!(parse_sdp_line("ab cd").is_err());
}

#[test]
fn test_parse_sdp_line_empty_value() {
    assert!(parse_sdp_line("v=").is_err());
    assert!(parse_sdp_line("o=").is_err());
    assert!(parse_sdp_line("s=").is_err());
}

#[test]
fn test_parse_sdp_line_empty_name() {
    assert!(parse_sdp_line("=abc").is_err());
}

#[test]
fn test_parse_sdp_line_valid_a_line() {
    assert!(parse_sdp_line("a=rtpmap:8 PCMA/8000").is_ok());
}

#[test]
fn test_parse_sdp_line_invalid_a_line() {
    assert!(parse_sdp_line("a=rtpmap:8 PCMA/8000 1").is_err());
}

// TODO add unit tests
fn parse_sdp_vector(lines: &[SdpLine]) -> Result<SdpSession, SdpParserError> {
    if lines.len() < 5 {
        return Err(SdpParserError::ParserSequence {
            message: "SDP neeeds at least 5 lines".to_string(),
            line: None })
    }

    // TODO are these mataches really the only way to verify the types?
    let version: u64 = match lines[0] {
        SdpLine::Version{value: v} => v,
        _ => return Err(SdpParserError::ParserSequence {
            message: "first line needs to be version number".to_string(),
            line: None })
    };
    let origin: SdpOrigin = match lines[1] {
        SdpLine::Origin{value: ref v} => v.clone(),
        _ => return Err(SdpParserError::ParserSequence {
            message: "second line needs to be origin".to_string(),
            line: None })
    };
    let session: String = match lines[2] {
        SdpLine::Session{value: ref v} => v.clone(),
        _ => return Err(SdpParserError::ParserSequence {
            message: "third line needs to be session".to_string(),
            line: None })
    };
    let mut sdp_session = SdpSession::new(version,
                                          origin,
                                          session);
    for (i, line) in lines.iter().enumerate().skip(3) {
        match *line {
            SdpLine::Attribute{value: ref v} => {sdp_session.add_attribute(v.clone())},
            SdpLine::Bandwidth{value: ref v} => {sdp_session.add_bandwidth(v.clone())},
            SdpLine::Timing{value: ref v} => {sdp_session.set_timing(v.clone())},
            SdpLine::Media{..} => {sdp_session.extend_media(
                                        try!(parse_media_vector(&lines[i..])))
                                  },
            SdpLine::Origin{..} |
            SdpLine::Session{..} |
            SdpLine::Version{..} => return Err(SdpParserError::ParserSequence {
                                                        message: "internal parser error".to_string(),
                                                        line: Some(i)}),
            // TODO does anyone really ever need these?
            SdpLine::Connection{..} | SdpLine::Email{..} |
            SdpLine::Information{..} | SdpLine::Key{..} |
            SdpLine::Phone{..} | SdpLine::Repeat{..} |
            SdpLine::Uri{..} | SdpLine::Zone{..}         => (),
        };
        if sdp_session.has_media() {
            break;
        };
    }
    if !sdp_session.has_timing() {
        return Err(SdpParserError::ParserSequence {
            message: "Missing timing".to_string(),
            line: None},);
    }
    if !sdp_session.has_media() {
        return Err(SdpParserError::ParserSequence {
            message: "Missing media".to_string(),
            line: None},);
    }
    Ok(sdp_session)
}

pub fn parse_sdp(sdp: &str, fail_on_warning: bool) -> Result<SdpSession, SdpParserError> {
    if sdp.is_empty() {
        return Err(SdpParserError::ParserLineError{message: "empty SDP".to_string(),
                                                            line: "".to_string()});
    }
    if sdp.len() < 62 {
        return Err(SdpParserError::ParserLineError{message: "string to short to be valid SDP".to_string(),
                                                            line: sdp.to_string()});
    }
    let lines = sdp.lines();
    let mut errors: Vec<SdpParserError> = Vec::new();
    let mut warnings: Vec<SdpParserError> = Vec::new();
    let mut sdp_lines: Vec<SdpLine> = Vec::new();
    for line in lines {
        let stripped_line = line.trim();
        if stripped_line.is_empty() {
            continue;
        }
        match parse_sdp_line(stripped_line) {
            Ok(n) => { sdp_lines.push(n); },
            Err(e) => {
                match e {
                    // FIXME is this really a good way to accomplish this?
                    SdpParserError::ParserLineError { message: x, line: y } =>
                        { errors.push(SdpParserError::ParserLineError { message: x, line: y}) },
                    SdpParserError::ParserUnsupported { message: x, line: y } =>
                        {
                            println!("Warning unsupported value encountered: {}\n in line {}", x, y);
                            warnings.push(SdpParserError::ParserUnsupported { message: x, line: y});
                        },
                    SdpParserError::ParserSequence {message: x, line: y} =>
                        { errors.push(SdpParserError::ParserSequence { message: x, line: y})}
                }
            }
        };
    };
    for warning in warnings {
        if fail_on_warning {
            return Err(warning);
        } else {
            match warning {
                SdpParserError::ParserUnsupported { message: msg, line: l} =>
                    { println!("Parser unknown: {}\n  in line: {}", msg, l) },
                _ => panic!(),
            };
        };
    };
    for error in errors {
        /*
        match error {
            SdpParserError::ParserLineError { message: msg, line: l} =>
                { println!("Parser error: {}\n  in line: {}", msg, l) },
            SdpParserError::ParserSequence { message: msg, ..} =>
                { println!("Parser sequence: {}", msg)}
            _ => panic!(),
        };
        */
        return Err(error);
    };
    let session = try!(parse_sdp_vector(&sdp_lines));
    Ok(session)
}

#[test]
fn test_parse_sdp_zero_length_string_fails() {
    assert!(parse_sdp("", true).is_err());
}

#[test]
fn test_parse_sdp_to_short_string() {
    assert!(parse_sdp("fooooobarrrr", true).is_err());
}
