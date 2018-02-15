#![cfg_attr(feature="clippy", feature(plugin))]

use std::net::IpAddr;
use std::fmt;

pub mod attribute_type;
pub mod error;
pub mod media_type;
pub mod network;
pub mod unsupported_types;

use attribute_type::{SdpAttribute, parse_attribute};
use error::{SdpParserInternalError, SdpParserError};
use media_type::{SdpMedia, SdpMediaLine, parse_media, parse_media_vector};
use network::{parse_addrtype, parse_nettype, parse_unicast_addr};
use unsupported_types::{parse_email, parse_information, parse_key, parse_phone, parse_repeat,
                        parse_uri, parse_zone};

#[derive(Clone)]
pub enum SdpBandwidth {
    As(u32),
    Ct(u32),
    Tias(u32),
    Unknown(String, u32),
}

#[derive(Clone)]
pub struct SdpConnection {
    pub addr: IpAddr,
    pub ttl: Option<u8>,
    pub amount: Option<u32>,
}

#[derive(Clone)]
pub struct SdpOrigin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub unicast_addr: IpAddr,
}

impl fmt::Display for SdpOrigin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "origin: {}, {}, {}, {}",
               self.username,
               self.session_id,
               self.session_version,
               self.unicast_addr)
    }
}

#[derive(Clone)]
pub struct SdpTiming {
    pub start: u64,
    pub stop: u64,
}

pub enum SdpType {
    Attribute(SdpAttribute),
    Bandwidth(SdpBandwidth),
    Connection(SdpConnection),
    Email(String),
    Information(String),
    Key(String),
    Media(SdpMediaLine),
    Phone(String),
    Origin(SdpOrigin),
    Repeat(String),
    Session(String),
    Timing(SdpTiming),
    Uri(String),
    Version(u64),
    Zone(String),
}

pub struct SdpLine {
    pub line_number: usize,
    pub sdp_type: SdpType,
}

pub struct SdpSession {
    pub version: u64,
    pub origin: SdpOrigin,
    pub session: String,
    pub connection: Option<SdpConnection>,
    pub bandwidth: Vec<SdpBandwidth>,
    pub timing: Option<SdpTiming>,
    pub attribute: Vec<SdpAttribute>,
    pub media: Vec<SdpMedia>,
    // unsupported values:
    // information: Option<String>,
    // uri: Option<String>,
    // email: Option<String>,
    // phone: Option<String>,
    // repeat: Option<String>,
    // zone: Option<String>,
    // key: Option<String>,
}

impl SdpSession {
    pub fn new(version: u64, origin: SdpOrigin, session: String) -> SdpSession {
        SdpSession {
            version,
            origin,
            session,
            connection: None,
            bandwidth: Vec::new(),
            timing: None,
            attribute: Vec::new(),
            media: Vec::new(),
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

    pub fn get_connection(&self) -> &Option<SdpConnection> {
        &self.connection
    }

    pub fn set_connection(&mut self, c: &SdpConnection) {
        self.connection = Some(c.clone())
    }

    pub fn add_bandwidth(&mut self, b: &SdpBandwidth) {
        self.bandwidth.push(b.clone())
    }

    pub fn set_timing(&mut self, t: &SdpTiming) {
        self.timing = Some(t.clone())
    }

    pub fn add_attribute(&mut self, a: &SdpAttribute) -> Result<(), SdpParserInternalError> {
        if !a.allowed_at_session_level() {
            return Err(SdpParserInternalError::Generic(format!("{} not allowed at session level",
                                                               a)));
        };
        Ok(self.attribute.push(a.clone()))
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

    // FIXME this is a temporary hack until we re-oranize the SdpAttribute enum
    // so that we can build a generic has_attribute(X) function
    fn has_extmap_attribute(&self) -> bool {
        for attribute in &self.attribute {
            if let &SdpAttribute::Extmap(_) = attribute {
                return true;
            }
        }
        false
    }

    pub fn has_media(&self) -> bool {
        !self.media.is_empty()
    }
}

fn parse_session(value: &str) -> Result<SdpType, SdpParserInternalError> {
    println!("session: {}", value);
    Ok(SdpType::Session(String::from(value)))
}

#[test]
fn test_session_works() {
    assert!(parse_session("topic").is_ok());
}


fn parse_version(value: &str) -> Result<SdpType, SdpParserInternalError> {
    let ver = value.parse::<u64>()?;
    if ver != 0 {
        return Err(SdpParserInternalError::Generic(format!("version type contains unsupported value {}",
                                                           ver)));
    };
    println!("version: {}", ver);
    Ok(SdpType::Version(ver))
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

fn parse_origin(value: &str) -> Result<SdpType, SdpParserInternalError> {
    let mut tokens = value.split_whitespace();
    let username = match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic("Origin type is missing username token"
                                                           .to_string()))
        }
        Some(x) => x,
    };
    let session_id = match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic("Origin type is missing session ID token"
                                                           .to_string()))
        }
        Some(x) => x.parse::<u64>()?,
    };
    let session_version = match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic(
                           "Origin type is missing session version token"
                           .to_string()))
        }
        Some(x) => x.parse::<u64>()?,
    };
    match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic(
                           "Origin type is missing session version token".to_string(),
                       ))
        }
        Some(x) => parse_nettype(x)?,
    };
    let addrtype = match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic("Origin type is missing address type token"
                                                           .to_string()))
        }
        Some(x) => parse_addrtype(x)?,
    };
    let unicast_addr = match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic("Origin type is missing IP address token"
                                                           .to_string()))
        }
        Some(x) => parse_unicast_addr(x)?,
    };
    if !addrtype.same_protocol(&unicast_addr) {
        return Err(SdpParserInternalError::Generic("Origin addrtype does not match address."
                                                       .to_string()));
    }
    let o = SdpOrigin {
        username: String::from(username),
        session_id,
        session_version,
        unicast_addr,
    };
    println!("{}", o);
    Ok(SdpType::Origin(o))
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

fn parse_connection(value: &str) -> Result<SdpType, SdpParserInternalError> {
    let cv: Vec<&str> = value.split_whitespace().collect();
    if cv.len() != 3 {
        return Err(SdpParserInternalError::Generic("connection attribute must have three tokens"
                                                       .to_string()));
    }
    parse_nettype(cv[0])?;
    let addrtype = parse_addrtype(cv[1])?;
    let mut ttl = None;
    let mut amount = None;
    let mut addr_token = cv[2];
    if addr_token.find('/') != None {
        let addr_tokens: Vec<&str> = addr_token.split('/').collect();
        if addr_tokens.len() >= 3 {
            amount = Some(addr_tokens[2].parse::<u32>()?);
        }
        ttl = Some(addr_tokens[1].parse::<u8>()?);
        addr_token = addr_tokens[0];
    }
    let addr = parse_unicast_addr(addr_token)?;
    if !addrtype.same_protocol(&addr) {
        return Err(SdpParserInternalError::Generic("connection addrtype does not match address."
                                                       .to_string()));
    }
    let c = SdpConnection { addr, ttl, amount };
    println!("connection: {}", c.addr);
    Ok(SdpType::Connection(c))
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

fn parse_bandwidth(value: &str) -> Result<SdpType, SdpParserInternalError> {
    let bv: Vec<&str> = value.split(':').collect();
    if bv.len() != 2 {
        return Err(SdpParserInternalError::Generic("bandwidth attribute must have two tokens"
                                                       .to_string()));
    }
    let bandwidth = bv[1].parse::<u32>()?;
    let bw = match bv[0].to_uppercase().as_ref() {
        "AS" => SdpBandwidth::As(bandwidth),
        "CT" => SdpBandwidth::Ct(bandwidth),
        "TIAS" => SdpBandwidth::Tias(bandwidth),
        _ => SdpBandwidth::Unknown(String::from(bv[0]), bandwidth),
    };
    println!("bandwidth: {}, {}", bv[0], bandwidth);
    Ok(SdpType::Bandwidth(bw))
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

fn parse_timing(value: &str) -> Result<SdpType, SdpParserInternalError> {
    let tv: Vec<&str> = value.split_whitespace().collect();
    if tv.len() != 2 {
        return Err(SdpParserInternalError::Generic("timing attribute must have two tokens"
                                                       .to_string()));
    }
    let start = tv[0].parse::<u64>()?;
    let stop = tv[1].parse::<u64>()?;
    let t = SdpTiming { start, stop };
    println!("timing: {}, {}", t.start, t.stop);
    Ok(SdpType::Timing(t))
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

fn parse_sdp_line(line: &str, line_number: usize) -> Result<SdpLine, SdpParserError> {
    if line.find('=') == None {
        return Err(SdpParserError::Line {
                       error: SdpParserInternalError::Generic("missing = character in line"
                                                                  .to_string()),
                       line: line.to_string(),
                       line_number: line_number,
                   });
    }
    let mut splitted_line = line.splitn(2, '=');
    let line_type = match splitted_line.next() {
        None => {
            return Err(SdpParserError::Line {
                           error: SdpParserInternalError::Generic("missing type".to_string()),
                           line: line.to_string(),
                           line_number: line_number,
                       })
        }
        Some(t) => {
            let trimmed = t.trim();
            if trimmed.len() > 1 {
                return Err(SdpParserError::Line {
                               error: SdpParserInternalError::Generic("type too long".to_string()),
                               line: line.to_string(),
                               line_number: line_number,
                           });
            }
            if trimmed.is_empty() {
                return Err(SdpParserError::Line {
                               error: SdpParserInternalError::Generic("type is empty".to_string()),
                               line: line.to_string(),
                               line_number: line_number,
                           });
            }
            trimmed
        }
    };
    let line_value = match splitted_line.next() {
        None => {
            return Err(SdpParserError::Line {
                           error: SdpParserInternalError::Generic("missing value".to_string()),
                           line: line.to_string(),
                           line_number: line_number,
                       })
        }
        Some(v) => {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(SdpParserError::Line {
                               error: SdpParserInternalError::Generic("value is empty".to_string()),
                               line: line.to_string(),
                               line_number: line_number,
                           });
            }
            trimmed
        }
    };
    match line_type.to_lowercase().as_ref() {
            "a" => parse_attribute(line_value),
            "b" => parse_bandwidth(line_value),
            "c" => parse_connection(line_value),
            "e" => parse_email(line_value),
            "i" => parse_information(line_value),
            "k" => parse_key(line_value),
            "m" => parse_media(line_value),
            "o" => parse_origin(line_value),
            "p" => parse_phone(line_value),
            "r" => parse_repeat(line_value),
            "s" => parse_session(line_value),
            "t" => parse_timing(line_value),
            "u" => parse_uri(line_value),
            "v" => parse_version(line_value),
            "z" => parse_zone(line_value),
            _ => Err(SdpParserInternalError::Generic("unknown sdp type".to_string())),
        }
        .map(|sdp_type| {
                 SdpLine {
                     line_number,
                     sdp_type,
                 }
             })
        .map_err(|e| match e {
                     SdpParserInternalError::Generic(..) |
                     SdpParserInternalError::Integer(..) |
                     SdpParserInternalError::Address(..) => {
                         SdpParserError::Line {
                             error: e,
                             line: line.to_string(),
                             line_number: line_number,
                         }
                     }
                     SdpParserInternalError::Unsupported(..) => {
                         SdpParserError::Unsupported {
                             error: e,
                             line: line.to_string(),
                             line_number: line_number,
                         }
                     }
                 })
}

#[test]
fn test_parse_sdp_line_works() {
    assert!(parse_sdp_line("v=0", 0).is_ok());
    assert!(parse_sdp_line("s=somesession", 0).is_ok());
}

#[test]
fn test_parse_sdp_line_empty_line() {
    assert!(parse_sdp_line("", 0).is_err());
}

#[test]
fn test_parse_sdp_line_unknown_key() {
    assert!(parse_sdp_line("y=foobar", 0).is_err());
}

#[test]
fn test_parse_sdp_line_too_long_type() {
    assert!(parse_sdp_line("ab=foobar", 0).is_err());
}

#[test]
fn test_parse_sdp_line_without_equal() {
    assert!(parse_sdp_line("abcd", 0).is_err());
    assert!(parse_sdp_line("ab cd", 0).is_err());
}

#[test]
fn test_parse_sdp_line_empty_value() {
    assert!(parse_sdp_line("v=", 0).is_err());
    assert!(parse_sdp_line("o=", 0).is_err());
    assert!(parse_sdp_line("s=", 0).is_err());
}

#[test]
fn test_parse_sdp_line_empty_name() {
    assert!(parse_sdp_line("=abc", 0).is_err());
}

#[test]
fn test_parse_sdp_line_valid_a_line() {
    assert!(parse_sdp_line("a=rtpmap:8 PCMA/8000", 0).is_ok());
}

#[test]
fn test_parse_sdp_line_invalid_a_line() {
    assert!(parse_sdp_line("a=rtpmap:200 PCMA/8000", 0).is_err());
}

fn sanity_check_sdp_session(session: &SdpSession) -> Result<(), SdpParserError> {
    if !session.has_timing() {
        return Err(SdpParserError::Sequence {
                       message: "Missing timing type".to_string(),
                       line_number: 0,
                   });
    }

    if !session.has_media() {
        return Err(SdpParserError::Sequence {
                       message: "Missing media setion".to_string(),
                       line_number: 0,
                   });
    }

    // Check that extmaps are not defined on session and media level
    if session.has_extmap_attribute() {
        for msection in &session.media {
            if msection.has_extmap_attribute() {
                return Err(SdpParserError::Sequence {
                               message: "Extmap can't be define at session and media level"
                                   .to_string(),
                               line_number: 0,
                           });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
fn create_dummy_sdp_session() -> SdpSession {
    let origin = parse_origin("mozilla 506705521068071134 0 IN IP4 0.0.0.0");
    assert!(origin.is_ok());
    let sdp_session;
    if let SdpType::Origin(o) = origin.unwrap() {
        sdp_session = SdpSession::new(0, o, "-".to_string());
    } else {
        panic!("SdpType is not Origin");
    }
    sdp_session
}

#[cfg(test)]
use media_type::create_dummy_media_section;

#[test]
fn test_sanity_check_sdp_session_timing() {
    let mut sdp_session = create_dummy_sdp_session();
    sdp_session.extend_media(vec![create_dummy_media_section()]);

    assert!(sanity_check_sdp_session(&sdp_session).is_err());

    let t = SdpTiming { start: 0, stop: 0 };
    sdp_session.set_timing(&t);

    assert!(sanity_check_sdp_session(&sdp_session).is_ok());
}

#[test]
fn test_sanity_check_sdp_session_media() {
    let mut sdp_session = create_dummy_sdp_session();
    let t = SdpTiming { start: 0, stop: 0 };
    sdp_session.set_timing(&t);

    assert!(sanity_check_sdp_session(&sdp_session).is_err());

    sdp_session.extend_media(vec![create_dummy_media_section()]);

    assert!(sanity_check_sdp_session(&sdp_session).is_ok());
}

#[test]
fn test_sanity_check_sdp_session_extmap() {
    let mut sdp_session = create_dummy_sdp_session();
    let t = SdpTiming { start: 0, stop: 0 };
    sdp_session.set_timing(&t);
    sdp_session.extend_media(vec![create_dummy_media_section()]);

    let attribute = parse_attribute("extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",);
    assert!(attribute.is_ok());
    let extmap;
    if let SdpType::Attribute(a) = attribute.unwrap() {
        extmap = a;
    } else {
        panic!("SdpType is not Attribute");
    }
    let ret = sdp_session.add_attribute(&extmap);
    assert!(ret.is_ok());
    assert!(sdp_session.has_extmap_attribute());

    assert!(sanity_check_sdp_session(&sdp_session).is_ok());

    let mattribute = parse_attribute("extmap:1/sendonly urn:ietf:params:rtp-hdrext:ssrc-audio-level",);
    assert!(mattribute.is_ok());
    let mextmap;
    if let SdpType::Attribute(ma) = mattribute.unwrap() {
        mextmap = ma;
    } else {
        panic!("SdpType is not Attribute");
    }
    let mut second_media = create_dummy_media_section();
    assert!(second_media.add_attribute(&mextmap).is_ok());
    assert!(second_media.has_extmap_attribute());

    sdp_session.extend_media(vec![second_media]);
    assert!(sdp_session.media.len() == 2);

    assert!(sanity_check_sdp_session(&sdp_session).is_err());

    sdp_session.attribute = Vec::new();

    assert!(sanity_check_sdp_session(&sdp_session).is_ok());
}

#[test]
fn test_sanity_check_sdp_session_simulcast() {
    let mut sdp_session = create_dummy_sdp_session();
    let t = SdpTiming { start: 0, stop: 0 };
    sdp_session.set_timing(&t);
    sdp_session.extend_media(vec![create_dummy_media_section()]);

    assert!(sanity_check_sdp_session(&sdp_session).is_ok());
}

// TODO add unit tests
fn parse_sdp_vector(lines: &[SdpLine]) -> Result<SdpSession, SdpParserError> {
    if lines.len() < 5 {
        return Err(SdpParserError::Sequence {
                       message: "SDP neeeds at least 5 lines".to_string(),
                       line_number: 0,
                   });
    }

    // TODO are these mataches really the only way to verify the types?
    let version: u64 = match lines[0].sdp_type {
        SdpType::Version(v) => v,
        _ => {
            return Err(SdpParserError::Sequence {
                           message: "first line needs to be version number".to_string(),
                           line_number: lines[0].line_number,
                       })
        }
    };
    let origin: SdpOrigin = match lines[1].sdp_type {
        SdpType::Origin(ref v) => v.clone(),
        _ => {
            return Err(SdpParserError::Sequence {
                           message: "second line needs to be origin".to_string(),
                           line_number: lines[1].line_number,
                       })
        }
    };
    let session: String = match lines[2].sdp_type {
        SdpType::Session(ref v) => v.clone(),
        _ => {
            return Err(SdpParserError::Sequence {
                           message: "third line needs to be session".to_string(),
                           line_number: lines[2].line_number,
                       })
        }
    };
    let mut sdp_session = SdpSession::new(version, origin, session);
    for (index, line) in lines.iter().enumerate().skip(3) {
        match line.sdp_type {
            SdpType::Attribute(ref a) => {
                sdp_session
                    .add_attribute(a)
                    .map_err(|e: SdpParserInternalError| {
                                 SdpParserError::Sequence {
                                     message: format!("{}", e),
                                     line_number: line.line_number,
                                 }
                             })?
            }
            SdpType::Bandwidth(ref b) => sdp_session.add_bandwidth(b),
            SdpType::Timing(ref t) => sdp_session.set_timing(t),
            SdpType::Connection(ref c) => sdp_session.set_connection(c),
            SdpType::Media(_) => sdp_session.extend_media(parse_media_vector(&lines[index..])?),
            SdpType::Origin(_) |
            SdpType::Session(_) |
            SdpType::Version(_) => {
                return Err(SdpParserError::Sequence {
                               message: "version, origin or session at wrong level".to_string(),
                               line_number: line.line_number,
                           })
            }
            // the line parsers throw unsupported errors for these already
            SdpType::Email(_) |
            SdpType::Information(_) |
            SdpType::Key(_) |
            SdpType::Phone(_) |
            SdpType::Repeat(_) |
            SdpType::Uri(_) |
            SdpType::Zone(_) => (),
        };
        if sdp_session.has_media() {
            break;
        };
    }
    sanity_check_sdp_session(&sdp_session)?;
    Ok(sdp_session)
}

pub fn parse_sdp(sdp: &str, fail_on_warning: bool) -> Result<SdpSession, SdpParserError> {
    if sdp.is_empty() {
        return Err(SdpParserError::Line {
                       error: SdpParserInternalError::Generic("empty SDP".to_string()),
                       line: sdp.to_string(),
                       line_number: 0,
                   });
    }
    if sdp.len() < 62 {
        return Err(SdpParserError::Line {
                       error: SdpParserInternalError::Generic("string to short to be valid SDP"
                                                                  .to_string()),
                       line: sdp.to_string(),
                       line_number: 0,
                   });
    }
    let lines = sdp.lines();
    let mut errors: Vec<SdpParserError> = Vec::new();
    let mut warnings: Vec<SdpParserError> = Vec::new();
    let mut sdp_lines: Vec<SdpLine> = Vec::new();
    for (line_number, line) in lines.enumerate() {
        let stripped_line = line.trim();
        if stripped_line.is_empty() {
            continue;
        }
        match parse_sdp_line(stripped_line, line_number) {
            Ok(n) => {
                sdp_lines.push(n);
            }
            Err(e) => {
                match e {
                    // FIXME is this really a good way to accomplish this?
                    SdpParserError::Line {
                        error,
                        line,
                        line_number,
                    } => {
                        errors.push(SdpParserError::Line {
                                        error,
                                        line,
                                        line_number,
                                    })
                    }
                    SdpParserError::Unsupported {
                        error,
                        line,
                        line_number,
                    } => {
                        warnings.push(SdpParserError::Unsupported {
                                          error,
                                          line,
                                          line_number,
                                      });
                    }
                    SdpParserError::Sequence {
                        message,
                        line_number,
                    } => {
                        errors.push(SdpParserError::Sequence {
                                        message,
                                        line_number,
                                    })
                    }
                }
            }
        };
    }
    for warning in warnings {
        if fail_on_warning {
            return Err(warning);
        } else {
            println!("Warning: {}", warning);
        };
    }
    // We just return the last of the errors here
    if let Some(e) = errors.pop() {
        return Err(e);
    };
    let session = parse_sdp_vector(&sdp_lines)?;
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

#[test]
fn test_parse_sdp_line_error() {
    assert!(parse_sdp("v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 foobar\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n",
                      true)
                    .is_err());
}

#[test]
fn test_parse_sdp_unsupported_error() {
    assert!(parse_sdp("v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
m=foobar 0 UDP/TLS/RTP/SAVPF 0\r\n",
                      true)
                    .is_err());
}

#[test]
fn test_parse_sdp_unsupported_warning() {
    assert!(parse_sdp("v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n
a=unsupported\r\n",
                      false)
                    .is_ok());
}

#[test]
fn test_parse_sdp_sequence_error() {
    assert!(parse_sdp("v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
t=0 0\r\n
s=-\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n",
                      true)
                    .is_err());
}

#[test]
fn test_parse_sdp_integer_error() {
    assert!(parse_sdp("v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n
a=rtcp:34er21\r\n",
                      true)
                    .is_err());
}

#[test]
fn test_parse_sdp_ipaddr_error() {
    assert!(parse_sdp("v=0\r\n
o=- 0 0 IN IP4 0.a.b.0\r\n
s=-\r\n
t=0 0\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n",
                      true)
                    .is_err());
}

#[test]
fn test_parse_sdp_invalid_session_attribute() {
    assert!(parse_sdp("v=0\r\n
o=- 0 0 IN IP4 0.a.b.0\r\n
s=-\r\n
t=0 0\r\n
a=bundle-only\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n",
                      true)
                    .is_err());
}

#[test]
fn test_parse_sdp_invalid_media_attribute() {
    assert!(parse_sdp("v=0\r\n
o=- 0 0 IN IP4 0.a.b.0\r\n
s=-\r\n
t=0 0\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n
a=ice-lite\r\n",
                      true)
                    .is_err());
}
