use std::str::FromStr;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;

enum SdpParserResult {
    ParsedSuccessfully,
    ParserLineError   { message: String,
                        line: String },
    ParserUnsupported { message: String,
                        line: String },
}

impl From<ParseIntError> for SdpParserResult {
    fn from(_: ParseIntError) -> SdpParserResult {
        // TODO empty line error here makes no sense
        SdpParserResult::ParserLineError { message: "failed to parse integer".to_string(),
                                           line: "".to_string() }
    }
}

struct SdpAttribute {
    name: String,
    value: String
}

struct SdpBandwidth {
    bwtype: String,
    bandwidth: u64
}

enum SdpNetType {
    Internet
}

impl fmt::Display for SdpNetType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IN")
    }
}

enum SdpAddrType {
    IP4,
    IP6
}

impl fmt::Display for SdpAddrType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            SdpAddrType::IP4 => "Ip4",
            SdpAddrType::IP6 => "Ip6"
        };
        write!(f, "{}", printable)
    }
}

struct SdpConnection {
    nettype: SdpNetType,
    addrtype: SdpAddrType,
    unicast_addr: IpAddr
}

enum SdpMediaValue {
    Audio,
    Video,
    Application
}

impl fmt::Display for SdpMediaValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            SdpMediaValue::Audio       => "Audio",
            SdpMediaValue::Video       => "Video",
            SdpMediaValue::Application => "Application"
        };
        write!(f, "{}", printable)
    }
}

enum SdpProtocolValue {
    UdpTlsRtpSavpf,
    TcpTlsRtpSavpf,
    DtlsSctp,
    UdpDtlsSctp,
    TcpDtlsSctp
}

impl fmt::Display for SdpProtocolValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            SdpProtocolValue::UdpTlsRtpSavpf => "Udp/Tls/Rtp/Savpf",
            SdpProtocolValue::TcpTlsRtpSavpf => "Tcp/Tls/Rtp/Savpf",
            SdpProtocolValue::DtlsSctp       => "Dtls/Sctp",
            SdpProtocolValue::UdpDtlsSctp    => "Udp/Dtls/Sctp",
            SdpProtocolValue::TcpDtlsSctp    => "Tcp/Dtls/Sctp"
        };
        write!(f, "{}", printable)
    }
}

enum SdpFormatList {
    Integers {list: Vec<u32>},
    Strings {list: Vec<String>}
}

impl fmt::Display for SdpFormatList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SdpFormatList::Integers { list: ref x } => write!(f, "{:?}", x),
            SdpFormatList::Strings { list: ref x } => write!(f, "{:?}", x)
        }
    }
}

struct SdpMedia {
    media: SdpMediaValue,
    port: u32,
    proto: SdpProtocolValue,
    formats: SdpFormatList
}

struct SdpOrigin {
    username: String,
    session_id: u64,
    session_version: u64,
    nettype: SdpNetType,
    addrtype: SdpAddrType,
    unicast_addr: IpAddr
}

struct SdpTiming {
    start: u64,
    stop: u64
}

enum SdpLine {
    Attribute {attribute: SdpAttribute},
    Bandwidth {bandwidth: SdpBandwidth},
    Connection {connection: SdpConnection},
    Media {media: SdpMedia},
    Origin {origin: SdpOrigin},
    SdpString {string: String},
    SdpUInt {uint: u64},
    Timing {timing: SdpTiming}
}

fn create_sdp_string(value: &str) -> SdpLine {
    return SdpLine::SdpString {string: String::from(value)}
}

fn parse_repeat(value: &str) -> Result<SdpLine, SdpParserResult> {
    // TODO implement this if it's ever needed
    println!("repeat: {}", value);
    return Result::Ok(create_sdp_string(value))
}

fn parse_zone(value: &str) -> Result<SdpLine, SdpParserResult> {
    // TODO implement this if it's ever needed
    println!("zone: {}", value);
    return Result::Ok(create_sdp_string(value))
}

fn parse_key(value: &str) -> Result<SdpLine, SdpParserResult> {
    // TODO implement this if it's ever needed
    println!("key: {}", value);
    return Result::Ok(create_sdp_string(value))
}

fn parse_information(value: &str) -> Result<SdpLine, SdpParserResult> {
    println!("information: {}", value);
    return Result::Ok(create_sdp_string(value))
}

fn parse_uri(value: &str) -> Result<SdpLine, SdpParserResult> {
    // TODO check if this is really a URI
    println!("uri: {}", value);
    return Result::Ok(create_sdp_string(value))
}

fn parse_email(value: &str) -> Result<SdpLine, SdpParserResult> {
    // TODO check if this is really an email address
    println!("email: {}", value);
    return Result::Ok(create_sdp_string(value))
}

fn parse_phone(value: &str) -> Result<SdpLine, SdpParserResult> {
    // TODO check if this is really a phone number
    println!("phone: {}", value);
    return Result::Ok(create_sdp_string(value))
}

fn parse_session(value: &str) -> Result<SdpLine, SdpParserResult> {
    println!("session: {}", value);
    return Result::Ok(create_sdp_string(value))
}

fn parse_version(value: &str) -> Result<SdpLine, SdpParserResult> {
    let ver = try!(value.parse::<u64>());
    if ver != 0 {
        return Result::Err(SdpParserResult::ParserLineError {
            message: "unsupported version in v field".to_string(),
            line: value.to_string() });
    };
    println!("version: {}", ver);
    let l = SdpLine::SdpUInt {uint: ver };
    return Result::Ok(l)
}

fn parse_nettype(value: &str) -> Result<SdpNetType, SdpParserResult> {
    if value.to_uppercase() != String::from("IN") {
        return Result::Err(SdpParserResult::ParserLineError {
            message: "nettype needs to be IN".to_string(),
            line: value.to_string() });
    };
    Result::Ok(SdpNetType::Internet)
}

fn parse_addrtype(value: &str) -> Result<SdpAddrType, SdpParserResult> {
    Result::Ok(match value.to_uppercase().as_ref() {
        "IP4" => SdpAddrType::IP4,
        "IP6" => SdpAddrType::IP6,
        _ => return Result::Err(SdpParserResult::ParserLineError {
            message: "address type needs to be IP4 or IP6".to_string(),
            line: value.to_string() })
    })
}

fn parse_unicast_addr(addrtype: &SdpAddrType, value: &str) -> Result<IpAddr, SdpParserResult> {
    Result::Ok(match addrtype {
        &SdpAddrType::IP4 => {
            IpAddr::V4(match Ipv4Addr::from_str(value) {
                Ok(n) => n,
                Err(_) => return Result::Err(SdpParserResult::ParserLineError {
                    message: "failed to parse unicast IP4 address attribute".to_string(),
                    line: value.to_string() })
            })
        },
        &SdpAddrType::IP6 => {
            IpAddr::V6(match Ipv6Addr::from_str(value) {
                Ok(n) => n,
                Err(_) => return Result::Err(SdpParserResult::ParserLineError {
                    message: "failed to parse unicast IP6 address attribute".to_string(),
                    line: value.to_string() })
            })
        }
    })
}

fn parse_origin(value: &str) -> Result<SdpLine, SdpParserResult> {
    let ot: Vec<&str> = value.split_whitespace().collect();
    if ot.len() != 6 {
        return Result::Err(SdpParserResult::ParserLineError {
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
    let l = SdpLine::Origin { origin: o };
    return Result::Ok(l)
}

fn parse_connection(value: &str) -> Result<SdpLine, SdpParserResult> {
    let cv: Vec<&str> = value.split_whitespace().collect();
    if cv.len() != 3 {
        return Result::Err(SdpParserResult::ParserLineError {
            message: "connection attribute must have three tokens".to_string(),
            line: value.to_string() });
    }
    // TODO this is exactly the same parser as the end of origin.
    //      Share it in a function?!
    let nettype = try!(parse_nettype(cv[0]));
    let addrtype = try!(parse_addrtype(cv[1]));
    let unicast_addr = try!(parse_unicast_addr(&addrtype, cv[2]));
    let c = SdpConnection { nettype: nettype,
                            addrtype: addrtype,
                            unicast_addr: unicast_addr };
    println!("connection: {}, {}, {}",
             c.nettype, c.addrtype, c.unicast_addr);
    let l = SdpLine::Connection { connection: c };
    return Result::Ok(l)
}

fn parse_bandwidth(value: &str) -> Result<SdpLine, SdpParserResult> {
    let bv: Vec<&str> = value.split(':').collect();
    if bv.len() != 2 {
        return Result::Err(SdpParserResult::ParserLineError {
            message: "bandwidth attribute must have two tokens".to_string(),
            line: value.to_string() });
    }
    let bwtype = bv[0];
    match bwtype.to_uppercase().as_ref() {
        "AS" | "TIAS" => (),
        _ => return Result::Err(SdpParserResult::ParserUnsupported {
              message: "unsupported bandwidth type value".to_string(),
              line: value.to_string() }),
    };
    let bandwidth = try!(bv[1].parse::<u64>());
    let b = SdpBandwidth { bwtype: String::from(bwtype),
                            bandwidth: bandwidth };
    println!("bandwidth: {}, {}",
             b.bwtype, b.bandwidth);
    let l = SdpLine::Bandwidth { bandwidth: b };
    return Result::Ok(l)
}

fn parse_timing(value: &str) -> Result<SdpLine, SdpParserResult> {
    let tv: Vec<&str> = value.split_whitespace().collect();
    if tv.len() != 2 {
        return Result::Err(SdpParserResult::ParserLineError {
            message: "timing attribute must have two tokens".to_string(),
            line: value.to_string() });
    }
    let start_time = try!(tv[0].parse::<u64>());
    let stop_time = try!(tv[1].parse::<u64>());
    let t = SdpTiming { start: start_time,
                        stop: stop_time };
    println!("timing: {}, {}", t.start, t.stop);
    let l = SdpLine::Timing {timing: t};
    return Result::Ok(l)
}

fn parse_media_token(value: &str) -> Result<SdpMediaValue, SdpParserResult> {
    Result::Ok(match value.to_lowercase().as_ref() {
        "audio"       => SdpMediaValue::Audio,
        "video"       => SdpMediaValue::Video,
        "application" => SdpMediaValue::Application,
        _ => return Result::Err(SdpParserResult::ParserUnsupported {
              message: "unsupported media value".to_string(),
              line: value.to_string() }),
    })
}

fn parse_protocol_token(value: &str) -> Result<SdpProtocolValue, SdpParserResult> {
    Result::Ok(match value.to_uppercase().as_ref() {
        "UDP/TLS/RTP/SAVPF" => SdpProtocolValue::UdpTlsRtpSavpf,
        "TCP/TLS/RTP/SAVPF" => SdpProtocolValue::TcpTlsRtpSavpf,
        "DTLS/SCTP"         => SdpProtocolValue::DtlsSctp,
        "UDP/DTLS/SCTP"     => SdpProtocolValue::UdpDtlsSctp,
        "TCP/DTLS/SCTP"     => SdpProtocolValue::TcpDtlsSctp,
        _ => return Result::Err(SdpParserResult::ParserUnsupported {
              message: "unsupported protocol value".to_string(),
              line: value.to_string() }),
    })
}

fn parse_media(value: &str) -> Result<SdpLine, SdpParserResult> {
    let mv: Vec<&str> = value.split_whitespace().collect();
    if mv.len() < 4 {
        return Result::Err(SdpParserResult::ParserLineError {
            message: "media attribute must have at least four tokens".to_string(),
            line: value.to_string() });
    }
    let media = try!(parse_media_token(mv[0]));
    let port = try!(mv[1].parse::<u32>());
    if port > 65535 {
        return Result::Err(SdpParserResult::ParserLineError {
            message: "media port token is too big".to_string(),
            line: value.to_string() })
    }
    let proto = try!(parse_protocol_token(mv[2]));
    let fmt_slice: &[&str] = &mv[3..];
    let fmt = match media {
        SdpMediaValue::Audio | SdpMediaValue::Video => {
            let mut fmt_vec: Vec<u32> = vec![];
            for num in fmt_slice {
                let fmt_num = try!(num.parse::<u32>());
                match fmt_num {
                    0 => (),           // PCMU
                    8 => (),           // PCMA
                    9 => (),           // G722
                    13 => (),          // Comfort Noise
                    96 ... 127 => (),  // dynamic range
                    _ => return Result::Err(SdpParserResult::ParserLineError {
                          message: "format number in media line is out of range".to_string(),
                          line: value.to_string() }),
                };
                fmt_vec.push(fmt_num);
            };
            SdpFormatList::Integers { list: fmt_vec }
        },
        SdpMediaValue::Application => {
            let mut fmt_vec: Vec<String> = vec![];
            // TODO enforce length == 1 and content 'webrtc-datachannel' only?
            for token in fmt_slice {
                fmt_vec.push(String::from(*token));
            }
            SdpFormatList::Strings { list: fmt_vec }
        }
    };
    let m = SdpMedia { media: media,
                       port: port,
                       proto: proto,
                       formats: fmt };
    println!("media: {}, {}, {}, {}",
             m.media, m.port, m.proto, m.formats);
    let l = SdpLine::Media { media: m };
    return Result::Ok(l)
}

fn parse_attribute(value: &str) -> Result<SdpLine, SdpParserResult> {
    let attribute = value;
    let colon = attribute.find(':');
    let name: &str;
    let mut value: &str = "";
    if colon == None {
        name = attribute;
    } else {
        let (aname, avalue) = attribute.split_at(colon.unwrap());
        name = aname;
        value = avalue;
    }
    match name.to_lowercase().as_ref() {
        // TODO TODO TODO
        "candidate" => (),
        "end-of-candidates" => (),
        "extmap" => (),
        "fingerprint" => (),
        "fmtp" => (),
        "group" => (),
        "ice-options" => (),
        "ice-pwd" => (),
        "ice-ufrag" => (),
        "inactive" => (),
        "mid" => (),
        "msid" => (),
        "msid-semantic" => (),
        "rid" => (),
        "recvonly" => (),
        "rtcp" => (),
        "rtcp-fb" => (),
        "rtcp-mux" => (),
        "rtcp-rsize" => (),
        "rtpmap" => (),
        "sctpmap" => (),
        "sctp-port" => (),
        "sendonly" => (),
        "sendrecv" => (),
        "setup" => (),
        "ssrc" => (),
        "ssrc-group" => (),
        _ => return Result::Err(SdpParserResult::ParserUnsupported {
              message: "unsupported attribute value".to_string(),
              line: name.to_string() }),
    }
    let a = SdpAttribute { name: String::from(name),
                           value: String::from(value) };
    println!("attribute: {}, {}", 
             a.name, a.value);
    let l = SdpLine::Attribute { attribute: a };
    return Result::Ok(l)
}

fn parse_sdp_line(line: &str) -> SdpParserResult {
    let v: Vec<&str> = line.splitn(2, '=').collect();
    if v.len() < 2 {
        return SdpParserResult::ParserLineError {
            message: "failed to split field and attribute".to_string(),
            line: line.to_string() };
    };
    let name = v[0].trim();
    if name.is_empty() || name.len() > 1 {
        return SdpParserResult::ParserLineError {
            message: "field name empty or too long".to_string(),
            line: line.to_string() };
    };
    let value = v[1].trim();
    if value.len() == 0 {
        return SdpParserResult::ParserLineError {
            message: "attribute value has zero length".to_string(),
            line: line.to_string() };
    }
    // TODO once this function returns a Result<> this should simply be covered
    // with a try!()
    let line = match name.to_lowercase().as_ref() {
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
        _   => { return SdpParserResult::ParserLineError {
                    message: "unsupported sdp field".to_string(),
                    line: line.to_string() } }
    };
    // TODO there must be a way to error right from the previous match
    match line {
        Ok(n) => { println!("parsed successfully") },
        Err(e) => { return e }
    }
    return SdpParserResult::ParsedSuccessfully
}

pub fn parse_sdp(sdp: &str, fail_on_warning: bool) -> bool {
    if sdp.is_empty() {
        return false;
    }
    let lines = sdp.lines();
    let mut v: Vec<SdpParserResult> = Vec::new();
    for line in lines {
        let result = parse_sdp_line(line);
        match result {
            SdpParserResult::ParsedSuccessfully => (),
            // FIXME is this really a good way to accomplish this?
            SdpParserResult::ParserLineError { message: x, line: y } =>
                { v.push(SdpParserResult::ParserLineError { message: x, line: y}) }
            SdpParserResult::ParserUnsupported { message: x, line: y } =>
                {
                    if fail_on_warning {
                        v.push(SdpParserResult::ParserUnsupported { message: x, line: y});
                    } else {
                        println!("Warning unsupported value encountered: {}\n in line {}", x, y);
                    }
                }
        };
    };
    if v.len() > 0 {
        while let Some(x) = v.pop() {
            match x {
                SdpParserResult::ParsedSuccessfully => {}, // TODO should we fail here?
                SdpParserResult::ParserLineError { message: msg, line: l} =>
                    { println!("Parser error: {}\n  in line: {}", msg, l) }
                SdpParserResult::ParserUnsupported { message: msg, line: l} =>
                    { println!("Parser unknown: {}\n  in line: {}", msg, l) }
            }
        }
        return false;
    };
    true
}
