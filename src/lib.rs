#![cfg_attr(feature = "clippy", feature(plugin))]

#[macro_use]
extern crate log;
#[cfg(feature = "serialize")]
#[macro_use]
extern crate serde_derive;
#[cfg(feature = "serialize")]
extern crate serde;

use std::net::IpAddr;
use std::str::FromStr;

#[macro_use]
pub mod attribute_type;
pub mod anonymizer;
pub mod error;
pub mod media_type;
pub mod network;

use anonymizer::{AnonymizingClone, StatefulSdpAnonymizer};
use attribute_type::{
    parse_attribute, SdpAttribute, SdpAttributeRid, SdpAttributeSimulcastVersion, SdpAttributeType,
    SdpSingleDirection,
};
use error::{SdpParserError, SdpParserInternalError};
use media_type::{
    parse_media, parse_media_vector, SdpFormatList, SdpMedia, SdpMediaLine, SdpMediaValue,
    SdpProtocolValue,
};
use network::{address_to_string, parse_address_type, parse_network_type, parse_unicast_address};

#[derive(Clone)]
#[cfg_attr(feature = "serialize", derive(Serialize))]
pub enum SdpBandwidth {
    As(u32),
    Ct(u32),
    Tias(u32),
    Unknown(String, u32),
}

impl ToString for SdpBandwidth {
    fn to_string(&self) -> String {
        match *self {
            SdpBandwidth::As(ref x) => format!("AS:{}", x.to_string()),
            SdpBandwidth::Ct(ref x) => format!("CT:{}", x.to_string()),
            SdpBandwidth::Tias(ref x) => format!("TIAS:{}", x.to_string()),
            SdpBandwidth::Unknown(ref tp, ref x) => format!("{}:{}", tp.to_string(), x.to_string()),
        }
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "serialize", derive(Serialize))]
pub struct SdpConnection {
    pub address: IpAddr,
    pub ttl: Option<u8>,
    pub amount: Option<u32>,
}

impl ToString for SdpConnection {
    fn to_string(&self) -> String {
        format!(
            "{address}{ttl}{amount}",
            address = address_to_string(self.address),
            ttl = option_to_string!("/{}", self.ttl),
            amount = option_to_string!("/{}", self.amount)
        )
    }
}

impl AnonymizingClone for SdpConnection {
    fn masked_clone(&self, anon: &mut StatefulSdpAnonymizer) -> Self {
        let mut masked = self.clone();
        masked.address = anon.mask_ip(&self.address);
        masked
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "serialize", derive(Serialize))]
pub struct SdpOrigin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub unicast_addr: IpAddr,
}

impl ToString for SdpOrigin {
    fn to_string(&self) -> String {
        format!(
            "{username} {sess_id} {sess_vers} {unicast_addr}",
            username = self.username.clone(),
            sess_id = self.session_id.to_string(),
            sess_vers = self.session_version.to_string(),
            unicast_addr = address_to_string(self.unicast_addr)
        )
    }
}

impl AnonymizingClone for SdpOrigin {
    fn masked_clone(&self, anon: &mut StatefulSdpAnonymizer) -> Self {
        let mut masked = self.clone();
        masked.username = anon.mask_origin_user(&self.username);
        masked.unicast_addr = anon.mask_ip(&masked.unicast_addr);
        masked
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "serialize", derive(Serialize))]
pub struct SdpTiming {
    pub start: u64,
    pub stop: u64,
}

impl ToString for SdpTiming {
    fn to_string(&self) -> String {
        format!("{} {}", self.start.to_string(), self.stop.to_string())
    }
}

#[cfg_attr(feature = "serialize", derive(Serialize))]
pub enum SdpType {
    // Note: Email, Information, Key, Phone, Repeat, Uri and Zone are left out
    //       on purposes as we don't want to support them.
    Attribute(SdpAttribute),
    Bandwidth(SdpBandwidth),
    Connection(SdpConnection),
    Media(SdpMediaLine),
    Origin(SdpOrigin),
    Session(String),
    Timing(SdpTiming),
    Version(u64),
}

#[cfg_attr(feature = "serialize", derive(Serialize))]
pub struct SdpLine {
    pub line_number: usize,
    pub sdp_type: SdpType,
}

#[derive(Clone)]
#[cfg_attr(feature = "serialize", derive(Serialize))]
pub struct SdpSession {
    pub version: u64,
    pub origin: SdpOrigin,
    pub session: String,
    pub connection: Option<SdpConnection>,
    pub bandwidth: Vec<SdpBandwidth>,
    pub timing: Option<SdpTiming>,
    pub attribute: Vec<SdpAttribute>,
    pub media: Vec<SdpMedia>,
    pub warnings: Vec<SdpParserError>, // unsupported values:
                                       // information: Option<String>,
                                       // uri: Option<String>,
                                       // email: Option<String>,
                                       // phone: Option<String>,
                                       // repeat: Option<String>,
                                       // zone: Option<String>,
                                       // key: Option<String>
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
            warnings: Vec::new(),
        }
    }

    pub fn get_version(&self) -> u64 {
        self.version
    }

    pub fn get_origin(&self) -> &SdpOrigin {
        &self.origin
    }

    pub fn get_session(&self) -> &str {
        &self.session
    }

    pub fn get_connection(&self) -> &Option<SdpConnection> {
        &self.connection
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

    pub fn add_attribute(&mut self, a: SdpAttribute) -> Result<(), SdpParserInternalError> {
        if !a.allowed_at_session_level() {
            return Err(SdpParserInternalError::Generic(format!(
                "{} not allowed at session level",
                a.to_string()
            )));
        };
        self.attribute.push(a);
        Ok(())
    }

    pub fn extend_media(&mut self, v: Vec<SdpMedia>) {
        self.media.extend(v)
    }

    pub fn parse_session_vector(&mut self, lines: &mut Vec<SdpLine>) -> Result<(), SdpParserError> {
        while !lines.is_empty() {
            let line = lines.remove(0);
            match line.sdp_type {
                SdpType::Attribute(a) => {
                    let _line_number = line.line_number;
                    self.add_attribute(a).map_err(|e: SdpParserInternalError| {
                        SdpParserError::Sequence {
                            message: format!("{}", e),
                            line_number: _line_number,
                        }
                    })?
                }
                SdpType::Bandwidth(b) => self.add_bandwidth(b),
                SdpType::Timing(t) => self.set_timing(t),
                SdpType::Connection(c) => self.set_connection(c),

                SdpType::Origin(_) | SdpType::Session(_) | SdpType::Version(_) => {
                    return Err(SdpParserError::Sequence {
                        message: "version, origin or session at wrong level".to_string(),
                        line_number: line.line_number,
                    });
                }
                SdpType::Media(_) => {
                    return Err(SdpParserError::Sequence {
                        message: "media line not allowed in session parser".to_string(),
                        line_number: line.line_number,
                    });
                }
            }
        }
        Ok(())
    }

    pub fn get_attribute(&self, t: SdpAttributeType) -> Option<&SdpAttribute> {
        self.attribute
            .iter()
            .find(|a| SdpAttributeType::from(*a) == t)
    }

    pub fn add_media(
        &mut self,
        media_type: SdpMediaValue,
        direction: SdpAttribute,
        port: u32,
        protocol: SdpProtocolValue,
        addr: String,
    ) -> Result<(), SdpParserInternalError> {
        let mut media = SdpMedia::new(SdpMediaLine {
            media: media_type,
            port,
            port_count: 1,
            proto: protocol,
            formats: SdpFormatList::Integers(Vec::new()),
        });

        media.add_attribute(direction)?;

        media.set_connection(SdpConnection {
            address: IpAddr::from_str(addr.as_str())?,
            ttl: None,
            amount: None,
        })?;

        self.media.push(media);

        Ok(())
    }
}

impl ToString for SdpSession {
    fn to_string(&self) -> String {
        format!(
            "v={version}\r\n\
             o={origin}\r\n\
             s={sess}\r\n\
             {timing}\
             {bandwidth}\
             {connection}\
             {sess_attributes}\
             {media_sections}",
            version = self.version.to_string(),
            origin = self.origin.to_string(),
            sess = self.session.clone(),
            timing = option_to_string!("t={}\r\n", self.timing),
            bandwidth = maybe_vector_to_string!("b={}\r\n", self.bandwidth, "\r\nb="),
            connection = option_to_string!("c={}\r\n", self.connection),
            sess_attributes = maybe_vector_to_string!("a={}\r\n", self.attribute, "\r\na="),
            media_sections = maybe_vector_to_string!("{}", self.media, "\r\n")
        )
    }
}

impl AnonymizingClone for SdpSession {
    fn masked_clone(&self, anon: &mut StatefulSdpAnonymizer) -> Self {
        let mut masked: SdpSession = SdpSession {
            version: self.version,
            session: self.session.clone(),
            origin: self.origin.masked_clone(anon),
            connection: self.connection.clone(),
            timing: self.timing.clone(),
            bandwidth: self.bandwidth.clone(),
            attribute: Vec::new(),
            media: Vec::new(),
            warnings: Vec::new(),
        };
        masked.origin = self.origin.masked_clone(anon);
        masked.connection = masked
            .connection
            .and_then(|con| Some(con.masked_clone(anon)));
        for i in &self.attribute {
            masked.attribute.push(i.masked_clone(anon));
        }
        masked
    }
}

fn parse_session(value: &str) -> Result<SdpType, SdpParserInternalError> {
    trace!("session: {}", value);
    Ok(SdpType::Session(String::from(value)))
}

fn parse_version(value: &str) -> Result<SdpType, SdpParserInternalError> {
    let ver = value.parse::<u64>()?;
    if ver != 0 {
        return Err(SdpParserInternalError::Generic(format!(
            "version type contains unsupported value {}",
            ver
        )));
    };
    trace!("version: {}", ver);
    Ok(SdpType::Version(ver))
}

fn parse_origin(value: &str) -> Result<SdpType, SdpParserInternalError> {
    let mut tokens = value.split_whitespace();
    let username = match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic(
                "Origin type is missing username token".to_string(),
            ));
        }
        Some(x) => x,
    };
    let session_id = match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic(
                "Origin type is missing session ID token".to_string(),
            ));
        }
        Some(x) => x.parse::<u64>()?,
    };
    let session_version = match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic(
                "Origin type is missing session version token".to_string(),
            ));
        }
        Some(x) => x.parse::<u64>()?,
    };
    match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic(
                "Origin type is missing network type token".to_string(),
            ));
        }
        Some(x) => parse_network_type(x)?,
    };
    let addrtype = match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic(
                "Origin type is missing address type token".to_string(),
            ));
        }
        Some(x) => parse_address_type(x)?,
    };
    let unicast_addr = match tokens.next() {
        None => {
            return Err(SdpParserInternalError::Generic(
                "Origin type is missing IP address token".to_string(),
            ));
        }
        Some(x) => parse_unicast_address(x)?,
    };
    if !addrtype.same_protocol(&unicast_addr) {
        return Err(SdpParserInternalError::Generic(
            "Origin addrtype does not match address.".to_string(),
        ));
    }
    let o = SdpOrigin {
        username: String::from(username),
        session_id,
        session_version,
        unicast_addr,
    };
    trace!("origin: {}", o.to_string());
    Ok(SdpType::Origin(o))
}

fn parse_connection(value: &str) -> Result<SdpType, SdpParserInternalError> {
    let cv: Vec<&str> = value.split_whitespace().collect();
    if cv.len() != 3 {
        return Err(SdpParserInternalError::Generic(
            "connection attribute must have three tokens".to_string(),
        ));
    }
    parse_network_type(cv[0])?;
    let addrtype = parse_address_type(cv[1])?;
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
    let address = parse_unicast_address(addr_token)?;
    if !addrtype.same_protocol(&address) {
        return Err(SdpParserInternalError::Generic(
            "connection addrtype does not match address.".to_string(),
        ));
    }
    let c = SdpConnection {
        address,
        ttl,
        amount,
    };
    trace!("connection: {}", c.address);
    Ok(SdpType::Connection(c))
}

fn parse_bandwidth(value: &str) -> Result<SdpType, SdpParserInternalError> {
    let bv: Vec<&str> = value.split(':').collect();
    if bv.len() != 2 {
        return Err(SdpParserInternalError::Generic(
            "bandwidth attribute must have two tokens".to_string(),
        ));
    }
    let bandwidth = bv[1].parse::<u32>()?;
    let bw = match bv[0].to_uppercase().as_ref() {
        "AS" => SdpBandwidth::As(bandwidth),
        "CT" => SdpBandwidth::Ct(bandwidth),
        "TIAS" => SdpBandwidth::Tias(bandwidth),
        _ => SdpBandwidth::Unknown(String::from(bv[0]), bandwidth),
    };
    trace!("bandwidth: {}, {}", bv[0], bandwidth);
    Ok(SdpType::Bandwidth(bw))
}

fn parse_timing(value: &str) -> Result<SdpType, SdpParserInternalError> {
    let tv: Vec<&str> = value.split_whitespace().collect();
    if tv.len() != 2 {
        return Err(SdpParserInternalError::Generic(
            "timing attribute must have two tokens".to_string(),
        ));
    }
    let start = tv[0].parse::<u64>()?;
    let stop = tv[1].parse::<u64>()?;
    let t = SdpTiming { start, stop };
    trace!("timing: {}, {}", t.start, t.stop);
    Ok(SdpType::Timing(t))
}

fn parse_sdp_line(line: &str, line_number: usize) -> Result<SdpLine, SdpParserError> {
    if line.find('=') == None {
        return Err(SdpParserError::Line {
            error: SdpParserInternalError::Generic("missing = character in line".to_string()),
            line: line.to_string(),
            line_number,
        });
    }
    let mut splitted_line = line.splitn(2, '=');
    let line_type = match splitted_line.next() {
        None => {
            return Err(SdpParserError::Line {
                error: SdpParserInternalError::Generic("missing type".to_string()),
                line: line.to_string(),
                line_number,
            });
        }
        Some(t) => {
            let trimmed = t.trim();
            if trimmed.len() > 1 {
                return Err(SdpParserError::Line {
                    error: SdpParserInternalError::Generic("type too long".to_string()),
                    line: line.to_string(),
                    line_number,
                });
            }
            if trimmed.is_empty() {
                return Err(SdpParserError::Line {
                    error: SdpParserInternalError::Generic("type is empty".to_string()),
                    line: line.to_string(),
                    line_number,
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
                line_number,
            });
        }
        Some(v) => {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                return Err(SdpParserError::Line {
                    error: SdpParserInternalError::Generic("value is empty".to_string()),
                    line: line.to_string(),
                    line_number,
                });
            }
            trimmed
        }
    };
    match line_type.to_lowercase().as_ref() {
        "a" => parse_attribute(line_value),
        "b" => parse_bandwidth(line_value),
        "c" => parse_connection(line_value),
        "e" => Err(SdpParserInternalError::Generic(format!(
            "unsupported type email: {}",
            line_value
        ))),
        "i" => Err(SdpParserInternalError::Generic(format!(
            "unsupported type information: {}",
            line_value
        ))),
        "k" => Err(SdpParserInternalError::Generic(format!(
            "unsupported insecure key exchange: {}",
            line_value
        ))),
        "m" => parse_media(line_value),
        "o" => parse_origin(line_value),
        "p" => Err(SdpParserInternalError::Generic(format!(
            "unsupported type phone: {}",
            line_value
        ))),
        "r" => Err(SdpParserInternalError::Generic(format!(
            "unsupported type repeat: {}",
            line_value
        ))),
        "s" => parse_session(line_value),
        "t" => parse_timing(line_value),
        "u" => Err(SdpParserInternalError::Generic(format!(
            "unsupported type uri: {}",
            line_value
        ))),
        "v" => parse_version(line_value),
        "z" => Err(SdpParserInternalError::Generic(format!(
            "unsupported type zone: {}",
            line_value
        ))),
        _ => Err(SdpParserInternalError::Generic(
            "unknown sdp type".to_string(),
        )),
    }
    .map(|sdp_type| SdpLine {
        line_number,
        sdp_type,
    })
    .map_err(|e| match e {
        SdpParserInternalError::Generic(..)
        | SdpParserInternalError::Integer(..)
        | SdpParserInternalError::Float(..)
        | SdpParserInternalError::Address(..) => SdpParserError::Line {
            error: e,
            line: line.to_string(),
            line_number,
        },
        SdpParserInternalError::Unsupported(..) => SdpParserError::Unsupported {
            error: e,
            line: line.to_string(),
            line_number,
        },
    })
}

fn sanity_check_sdp_session(session: &SdpSession) -> Result<(), SdpParserError> {
    let make_seq_error = |x: &str| SdpParserError::Sequence {
        message: x.to_string(),
        line_number: 0,
    };

    if session.timing.is_none() {
        return Err(make_seq_error("Missing timing type at session level"));
    }

    let mut mconnections = 0;
    for msection in &session.media {
        if msection.get_connection().is_some() {
            mconnections += 1;
        }
    }

    if session.get_connection().is_none() {
        if session.media.is_empty() {
            return Err(make_seq_error("Missing connection type at session level"));
        }
        if mconnections != session.media.len() {
            return Err(make_seq_error(
                "Without connection type at session level all media section
                 must have connection types",
            ));
        }
    }

    // Check that extmaps are not defined on session and media level
    if session.get_attribute(SdpAttributeType::Extmap).is_some() {
        for msection in &session.media {
            if msection.get_attribute(SdpAttributeType::Extmap).is_some() {
                return Err(make_seq_error(
                    "Extmap can't be define at session and media level",
                ));
            }
        }
    }

    for msection in &session.media {
        if msection.get_attribute(SdpAttributeType::Sendonly).is_some() {
            if let Some(&SdpAttribute::Simulcast(ref x)) =
                msection.get_attribute(SdpAttributeType::Simulcast)
            {
                if !x.receive.is_empty() {
                    return Err(make_seq_error(
                        "Simulcast can't define receive parameters for sendonly",
                    ));
                }
            }
        }
        if msection.get_attribute(SdpAttributeType::Recvonly).is_some() {
            if let Some(&SdpAttribute::Simulcast(ref x)) =
                msection.get_attribute(SdpAttributeType::Simulcast)
            {
                if !x.send.is_empty() {
                    return Err(make_seq_error(
                        "Simulcast can't define send parameters for recvonly",
                    ));
                }
            }
        }

        let rids: Vec<&SdpAttributeRid> = msection
            .get_attributes()
            .iter()
            .filter_map(|attr| match *attr {
                SdpAttribute::Rid(ref rid) => Some(rid),
                _ => None,
            })
            .collect();
        let recv_rids: Vec<&str> = rids
            .iter()
            .filter_map(|rid| match rid.direction {
                SdpSingleDirection::Recv => Some(rid.id.as_str()),
                _ => None,
            })
            .collect();
        let send_rids: Vec<&str> = rids
            .iter()
            .filter_map(|rid| match rid.direction {
                SdpSingleDirection::Send => Some(rid.id.as_str()),
                _ => None,
            })
            .collect();

        for rid_format in rids.iter().flat_map(|rid| &rid.formats) {
            match *msection.get_formats() {
                SdpFormatList::Integers(ref int_fmt) => {
                    if !int_fmt.contains(&(u32::from(*rid_format))) {
                        return Err(make_seq_error(
                            "Rid pts must be declared in the media section",
                        ));
                    }
                }
                SdpFormatList::Strings(ref str_fmt) => {
                    if !str_fmt.contains(&rid_format.to_string()) {
                        return Err(make_seq_error(
                            "Rid pts must be declared in the media section",
                        ));
                    }
                }
            }
        }

        if let Some(&SdpAttribute::Simulcast(ref simulcast)) =
            msection.get_attribute(SdpAttributeType::Simulcast)
        {
            let check_defined_rids =
                |simulcast_version_list: &Vec<SdpAttributeSimulcastVersion>,
                 rid_ids: &[&str]|
                 -> Result<(), SdpParserError> {
                    for simulcast_rid in simulcast_version_list.iter().flat_map(|x| &x.ids) {
                        if !rid_ids.contains(&simulcast_rid.id.as_str()) {
                            return Err(make_seq_error(
                                "Simulcast RIDs must be defined in any rid attribute",
                            ));
                        }
                    }
                    Ok(())
                };

            check_defined_rids(&simulcast.receive, &recv_rids)?;
            check_defined_rids(&simulcast.send, &send_rids)?;
        }
    }

    Ok(())
}

// TODO add unit tests
fn parse_sdp_vector(lines: &mut Vec<SdpLine>) -> Result<SdpSession, SdpParserError> {
    if lines.len() < 4 {
        return Err(SdpParserError::Sequence {
            message: "SDP neeeds at least 4 lines".to_string(),
            line_number: 0,
        });
    }

    let version = match lines.remove(0).sdp_type {
        SdpType::Version(v) => v,
        _ => {
            return Err(SdpParserError::Sequence {
                message: "first line needs to be version number".to_string(),
                line_number: 0,
            });
        }
    };
    let origin = match lines.remove(0).sdp_type {
        SdpType::Origin(v) => v,
        _ => {
            return Err(SdpParserError::Sequence {
                message: "second line needs to be origin".to_string(),
                line_number: 1,
            });
        }
    };
    let session = match lines.remove(0).sdp_type {
        SdpType::Session(v) => v,
        _ => {
            return Err(SdpParserError::Sequence {
                message: "third line needs to be session".to_string(),
                line_number: 2,
            });
        }
    };
    let mut sdp_session = SdpSession::new(version, origin, session);

    let _media_pos = lines.iter().position(|ref l| match l.sdp_type {
        SdpType::Media(_) => true,
        _ => false,
    });

    match _media_pos {
        Some(p) => {
            let mut media: Vec<_> = lines.drain(p..).collect();
            sdp_session.parse_session_vector(lines)?;
            sdp_session.extend_media(parse_media_vector(&mut media)?);
        }
        None => sdp_session.parse_session_vector(lines)?,
    };

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
    // see test_parse_sdp_minimal_sdp_successfully
    if sdp.len() < 51 {
        return Err(SdpParserError::Line {
            error: SdpParserInternalError::Generic("string too short to be valid SDP".to_string()),
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
                    // TODO is this really a good way to accomplish this?
                    SdpParserError::Line {
                        error,
                        line,
                        line_number,
                    } => errors.push(SdpParserError::Line {
                        error,
                        line,
                        line_number,
                    }),
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
                    } => errors.push(SdpParserError::Sequence {
                        message,
                        line_number,
                    }),
                }
            }
        };
    }

    if fail_on_warning && (!warnings.is_empty()) {
        return Err(warnings.remove(0));
    }

    // We just return the last of the errors here
    if let Some(e) = errors.pop() {
        return Err(e);
    };

    let mut session = parse_sdp_vector(&mut sdp_lines)?;
    session.warnings = warnings;

    for warning in &session.warnings {
        warn!("Warning: {}", &warning);
    }

    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anonymizer::ToBytesVec;
    use media_type::create_dummy_media_section;

    fn create_dummy_sdp_session() -> SdpSession {
        let origin = parse_origin("mozilla 506705521068071134 0 IN IP4 0.0.0.0");
        assert!(origin.is_ok());
        let connection = parse_connection("IN IP4 198.51.100.7");
        assert!(connection.is_ok());
        let mut sdp_session;
        if let SdpType::Origin(o) = origin.unwrap() {
            sdp_session = SdpSession::new(0, o, "-".to_string());

            if let Ok(SdpType::Connection(c)) = connection {
                sdp_session.connection = Some(c);
            } else {
                unreachable!();
            }
        } else {
            unreachable!();
        }
        sdp_session
    }

    #[test]
    fn test_session_works() {
        assert!(parse_session("topic").is_ok());
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

    #[test]
    fn test_origin_works() {
        assert!(parse_origin("mozilla 506705521068071134 0 IN IP4 0.0.0.0").is_ok());
        assert!(parse_origin("mozilla 506705521068071134 0 IN IP6 2001:db8::1").is_ok());
    }

    #[test]
    fn test_origin_missing_username() {
        assert!(parse_origin("").is_err());
    }

    #[test]
    fn test_origin_missing_session_id() {
        assert!(parse_origin("mozilla ").is_err());
    }

    #[test]
    fn test_origin_missing_session_version() {
        assert!(parse_origin("mozilla 506705521068071134 ").is_err());
    }

    #[test]
    fn test_origin_missing_nettype() {
        assert!(parse_origin("mozilla 506705521068071134 0 ").is_err());
    }

    #[test]
    fn test_origin_unsupported_nettype() {
        assert!(parse_origin("mozilla 506705521068071134 0 UNSUPPORTED IP4 0.0.0.0").is_err());
    }

    #[test]
    fn test_origin_missing_addtype() {
        assert!(parse_origin("mozilla 506705521068071134 0 IN ").is_err());
    }

    #[test]
    fn test_origin_missing_ip_addr() {
        assert!(parse_origin("mozilla 506705521068071134 0 IN IP4 ").is_err());
    }

    #[test]
    fn test_origin_unsupported_addrtpe() {
        assert!(parse_origin("mozilla 506705521068071134 0 IN IP1 0.0.0.0").is_err());
    }

    #[test]
    fn test_origin_invalid_ip_addr() {
        assert!(parse_origin("mozilla 506705521068071134 0 IN IP4 1.1.1.256").is_err());
        assert!(parse_origin("mozilla 506705521068071134 0 IN IP6 ::g").is_err());
    }

    #[test]
    fn test_origin_addr_type_mismatch() {
        assert!(parse_origin("mozilla 506705521068071134 0 IN IP4 ::1").is_err());
    }

    #[test]
    fn connection_works() {
        assert!(parse_connection("IN IP4 127.0.0.1").is_ok());
        assert!(parse_connection("IN IP4 127.0.0.1/10/10").is_ok());
        assert!(parse_connection("IN IP6 ::1").is_ok());
        assert!(parse_connection("IN IP6 ::1/1/1").is_ok());
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
    fn test_parse_sdp_line_unsupported_types() {
        assert!(parse_sdp_line("e=foobar", 0).is_err());
        assert!(parse_sdp_line("i=foobar", 0).is_err());
        assert!(parse_sdp_line("k=foobar", 0).is_err());
        assert!(parse_sdp_line("p=foobar", 0).is_err());
        assert!(parse_sdp_line("r=foobar", 0).is_err());
        assert!(parse_sdp_line("u=foobar", 0).is_err());
        assert!(parse_sdp_line("z=foobar", 0).is_err());
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

    #[test]
    fn test_sanity_check_sdp_session_timing() {
        let mut sdp_session = create_dummy_sdp_session();
        sdp_session.extend_media(vec![create_dummy_media_section()]);

        assert!(sanity_check_sdp_session(&sdp_session).is_err());

        let t = SdpTiming { start: 0, stop: 0 };
        sdp_session.set_timing(t);

        assert!(sanity_check_sdp_session(&sdp_session).is_ok());
    }

    #[test]
    fn test_sanity_check_sdp_session_media() {
        let mut sdp_session = create_dummy_sdp_session();
        let t = SdpTiming { start: 0, stop: 0 };
        sdp_session.set_timing(t);

        assert!(sanity_check_sdp_session(&sdp_session).is_ok());

        sdp_session.extend_media(vec![create_dummy_media_section()]);

        assert!(sanity_check_sdp_session(&sdp_session).is_ok());
    }

    #[test]
    fn test_sanity_check_sdp_connection() {
        let origin = parse_origin("mozilla 506705521068071134 0 IN IP4 0.0.0.0");
        assert!(origin.is_ok());
        let mut sdp_session;
        if let SdpType::Origin(o) = origin.unwrap() {
            sdp_session = SdpSession::new(0, o, "-".to_string());
        } else {
            unreachable!();
        }
        let t = SdpTiming { start: 0, stop: 0 };
        sdp_session.set_timing(t);

        assert!(sanity_check_sdp_session(&sdp_session).is_err());

        // the dummy media section doesn't contain a connection
        sdp_session.extend_media(vec![create_dummy_media_section()]);

        assert!(sanity_check_sdp_session(&sdp_session).is_err());

        let connection = parse_connection("IN IP6 ::1");
        assert!(connection.is_ok());
        if let Ok(SdpType::Connection(c)) = connection {
            sdp_session.connection = Some(c);
        } else {
            unreachable!();
        }

        assert!(sanity_check_sdp_session(&sdp_session).is_ok());

        let mut second_media = create_dummy_media_section();
        let mconnection = parse_connection("IN IP4 0.0.0.0");
        assert!(mconnection.is_ok());
        if let Ok(SdpType::Connection(c)) = mconnection {
            assert!(second_media.set_connection(c).is_ok());
        } else {
            unreachable!();
        }
        sdp_session.extend_media(vec![second_media]);
        assert!(sdp_session.media.len() == 2);

        assert!(sanity_check_sdp_session(&sdp_session).is_ok());
    }

    #[test]
    fn test_sanity_check_sdp_session_extmap() {
        let mut sdp_session = create_dummy_sdp_session();
        let t = SdpTiming { start: 0, stop: 0 };
        sdp_session.set_timing(t);
        sdp_session.extend_media(vec![create_dummy_media_section()]);

        let attribute =
            parse_attribute("extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
        assert!(attribute.is_ok());
        let extmap;
        if let SdpType::Attribute(a) = attribute.unwrap() {
            extmap = a;
        } else {
            unreachable!();
        }
        let ret = sdp_session.add_attribute(extmap);
        assert!(ret.is_ok());
        assert!(sdp_session
            .get_attribute(SdpAttributeType::Extmap)
            .is_some());

        assert!(sanity_check_sdp_session(&sdp_session).is_ok());

        let mattribute =
            parse_attribute("extmap:1/sendonly urn:ietf:params:rtp-hdrext:ssrc-audio-level");
        assert!(mattribute.is_ok());
        let mextmap;
        if let SdpType::Attribute(ma) = mattribute.unwrap() {
            mextmap = ma;
        } else {
            unreachable!();
        }
        let mut second_media = create_dummy_media_section();
        assert!(second_media.add_attribute(mextmap).is_ok());
        assert!(second_media
            .get_attribute(SdpAttributeType::Extmap)
            .is_some());

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
        sdp_session.set_timing(t);
        sdp_session.extend_media(vec![create_dummy_media_section()]);

        assert!(sanity_check_sdp_session(&sdp_session).is_ok());
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
    fn test_parse_sdp_minimal_sdp_successfully() {
        assert!(parse_sdp(
            "v=0\r\n
o=- 0 0 IN IP6 ::1\r\n
s=-\r\n
c=IN IP6 ::1\r\n
t=0 0\r\n",
            true
        )
        .is_ok());
    }

    #[test]
    fn test_parse_sdp_too_short() {
        assert!(parse_sdp(
            "v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n",
            true
        )
        .is_err());
    }

    #[test]
    fn test_parse_sdp_line_error() {
        assert!(parse_sdp(
            "v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 foobar\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n",
            true
        )
        .is_err());
    }

    #[test]
    fn test_parse_sdp_unsupported_error() {
        assert!(parse_sdp(
            "v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
m=foobar 0 UDP/TLS/RTP/SAVPF 0\r\n",
            true
        )
        .is_err());
    }

    #[test]
    fn test_parse_sdp_unsupported_warning() {
        assert!(parse_sdp(
            "v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n
c=IN IP4 198.51.100.7\r\n
t=0 0\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n
a=unsupported\r\n",
            false
        )
        .is_ok());
    }

    #[test]
    fn test_parse_sdp_sequence_error() {
        assert!(parse_sdp(
            "v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
t=0 0\r\n
s=-\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n",
            true
        )
        .is_err());
    }

    #[test]
    fn test_parse_sdp_integer_error() {
        assert!(parse_sdp(
            "v=0\r\n
o=- 0 0 IN IP4 0.0.0.0\r\n
s=-\r\n
t=0 0\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n
a=rtcp:34er21\r\n",
            true
        )
        .is_err());
    }

    #[test]
    fn test_parse_sdp_ipaddr_error() {
        assert!(parse_sdp(
            "v=0\r\n
o=- 0 0 IN IP4 0.a.b.0\r\n
s=-\r\n
t=0 0\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n",
            true
        )
        .is_err());
    }

    #[test]
    fn test_parse_sdp_invalid_session_attribute() {
        assert!(parse_sdp(
            "v=0\r\n
o=- 0 0 IN IP4 0.a.b.0\r\n
s=-\r\n
t=0 0\r\n
a=bundle-only\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n",
            true
        )
        .is_err());
    }

    #[test]
    fn test_parse_sdp_invalid_media_attribute() {
        assert!(parse_sdp(
            "v=0\r\n
o=- 0 0 IN IP4 0.a.b.0\r\n
s=-\r\n
t=0 0\r\n
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n
a=ice-lite\r\n",
            true
        )
        .is_err());
    }

    #[test]
    fn test_mask_origin() {
        let mut anon = StatefulSdpAnonymizer::new();
        if let SdpType::Origin(origin_1) =
            parse_origin("mozilla 506705521068071134 0 IN IP4 0.0.0.0").unwrap()
        {
            for _ in 0..2 {
                let masked = origin_1.masked_clone(&mut anon);
                assert_eq!(masked.username, "origin-user-00000001");
                assert_eq!(masked.unicast_addr, std::net::Ipv4Addr::from(1));
            }
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_mask_sdp() {
        let mut anon = StatefulSdpAnonymizer::new();
        let sdp = parse_sdp(
            "v=0\r\n
        o=ausername 4294967296 2 IN IP4 127.0.0.1\r\n
        s=SIP Call\r\n
        c=IN IP4 198.51.100.7/51\r\n
        a=ice-pwd:12340\r\n
        a=ice-ufrag:4a799b2e\r\n
        a=fingerprint:sha-1 CD:34:D1:62:16:95:7B:B7:EB:74:E2:39:27:97:EB:0B:23:73:AC:BC\r\n
        t=0 0\r\n
        m=video 56436 RTP/SAVPF 120\r\n
        a=candidate:77142221 1 udp 2113937151 192.168.137.1 54081 typ host\r\n
        a=remote-candidates:0 10.0.0.1 5555\r\n
        a=rtpmap:120 VP8/90000\r\n",
            true,
        )
        .unwrap();
        let mut masked = sdp.masked_clone(&mut anon);
        assert_eq!(masked.origin.username, "origin-user-00000001");
        assert_eq!(masked.origin.unicast_addr, std::net::Ipv4Addr::from(1));
        assert_eq!(
            masked.connection.unwrap().address,
            std::net::Ipv4Addr::from(2)
        );
        let mut attributes = masked.attribute;
        for m in &mut masked.media {
            for attribute in m.get_attributes() {
                attributes.push(attribute.clone());
            }
        }
        for mut attribute in attributes {
            match attribute {
                SdpAttribute::Candidate(c) => {
                    assert_eq!(c.address, std::net::Ipv4Addr::from(3));
                    assert_eq!(c.port, 1);
                }
                SdpAttribute::Fingerprint(f) => {
                    assert_eq!(f.fingerprint, 1u64.to_byte_vec());
                }
                SdpAttribute::IcePwd(p) => {
                    assert_eq!(p, "ice-password-00000001");
                }
                SdpAttribute::IceUfrag(u) => {
                    assert_eq!(u, "ice-user-00000001");
                }
                SdpAttribute::RemoteCandidate(r) => {
                    assert_eq!(r.address, std::net::Ipv4Addr::from(4));
                    assert_eq!(r.port, 2);
                }
                _ => {}
            }
        }
    }
}
