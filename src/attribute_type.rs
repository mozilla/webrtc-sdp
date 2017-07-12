use std::net::IpAddr;
use std::str::FromStr;

use SdpLine;
use error::SdpParserError;
use network::{parse_nettype, parse_addrtype, parse_unicast_addr};

#[derive(Clone)]
pub enum SdpAttributeCandidateTransport {
    Udp,
    Tcp,
}

#[derive(Clone)]
pub enum SdpAttributeCandidateType {
    Host,
    Srflx,
    Prflx,
    Relay,
}

#[derive(Clone)]
pub enum SdpAttributeCandidateTcpType {
    Active,
    Passive,
    Simultaneous,
}

#[derive(Clone)]
pub struct SdpAttributeCandidate {
    pub foundation: String,
    pub component: u32,
    pub transport: SdpAttributeCandidateTransport,
    pub priority: u64,
    pub address: IpAddr,
    pub port: u32,
    pub c_type: SdpAttributeCandidateType,
    pub raddr: Option<IpAddr>,
    pub rport: Option<u32>,
    pub tcp_type: Option<SdpAttributeCandidateTcpType>,
    pub generation: Option<u32>,
    pub ufrag: Option<String>,
    pub networkcost: Option<u32>,
}

impl SdpAttributeCandidate {
    pub fn new(foundation: String,
               component: u32,
               transport: SdpAttributeCandidateTransport,
               priority: u64,
               address: IpAddr,
               port: u32,
               c_type: SdpAttributeCandidateType)
               -> SdpAttributeCandidate {
        SdpAttributeCandidate {
            foundation,
            component,
            transport,
            priority,
            address,
            port,
            c_type,
            raddr: None,
            rport: None,
            tcp_type: None,
            generation: None,
            ufrag: None,
            networkcost: None,
        }
    }

    fn set_remote_address(&mut self, ip: IpAddr) {
        self.raddr = Some(ip)
    }

    fn set_remote_port(&mut self, p: u32) {
        self.rport = Some(p)
    }

    fn set_tcp_type(&mut self, t: SdpAttributeCandidateTcpType) {
        self.tcp_type = Some(t)
    }

    fn set_generation(&mut self, g: u32) {
        self.generation = Some(g)
    }

    fn set_ufrag(&mut self, u: String) {
        self.ufrag = Some(u)
    }

    fn set_network_cost(&mut self, n: u32) {
        self.networkcost = Some(n)
    }
}

#[derive(Clone)]
pub struct SdpAttributeRemoteCandidate {
    pub component: u32,
    pub address: IpAddr,
    pub port: u32,
}

#[derive(Clone)]
pub struct SdpAttributeSimulcastId {
    pub id: String,
    pub paused: bool,
}

impl SdpAttributeSimulcastId {
    pub fn new(idstr: String) -> SdpAttributeSimulcastId {
        if idstr.starts_with('~') {
            SdpAttributeSimulcastId {
                id: idstr[1..].to_string(),
                paused: true,
            }
        } else {
            SdpAttributeSimulcastId {
                id: idstr,
                paused: false,
            }
        }
    }
}

#[derive(Clone)]
pub struct SdpAttributeSimulcastAlternatives {
    pub ids: Vec<SdpAttributeSimulcastId>,
}

impl SdpAttributeSimulcastAlternatives {
    pub fn new(idlist: String) -> SdpAttributeSimulcastAlternatives {
        SdpAttributeSimulcastAlternatives {
            ids: idlist
                .split(',')
                .map(|x| x.to_string())
                .map(SdpAttributeSimulcastId::new)
                .collect(),
        }
    }
}

#[derive(Clone)]
pub struct SdpAttributeSimulcast {
    pub send: Vec<SdpAttributeSimulcastAlternatives>,
    pub receive: Vec<SdpAttributeSimulcastAlternatives>,
}

impl SdpAttributeSimulcast {
    fn parse_ids(&mut self, direction: SdpAttributeDirection, idlist: String) {
        let list = idlist
            .split(';')
            .map(|x| x.to_string())
            .map(SdpAttributeSimulcastAlternatives::new)
            .collect();
        // TODO prevent over-writing existing values
        match direction {
            SdpAttributeDirection::Recvonly => self.receive = list,
            SdpAttributeDirection::Sendonly => self.send = list,
            _ => (),
        }
    }
}

#[derive(Clone)]
pub struct SdpAttributeRtcp {
    pub port: u32,
    pub unicast_addr: Option<IpAddr>,
}

impl SdpAttributeRtcp {
    pub fn new(port: u32) -> SdpAttributeRtcp {
        SdpAttributeRtcp {
            port,
            unicast_addr: None,
        }
    }

    fn set_addr(&mut self, addr: IpAddr) {
        self.unicast_addr = Some(addr)
    }
}

#[derive(Clone)]
pub struct SdpAttributeRtcpFb {
    pub payload_type: u32,
    // TODO parse this and use an enum instead?
    pub feedback_type: String,
}

#[derive(Clone)]
pub enum SdpAttributeDirection {
    Recvonly,
    Sendonly,
    Sendrecv,
}

#[derive(Clone)]
pub struct SdpAttributeExtmap {
    pub id: u32,
    pub direction: Option<SdpAttributeDirection>,
    pub url: String,
}

#[derive(Clone)]
pub struct SdpAttributeFmtp {
    pub payload_type: u32,
    pub tokens: Vec<String>,
}

#[derive(Clone)]
pub struct SdpAttributeFingerprint {
    // TODO turn the supported hash algorithms into an enum?
    pub hash_algorithm: String,
    pub fingerprint: String,
}

#[derive(Clone)]
pub struct SdpAttributeSctpmap {
    pub port: u32,
    pub channels: u32,
}

#[derive(Clone)]
pub enum SdpAttributeGroupSemantic {
    LipSynchronization,
    FlowIdentification,
    SingleReservationFlow,
    AlternateNetworkAddressType,
    ForwardErrorCorrection,
    DecodingDependency,
    Bundle,
}

#[derive(Clone)]
pub struct SdpAttributeGroup {
    pub semantics: SdpAttributeGroupSemantic,
    pub tags: Vec<String>,
}

#[derive(Clone)]
pub struct SdpAttributeMsid {
    pub id: String,
    pub appdata: Option<String>,
}

#[derive(Clone)]
pub struct SdpAttributeRtpmap {
    pub payload_type: u32,
    pub codec_name: String,
    pub frequency: Option<u32>,
    pub channels: Option<u32>,
}

impl SdpAttributeRtpmap {
    pub fn new(payload_type: u32, codec_name: String) -> SdpAttributeRtpmap {
        SdpAttributeRtpmap {
            payload_type,
            codec_name,
            frequency: None,
            channels: None,
        }
    }

    fn set_frequency(&mut self, f: u32) {
        self.frequency = Some(f)
    }

    fn set_channels(&mut self, c: u32) {
        self.channels = Some(c)
    }
}

#[derive(Clone)]
pub enum SdpAttributeSetup {
    Active,
    Actpass,
    Holdconn,
    Passive,
}

#[derive(Clone)]
pub struct SdpAttributeSsrc {
    pub id: u32,
    pub attribute: Option<String>,
    pub value: Option<String>,
}

impl SdpAttributeSsrc {
    pub fn new(id: u32) -> SdpAttributeSsrc {
        SdpAttributeSsrc {
            id,
            attribute: None,
            value: None,
        }
    }

    fn set_attribute(&mut self, a: &str) {
        if a.find(':') == None {
            self.attribute = Some(a.to_string());
        } else {
            let v: Vec<&str> = a.splitn(2, ':').collect();
            self.attribute = Some(v[0].to_string());
            self.value = Some(v[1].to_string());
        }
    }
}

#[derive(Clone)]
pub enum SdpAttribute {
    BundleOnly,
    Candidate(SdpAttributeCandidate),
    EndOfCandidates,
    Extmap(SdpAttributeExtmap),
    Fingerprint(SdpAttributeFingerprint),
    Fmtp(SdpAttributeFmtp),
    Group(SdpAttributeGroup),
    IceLite,
    IceMismatch,
    IceOptions(Vec<String>),
    IcePwd(String),
    IceUfrag(String),
    Identity(String),
    ImageAttr(String),
    Inactive,
    Label(String),
    MaxMessageSize(u64),
    MaxPtime(u64),
    Mid(String),
    Msid(SdpAttributeMsid),
    MsidSemantic(String),
    Ptime(u64),
    Rid(String),
    Recvonly,
    RemoteCandidate(SdpAttributeRemoteCandidate),
    Rtpmap(SdpAttributeRtpmap),
    Rtcp(SdpAttributeRtcp),
    Rtcpfb(SdpAttributeRtcpFb),
    RtcpMux,
    RtcpRsize,
    Sctpmap(SdpAttributeSctpmap),
    SctpPort(u64),
    Sendonly,
    Sendrecv,
    Setup(SdpAttributeSetup),
    Simulcast(SdpAttributeSimulcast),
    Ssrc(SdpAttributeSsrc),
    SsrcGroup(String),
}

impl FromStr for SdpAttribute {
    type Err = SdpParserError;

    fn from_str(line: &str) -> Result<SdpAttribute, SdpParserError> {
        let tokens: Vec<_> = line.splitn(2, ':').collect();
        let name = tokens[0].to_lowercase();
        let val = match tokens.get(1) {
            Some(x) => x.trim(),
            None => ""
        };
        if tokens.len() > 1 {
            match name.as_str() {
                "bundle-only" | "end-of-candidates" | "ice-lite"
                    | "ice-mismatch" |  "inactive" |  "recvonly"
                    | "rtcp-mux" | "rtcp-rsize" | "sendonly"
                    | "sendrecv" => {
                        return Err(SdpParserError::Line{
                            message: "This attribute is not allowed to have a value".to_string(),
                            line: line.to_string()});
                    },
                _ => ()
            }
        }
        match name.as_str() {
            "bundle-only" => Ok(SdpAttribute::BundleOnly),
            "end-of-candidates" => Ok(SdpAttribute::EndOfCandidates),
            "ice-lite" => Ok(SdpAttribute::IceLite),
            "ice-mismatch" => Ok(SdpAttribute::IceMismatch),
            "ice-pwd" => Ok(SdpAttribute::IcePwd(string_or_empty(val, line)?)),
            "ice-ufrag" => Ok(SdpAttribute::IceUfrag(string_or_empty(val, line)?)),
            "identity" => Ok(SdpAttribute::Identity(string_or_empty(val, line)?)),
            "imageattr" => Ok(SdpAttribute::ImageAttr(string_or_empty(val, line)?)),
            "inactive" => Ok(SdpAttribute::Inactive),
            "label" => Ok(SdpAttribute::Label(string_or_empty(val, line)?)),
            "max-message-size" => Ok(SdpAttribute::MaxMessageSize(val.parse()?)),
            "maxptime" => Ok(SdpAttribute::MaxPtime(val.parse()?)),
            "mid" => Ok(SdpAttribute::Mid(string_or_empty(val, line)?)),
            "msid-semantic" => Ok(SdpAttribute::MsidSemantic(string_or_empty(val, line)?)),
            "rid" => Ok(SdpAttribute::Rid(string_or_empty(val, line)?)),
            "recvonly" => Ok(SdpAttribute::Recvonly),
            "rtcp-mux" => Ok(SdpAttribute::RtcpMux),
            "rtcp-rsize" => Ok(SdpAttribute::RtcpRsize),
            "sendonly" => Ok(SdpAttribute::Sendonly),
            "sendrecv" => Ok(SdpAttribute::Sendrecv),
            "ssrc-group" => Ok(SdpAttribute::SsrcGroup(string_or_empty(val, line)?)),
            "ptime" => Ok(SdpAttribute::Ptime(val.parse()?)),
            "sctp-port" => parse_sctp_port(val, line),
            "candidate" =>  parse_candidate(val, line),
            "extmap" => parse_extmap(val, line),
            "fingerprint" => parse_fingerprint(val, line),
            "fmtp" => parse_fmtp(val, line),
            "group" => parse_group(val, line),
            "ice-options" => parse_ice_options(val, line),
            "msid" => parse_msid(val, line),
            "remote-candidates" => parse_remote_candidates(val, line),
            "rtpmap" => parse_rtpmap(val, line),
            "rtcp" => parse_rtcp(val, line),
            "rtcp-fb" => parse_rtcp_fb(val, line),
            "sctpmap" => parse_sctpmap(val, line),
            "setup" => parse_setup(val, line),
            "simulcast" => parse_simulcast(val, line),
            "ssrc" => parse_ssrc(val, line),
            _ => Err(SdpParserError::Unsupported {
                message: "Unknown attribute type".to_string(),
                line: line.to_string(),
            }),
        }
    }
}

fn string_or_empty(to_parse: &str,
                   line: &str) -> Result<String, SdpParserError>  {
    if to_parse.is_empty() {
        Err(SdpParserError::Line{
            message: "This attribute is required to have a value".to_string(),
            line: line.to_string()})
    } else {
        Ok(to_parse.to_string())
    }
}

fn parse_sctp_port(to_parse: &str,
                   line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let port = to_parse.parse()?;
    if port > 65535 {
        return Err(SdpParserError::Line{
            message: "Sctpport port can only be a bit 16bit number".to_string(),
            line: line.to_string()})
    }
    Ok(SdpAttribute::SctpPort(port))
}

fn parse_candidate(to_parse: &str,
                   line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let tokens: Vec<&str> = to_parse.split_whitespace().collect();
    if tokens.len() < 8 {
        return Err(SdpParserError::Line{
            message: "Candidate needs to have minimum eigth tokens".to_string(),
            line: line.to_string()})
    }
    let component = tokens[1].parse::<u32>()?;
    let transport = match tokens[2].to_lowercase().as_ref() {
        "udp" => SdpAttributeCandidateTransport::Udp,
        "tcp" => SdpAttributeCandidateTransport::Tcp,
        _ => return Err(SdpParserError::Line{
            message: "Unknonw candidate transport value".to_string(),
            line: line.to_string()})
    };
    let priority = tokens[3].parse::<u64>()?;
    let address = parse_unicast_addr(tokens[4])?;
    let port = tokens[5].parse::<u32>()?;
    if port > 65535 {
        return Err(SdpParserError::Line{
            message: "ICE candidate port can only be a bit 16bit number".to_string(),
            line: line.to_string()})
    }
    match tokens[6].to_lowercase().as_ref() {
        "typ" => (),
        _ => return Err(SdpParserError::Line{
            message: "Candidate attribute token must be 'typ'".to_string(),
            line: line.to_string()})
    };
    let cand_type = match tokens[7].to_lowercase().as_ref() {
        "host" => SdpAttributeCandidateType::Host,
        "srflx" => SdpAttributeCandidateType::Srflx,
        "prflx" => SdpAttributeCandidateType::Prflx,
        "relay" => SdpAttributeCandidateType::Relay,
        _ => return Err(SdpParserError::Line{
            message: "Unknow candidate type value".to_string(),
            line: line.to_string()})
    };
    let mut cand = SdpAttributeCandidate::new(tokens[0].to_string(),
                                              component,
                                              transport,
                                              priority,
                                              address,
                                              port,
                                              cand_type);
    if tokens.len() > 8 {
        let mut index = 8;
        while tokens.len() > index + 1 {
            match tokens[index].to_lowercase().as_ref() {
                "generation" => {
                    let generation = tokens[index + 1].parse::<u32>()?;
                    cand.set_generation(generation);
                    index += 2;
                },
                "network-cost" => {
                    let cost = tokens[index + 1].parse::<u32>()?;
                    cand.set_network_cost(cost);
                    index += 2;
                },
                "raddr" => {
                    let addr = parse_unicast_addr(tokens[index + 1])?;
                    cand.set_remote_address(addr);
                    index += 2;
                },
                "rport" => {
                    let port = tokens[index + 1].parse::<u32>()?;
                    if port > 65535 {
                        return Err(SdpParserError::Line{
                            message: "ICE candidate rport can only be a bit 16bit number".to_string(),
                            line: line.to_string()})
                    }
                    cand.set_remote_port(port);
                    index += 2;
                },
                "tcptype" => {
                    cand.set_tcp_type(match tokens[index + 1].to_lowercase().as_ref() {
                        "active" => SdpAttributeCandidateTcpType::Active,
                        "passive" => SdpAttributeCandidateTcpType::Passive,
                        "so" => SdpAttributeCandidateTcpType::Simultaneous,
                        _ => return Err(SdpParserError::Line{
                            message: "Unknown tcptype value in candidate line".to_string(),
                            line: line.to_string()})
                    });
                    index += 2;
                },
                "ufrag" => {
                    let ufrag = tokens[index + 1];
                    cand.set_ufrag(ufrag.to_string());
                    index += 2;
                },
                _ => return Err(SdpParserError::Unsupported{
                    message: "Uknown candidate extension name".to_string(),
                    line: line.to_string()})
            };
        }
    }
    Ok(SdpAttribute::Candidate(cand))
}

fn parse_extmap(to_parse: &str,
                line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let tokens: Vec<&str> = to_parse.split_whitespace().collect();
    if tokens.len() != 2 {
        return Err(SdpParserError::Line{
            message: "Extmap needs to have two tokens".to_string(),
            line: line.to_string()})
    }
    let id: u32;
    let mut direction: Option<SdpAttributeDirection> = None;
    if tokens[0].find('/') == None {
        id = tokens[0].parse::<u32>()?;
    } else {
        let id_dir: Vec<&str> = tokens[0].splitn(2, '/').collect();
        id = id_dir[0].parse::<u32>()?;
        direction = Some(match id_dir[1].to_lowercase().as_ref() {
            "recvonly" => SdpAttributeDirection::Recvonly,
            "sendonly" => SdpAttributeDirection::Sendonly,
            "sendrecv" => SdpAttributeDirection::Sendrecv,
            _ => return Err(SdpParserError::Line{
                message: "Unsupported direction in extmap value".to_string(),
                line: line.to_string()}),
        })
    }
    Ok(SdpAttribute::Extmap(
        SdpAttributeExtmap {
            id,
            direction,
            url: tokens[1].to_string()
        }
    ))
}

fn parse_fingerprint(to_parse: &str,
                     line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let tokens: Vec<&str> = to_parse.split_whitespace().collect();
    if tokens.len() != 2 {
        return Err(SdpParserError::Line{
            message: "Fingerprint needs to have two tokens".to_string(),
            line: line.to_string()})
    }
    Ok(SdpAttribute::Fingerprint(
        SdpAttributeFingerprint {
            hash_algorithm: tokens[0].to_string(),
            fingerprint: tokens[1].to_string()
        }
    ))
}

fn parse_fmtp(to_parse: &str,
              line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let tokens: Vec<&str> = to_parse.split_whitespace().collect();
    if tokens.len() != 2 {
        return Err(SdpParserError::Line{
            message: "Fmtp needs to have two tokens".to_string(),
            line: line.to_string()})
    }
    Ok(SdpAttribute::Fmtp(
        SdpAttributeFmtp {
            // TODO check for dynamic PT range
            payload_type: tokens[0].parse::<u32>()?,
            // TODO this should probably be slit into known tokens
            // plus a list of unknown tokens
            tokens: to_parse.split(';').map(|x| x.to_string()).collect()
        }
    ))
}

fn parse_group(to_parse: &str,
               line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let mut tokens  = to_parse.split_whitespace();
    let semantics = match tokens.next() {
        None => return Err(SdpParserError::Line{
            message: "Group attribute is missing semantics token".to_string(),
            line: line.to_string()}),
        Some(x) =>  match x.to_uppercase().as_ref() {
            "LS" => SdpAttributeGroupSemantic::LipSynchronization,
            "FID" => SdpAttributeGroupSemantic::FlowIdentification,
            "SRF" => SdpAttributeGroupSemantic::SingleReservationFlow,
            "ANAT" => SdpAttributeGroupSemantic::AlternateNetworkAddressType,
            "FEC" => SdpAttributeGroupSemantic::ForwardErrorCorrection,
            "DDP" => SdpAttributeGroupSemantic::DecodingDependency,
            "BUNDLE" => SdpAttributeGroupSemantic::Bundle,
            _ => return Err(SdpParserError::Line{
                message: "Unsupported group semantics".to_string(),
                line: line.to_string()}),
        }
    };
    Ok(SdpAttribute::Group(
        SdpAttributeGroup {
            semantics,
            tags: tokens.map(|x| x.to_string()).collect()
        }
    ))
}

fn parse_ice_options(to_parse: &str,
                     line: &str) -> Result<SdpAttribute, SdpParserError>  {
    if to_parse.is_empty() {
        return Err(SdpParserError::Line{
            message: "ice-options is required to have a value".to_string(),
            line: line.to_string()})
    }
    Ok(SdpAttribute::IceOptions (
        to_parse.split_whitespace().map(|x| x.to_string()).collect()))
}

fn parse_msid(to_parse: &str,
              line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let mut tokens  = to_parse.split_whitespace();
    let id = match tokens.next() {
        None => return Err(SdpParserError::Line{
            message: "Msid attribute is missing msid-id token".to_string(),
            line: line.to_string()}),
        Some(x) => x.to_string()
    };
    let appdata = match tokens.next() {
        None => None,
        Some(x) => Some(x.to_string())
    };
    Ok(SdpAttribute::Msid(
        SdpAttributeMsid {
            id,
            appdata
        }
    ))
        
}
fn parse_remote_candidates(to_parse: &str,
                           line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let mut tokens = to_parse.split_whitespace();
    let component = match tokens.next() {
        None => return Err(SdpParserError::Line{
            message: "Remote-candidate attribute is missing component ID".to_string(),
            line: line.to_string()}),
        Some(x) => x.parse::<u32>()?
    };
    let address = match tokens.next() {
        None => return Err(SdpParserError::Line{
            message: "Remote-candidate attribute is missing connection address".to_string(),
            line: line.to_string()}),
        Some(x) => parse_unicast_addr(x)?
    };
    let port = match tokens.next() {
        None => return Err(SdpParserError::Line{
            message: "Remote-candidate attribute is missing port number".to_string(),
            line: line.to_string()}),
        Some(x) => x.parse::<u32>()?
    };
    if port > 65535 {
        return Err(SdpParserError::Line{
            message: "Remote-candidate port can only be a bit 16bit number".to_string(),
            line: line.to_string()})
    };
    Ok(SdpAttribute::RemoteCandidate(
        SdpAttributeRemoteCandidate {
            component,
            address,
            port
        }
    ))
}

fn parse_rtpmap(to_parse: &str,
                line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let tokens: Vec<&str> = to_parse.split_whitespace().collect();
    if tokens.len() != 2 {
        return Err(SdpParserError::Line{
            message: "Rtpmap needs to have two tokens".to_string(),
            line: line.to_string()})
    }
    // TODO limit this to dymaic PTs
    let payload_type: u32 = tokens[0].parse::<u32>()?;
    let split: Vec<&str> = tokens[1].split('/').collect();
    if split.len() > 3 {
        return Err(SdpParserError::Line{
            message: "Rtpmap codec token can max 3 subtokens".to_string(),
            line: line.to_string()})
    }
    let mut rtpmap = SdpAttributeRtpmap::new(payload_type,
                                             split[0].to_string());
    if split.len() > 1 {
        rtpmap.set_frequency(split[1].parse::<u32>()?);
    }
    if split.len() > 2 {
        rtpmap.set_channels(split[2].parse::<u32>()?);
    }
    Ok(SdpAttribute::Rtpmap(rtpmap))
}

fn parse_rtcp(to_parse: &str,
              line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let mut tokens = to_parse.split_whitespace();
    let port = match tokens.next() {
        None => return Err(SdpParserError::Line{
            message: "Rtcp attribute is missing port number".to_string(),
            line: line.to_string()}),
        Some(x) => x.parse::<u32>()?
    };
    if port > 65535 {
        return Err(SdpParserError::Line{
            message: "Rtcp port can only be a bit 16bit number".to_string(),
            line: line.to_string()})
    };
    let mut rtcp = SdpAttributeRtcp::new(port);
    match tokens.next() {
        None => (),
        Some(x) => {
            parse_nettype(x)?;
            match tokens.next() {
                None => return Err(SdpParserError::Line{
                    message: "Rtcp attribute is missing address type token".to_string(),
                    line: line.to_string()}),
                Some(x) => {
                    let addrtype = parse_addrtype(x)?;
                    let addr = match tokens.next() {
                        None => return Err(SdpParserError::Line{
                            message: "Rtcp attribute is missing ip address token".to_string(),
                            line: line.to_string()}),
                        Some(x) => {
                            let addr = parse_unicast_addr(x)?;
                            if !addrtype.same_protocol(&addr) {
                                return Err(SdpParserError::Line {
                                    message: "Failed to parse unicast address attribute.\
                                              addrtype does not match address."
                                        .to_string(),
                                    line: x.to_string()
                                });
                            }
                            addr
                        },
                    };
                    rtcp.set_addr(addr);
                },
            };
        },
    };
    Ok(SdpAttribute::Rtcp(rtcp))
}

fn parse_rtcp_fb(to_parse: &str,
                 line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let tokens: Vec<&str> = to_parse.splitn(2, ' ').collect();
    Ok(SdpAttribute::Rtcpfb(
        SdpAttributeRtcpFb {
            // TODO limit this to dymaic PTs
            payload_type: tokens[0].parse::<u32>()?,
            feedback_type: match tokens.get(1) {
                Some(x) => x.to_string(),
                None => return Err(SdpParserError::Line{
                    message: "Error parsing rtcpfb".to_string(),
                    line: line.to_string()})
            }
        }
    ))
}

fn parse_sctpmap(to_parse: &str,
                 line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let tokens: Vec<&str> = to_parse.split_whitespace().collect();
    if tokens.len() != 3 {
        return Err(SdpParserError::Line{
            message: "Sctpmap needs to have three tokens".to_string(),
            line: line.to_string()})
    }
    let port = tokens[0].parse::<u32>()?;
    if port > 65535 {
        return Err(SdpParserError::Line{
            message: "Sctpmap port can only be a bit 16bit number".to_string(),
            line: line.to_string()})
    }
    if tokens[1].to_lowercase() != "webrtc-datachannel" {
        return Err(SdpParserError::Line{
            message: "Unsupported sctpmap type token".to_string(),
            line: line.to_string()})
    }
    Ok(SdpAttribute::Sctpmap(
        SdpAttributeSctpmap {
            port,
            channels: tokens[2].parse::<u32>()?
        }
    ))
}

fn parse_setup(to_parse: &str,
               line: &str) -> Result<SdpAttribute, SdpParserError>  {
    Ok(SdpAttribute::Setup(
        match to_parse.to_lowercase().as_ref() {
            "active" => SdpAttributeSetup::Active,
            "actpass" => SdpAttributeSetup::Actpass,
            "holdconn" => SdpAttributeSetup::Holdconn,
            "passive" => SdpAttributeSetup::Passive,
            _ => return Err(SdpParserError::Line{
                message: "Unsupported setup value".to_string(),
                line: line.to_string()}),
        }
    ))
}

fn parse_simulcast(to_parse: &str,
                   line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let mut tokens = to_parse.split_whitespace();
    let mut token = match tokens.next() {
        None => return Err(SdpParserError::Line{
            message: "Simulcast attribute is missing send/recv value".to_string(),
            line: line.to_string()}),
        Some(x) => x,
    };
    let mut sc = SdpAttributeSimulcast {
        send: Vec::new(),
        receive: Vec::new()
    };
    loop {
        let sendrecv = match token.to_lowercase().as_ref() {
            "send" => SdpAttributeDirection::Sendonly,
            "recv" => SdpAttributeDirection::Recvonly,
            _ => return Err(SdpParserError::Line{
                message: "Unsupported send/recv value in simulcast attribute".to_string(),
                line: line.to_string()}),
        };
        match tokens.next() {
            None => return Err(SdpParserError::Line{
                message: "Simulcast attribute is missing id list".to_string(),
                line: line.to_string()}),
            Some(x) => sc.parse_ids(sendrecv, x.to_string()),
        };
        token = match tokens.next() {
            None => { break; },
            Some(x) => x,
        };
    }
    Ok(SdpAttribute::Simulcast(sc))
}

fn parse_ssrc(to_parse: &str,
              line: &str) -> Result<SdpAttribute, SdpParserError>  {
    let mut tokens  = to_parse.split_whitespace();
    let ssrc_id = match tokens.next() {
        None => return Err(SdpParserError::Line{
            message: "Ssrc attribute is missing ssrc-id value".to_string(),
            line: line.to_string()}),
        Some(x) => x.parse::<u32>()?
    };
    let mut ssrc = SdpAttributeSsrc::new(ssrc_id);
    match tokens.next() {
        None => (),
        Some(x) => ssrc.set_attribute(x),
    };
    Ok(SdpAttribute::Ssrc(ssrc))
}

pub fn parse_attribute(value: &str) -> Result<SdpLine, SdpParserError> {
    let attr: SdpAttribute = value.parse()?;
    // attr.parse_value(val.trim())?;
    /*
    println!("attribute: {}, {}", 
             a.name, a.value.some());
             */
    Ok(SdpLine::Attribute(attr))
}

#[test]
fn test_parse_attribute_candidate() {
    assert!(parse_attribute("candidate:0 1 UDP 2122252543 172.16.156.106 49760 typ host").is_ok());
    assert!(parse_attribute("candidate:foo 1 UDP 2122252543 172.16.156.106 49760 typ host")
                .is_ok());
    assert!(parse_attribute("candidate:0 1 TCP 2122252543 172.16.156.106 49760 typ host").is_ok());
    assert!(parse_attribute("candidate:0 1 TCP 2122252543 ::1 49760 typ host").is_ok());
    assert!(parse_attribute("candidate:0 1 UDP 2122252543 172.16.156.106 49760 typ srflx").is_ok());
    assert!(parse_attribute("candidate:0 1 UDP 2122252543 172.16.156.106 49760 typ prflx").is_ok());
    assert!(parse_attribute("candidate:0 1 UDP 2122252543 172.16.156.106 49760 typ relay").is_ok());
    assert!(parse_attribute("candidate:0 1 TCP 2122252543 172.16.156.106 49760 typ host tcptype active").is_ok());
    assert!(parse_attribute("candidate:0 1 TCP 2122252543 172.16.156.106 49760 typ host tcptype passive").is_ok());
    assert!(parse_attribute("candidate:0 1 TCP 2122252543 172.16.156.106 49760 typ host tcptype so").is_ok());
    assert!(parse_attribute("candidate:0 1 TCP 2122252543 172.16.156.106 49760 typ host ufrag foobar").is_ok());
    assert!(parse_attribute("candidate:0 1 TCP 2122252543 172.16.156.106 49760 typ host network-cost 50").is_ok());
    assert!(parse_attribute("candidate:1 1 UDP 1685987071 24.23.204.141 54609 typ srflx raddr 192.168.1.4 rport 61665 generation 0").is_ok());
    assert!(parse_attribute("candidate:1 1 UDP 1685987071 24.23.204.141 54609 typ srflx raddr 192.168.1.4 rport 61665").is_ok());
    assert!(parse_attribute("candidate:1 1 TCP 1685987071 24.23.204.141 54609 typ srflx raddr 192.168.1.4 rport 61665 tcptype passive").is_ok());
    assert!(parse_attribute("candidate:1 1 TCP 1685987071 24.23.204.141 54609 typ srflx raddr 192.168.1.4 rport 61665 tcptype passive generation 1").is_ok());
    assert!(parse_attribute("candidate:1 1 TCP 1685987071 24.23.204.141 54609 typ srflx raddr 192.168.1.4 rport 61665 tcptype passive generation 1 ufrag +DGd").is_ok());
    assert!(parse_attribute("candidate:1 1 TCP 1685987071 24.23.204.141 54609 typ srflx raddr 192.168.1.4 rport 61665 tcptype passive generation 1 ufrag +DGd network-cost 1").is_ok());

    assert!(parse_attribute("candidate:0 1 UDP 2122252543 172.16.156.106 49760 typ").is_err());
    assert!(parse_attribute("candidate:0 foo UDP 2122252543 172.16.156.106 49760 typ host")
                .is_err());
    assert!(parse_attribute("candidate:0 1 FOO 2122252543 172.16.156.106 49760 typ host").is_err());
    assert!(parse_attribute("candidate:0 1 UDP foo 172.16.156.106 49760 typ host").is_err());
    assert!(parse_attribute("candidate:0 1 UDP 2122252543 172.16.156 49760 typ host").is_err());
    assert!(parse_attribute("candidate:0 1 UDP 2122252543 172.16.156.106 70000 typ host").is_err());
    assert!(parse_attribute("candidate:0 1 UDP 2122252543 172.16.156.106 49760 type host")
                .is_err());
    assert!(parse_attribute("candidate:0 1 UDP 2122252543 172.16.156.106 49760 typ fost").is_err());
    // FIXME this should fail without the extra 'foobar' at the end
    assert!(parse_attribute("candidate:0 1 TCP 2122252543 172.16.156.106 49760 typ host unsupported foobar").is_err());
    assert!(parse_attribute("candidate:1 1 UDP 1685987071 24.23.204.141 54609 typ srflx raddr 192.168.1.4 rport 61665 generation B").is_err());
    assert!(parse_attribute("candidate:0 1 TCP 2122252543 172.16.156.106 49760 typ host network-cost C").is_err());
    assert!(parse_attribute("candidate:1 1 UDP 1685987071 24.23.204.141 54609 typ srflx raddr 192.168.1 rport 61665").is_err());
    assert!(parse_attribute("candidate:0 1 TCP 2122252543 172.16.156.106 49760 typ host tcptype foobar").is_err());
    assert!(parse_attribute("candidate:1 1 UDP 1685987071 24.23.204.141 54609 typ srflx raddr 192.168.1 rport 61665").is_err());
    assert!(parse_attribute("candidate:1 1 UDP 1685987071 24.23.204.141 54609 typ srflx raddr 192.168.1.4 rport 70000").is_err());
}

#[test]
fn test_parse_attribute_end_of_candidates() {
    assert!(parse_attribute("end-of-candidates").is_ok());
    assert!(parse_attribute("end-of-candidates foobar").is_err());
}

#[test]
fn test_parse_attribute_extmap() {
    assert!(parse_attribute("extmap:1/sendonly urn:ietf:params:rtp-hdrext:ssrc-audio-level")
                .is_ok());
    assert!(parse_attribute("extmap:2/sendrecv urn:ietf:params:rtp-hdrext:ssrc-audio-level")
                .is_ok());
    assert!(parse_attribute("extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time")
                .is_ok());

    assert!(parse_attribute("extmap:a/sendrecv urn:ietf:params:rtp-hdrext:ssrc-audio-level")
                .is_err());
    assert!(parse_attribute("extmap:4/unsupported urn:ietf:params:rtp-hdrext:ssrc-audio-level")
                .is_err());
}

#[test]
fn test_parse_attribute_fingerprint() {
    assert!(parse_attribute("fingerprint:sha-256 CD:34:D1:62:16:95:7B:B7:EB:74:E2:39:27:97:EB:0B:23:73:AC:BC:BF:2F:E3:91:CB:57:A9:9D:4A:A2:0B:40").is_ok())
}

#[test]
fn test_parse_attribute_fmtp() {
    assert!(parse_attribute("fmtp:109 maxplaybackrate=48000;stereo=1;useinbandfec=1").is_ok())
}

#[test]
fn test_parse_attribute_group() {
    assert!(parse_attribute("group:LS").is_ok());
    assert!(parse_attribute("group:LS 1 2").is_ok());
    assert!(parse_attribute("group:BUNDLE sdparta_0 sdparta_1 sdparta_2").is_ok());

    assert!(parse_attribute("group:").is_err());
    assert!(parse_attribute("group:NEVER_SUPPORTED_SEMANTICS").is_err());
}

#[test]
fn test_parse_attribute_bundle_only() {
    assert!(parse_attribute("bundle-only").is_ok());
    assert!(parse_attribute("bundle-only foobar").is_err());
}

#[test]
fn test_parse_attribute_ice_lite() {
    assert!(parse_attribute("ice-lite").is_ok());

    assert!(parse_attribute("ice-lite foobar").is_err());
}

#[test]
fn test_parse_attribute_ice_mismatch() {
    assert!(parse_attribute("ice-mismatch").is_ok());

    assert!(parse_attribute("ice-mismatch foobar").is_err());
}

#[test]
fn test_parse_attribute_ice_options() {
    assert!(parse_attribute("ice-options:trickle").is_ok());

    assert!(parse_attribute("ice-options:").is_err());
}

#[test]
fn test_parse_attribute_ice_pwd() {
    assert!(parse_attribute("ice-pwd:e3baa26dd2fa5030d881d385f1e36cce").is_ok());

    assert!(parse_attribute("ice-pwd:").is_err());
}

#[test]
fn test_parse_attribute_ice_ufrag() {
    assert!(parse_attribute("ice-ufrag:58b99ead").is_ok());

    assert!(parse_attribute("ice-ufrag:").is_err());
}

#[test]
fn test_parse_attribute_identity() {
    assert!(parse_attribute("identity:eyJpZHAiOnsiZG9tYWluIjoiZXhhbXBsZS5vcmciLCJwcm90b2NvbCI6ImJvZ3VzIn0sImFzc2VydGlvbiI6IntcImlkZW50aXR5XCI6XCJib2JAZXhhbXBsZS5vcmdcIixcImNvbnRlbnRzXCI6XCJhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3l6XCIsXCJzaWduYXR1cmVcIjpcIjAxMDIwMzA0MDUwNlwifSJ9").is_ok());

    assert!(parse_attribute("identity:").is_err());
}

#[test]
fn test_parse_attribute_imageattr() {
    assert!(parse_attribute("imageattr:120 send * recv *").is_ok());
    assert!(parse_attribute("imageattr:97 send [x=800,y=640,sar=1.1,q=0.6] [x=480,y=320] recv [x=330,y=250]").is_ok());
    assert!(parse_attribute("imageattr:97 recv [x=800,y=640,sar=1.1] send [x=330,y=250]").is_ok());
    assert!(parse_attribute("imageattr:97 send [x=[480:16:800],y=[320:16:640],par=[1.2-1.3],q=0.6] [x=[176:8:208],y=[144:8:176],par=[1.2-1.3]] recv *").is_ok());

    assert!(parse_attribute("imageattr:").is_err());
}

#[test]
fn test_parse_attribute_inactive() {
    assert!(parse_attribute("inactive").is_ok());
    assert!(parse_attribute("inactive foobar").is_err());
}

#[test]
fn test_parse_attribute_label() {
    assert!(parse_attribute("label:1").is_ok());
    assert!(parse_attribute("label:foobar").is_ok());
    assert!(parse_attribute("label:foobar barfoo").is_ok());

    assert!(parse_attribute("label:").is_err());
}

#[test]
fn test_parse_attribute_maxptime() {
    assert!(parse_attribute("maxptime:60").is_ok());

    assert!(parse_attribute("maxptime:").is_err());
}

#[test]
fn test_parse_attribute_mid() {
    assert!(parse_attribute("mid:sdparta_0").is_ok());
    assert!(parse_attribute("mid:sdparta_0 sdparta_1 sdparta_2").is_ok());

    assert!(parse_attribute("mid:").is_err());
}

#[test]
fn test_parse_attribute_msid() {
    assert!(parse_attribute("msid:{5a990edd-0568-ac40-8d97-310fc33f3411}").is_ok());
    assert!(parse_attribute("msid:{5a990edd-0568-ac40-8d97-310fc33f3411} {218cfa1c-617d-2249-9997-60929ce4c405}").is_ok());

    assert!(parse_attribute("msid:").is_err());
}

#[test]
fn test_parse_attribute_msid_semantics() {
    assert!(parse_attribute("msid-semantic:WMS *").is_ok())
}

#[test]
fn test_parse_attribute_ptime() {
    assert!(parse_attribute("ptime:30").is_ok());

    assert!(parse_attribute("ptime:").is_err());
}

#[test]
fn test_parse_attribute_rid() {
    assert!(parse_attribute("rid:foo send").is_ok());
    assert!(parse_attribute("rid:foo").is_ok());

    assert!(parse_attribute("rid:").is_err());
}

#[test]
fn test_parse_attribute_recvonly() {
    assert!(parse_attribute("recvonly").is_ok());
    assert!(parse_attribute("recvonly foobar").is_err());
}

#[test]
fn test_parse_attribute_remote_candidate() {
    assert!(parse_attribute("remote-candidates:0 10.0.0.1 5555").is_ok());
    assert!(parse_attribute("remote-candidates:12345 ::1 5555").is_ok());

    assert!(parse_attribute("remote-candidates:abc 10.0.0.1 5555").is_err());
    assert!(parse_attribute("remote-candidates:0 10.a.0.1 5555").is_err());
    assert!(parse_attribute("remote-candidates:0 10.0.0.1 70000").is_err());
    assert!(parse_attribute("remote-candidates:0 10.0.0.1").is_err());
    assert!(parse_attribute("remote-candidates:0").is_err());
    assert!(parse_attribute("remote-candidates:").is_err());
}

#[test]
fn test_parse_attribute_sendonly() {
    assert!(parse_attribute("sendonly").is_ok());
    assert!(parse_attribute("sendonly foobar").is_err());
}

#[test]
fn test_parse_attribute_sendrecv() {
    assert!(parse_attribute("sendrecv").is_ok());
    assert!(parse_attribute("sendrecv foobar").is_err());
}

#[test]
fn test_parse_attribute_setup() {
    assert!(parse_attribute("setup:active").is_ok());
    assert!(parse_attribute("setup:passive").is_ok());
    assert!(parse_attribute("setup:actpass").is_ok());
    assert!(parse_attribute("setup:holdconn").is_ok());

    assert!(parse_attribute("setup:").is_err());
    assert!(parse_attribute("setup:foobar").is_err());
}

#[test]
fn test_parse_attribute_rtcp() {
    assert!(parse_attribute("rtcp:5000").is_ok());
    assert!(parse_attribute("rtcp:9 IN IP4 0.0.0.0").is_ok());

    assert!(parse_attribute("rtcp:").is_err());
    assert!(parse_attribute("rtcp:70000").is_err());
    assert!(parse_attribute("rtcp:9 IN").is_err());
    assert!(parse_attribute("rtcp:9 IN IP4").is_err());
    assert!(parse_attribute("rtcp:9 IN IP4 ::1").is_err());
}

#[test]
fn test_parse_attribute_rtcp_fb() {
    assert!(parse_attribute("rtcp-fb:101 ccm fir").is_ok())
}

#[test]
fn test_parse_attribute_rtcp_mux() {
    assert!(parse_attribute("rtcp-mux").is_ok());
    assert!(parse_attribute("rtcp-mux foobar").is_err());
}

#[test]
fn test_parse_attribute_rtcp_rsize() {
    assert!(parse_attribute("rtcp-rsize").is_ok());
    assert!(parse_attribute("rtcp-rsize foobar").is_err());
}

#[test]
fn test_parse_attribute_rtpmap() {
    assert!(parse_attribute("rtpmap:109 opus/48000/2").is_ok())
}

#[test]
fn test_parse_attribute_sctpmap() {
    assert!(parse_attribute("sctpmap:5000 webrtc-datachannel 256").is_ok());

    assert!(parse_attribute("sctpmap:70000 webrtc-datachannel 256").is_err());
    assert!(parse_attribute("sctpmap:5000 unsupported 256").is_err());
    assert!(parse_attribute("sctpmap:5000 webrtc-datachannel 2a").is_err());
}

#[test]
fn test_parse_attribute_sctp_port() {
    assert!(parse_attribute("sctp-port:5000").is_ok());

    assert!(parse_attribute("sctp-port:").is_err());
    assert!(parse_attribute("sctp-port:70000").is_err());
}

#[test]
fn test_parse_attribute_max_message_size() {
    assert!(parse_attribute("max-message-size:1").is_ok());
    assert!(parse_attribute("max-message-size:100000").is_ok());
    assert!(parse_attribute("max-message-size:4294967297").is_ok());
    assert!(parse_attribute("max-message-size:0").is_ok());

    assert!(parse_attribute("max-message-size:").is_err());
    assert!(parse_attribute("max-message-size:abc").is_err());
}

#[test]
fn test_parse_attribute_simulcast() {
    assert!(parse_attribute("simulcast:send 1").is_ok());
    assert!(parse_attribute("simulcast:recv test").is_ok());
    assert!(parse_attribute("simulcast:recv ~test").is_ok());
    assert!(parse_attribute("simulcast:recv test;foo").is_ok());
    assert!(parse_attribute("simulcast:recv foo,bar").is_ok());
    assert!(parse_attribute("simulcast:recv foo,bar;test").is_ok());
    assert!(parse_attribute("simulcast:recv 1;4,5 send 6;7").is_ok());
    assert!(parse_attribute("simulcast:send 1,2,3;~4,~5 recv 6;~7,~8").is_ok());
    // old draft 03 notation used by Firefox 55
    assert!(parse_attribute("simulcast: send rid=foo;bar").is_ok());

    assert!(parse_attribute("simulcast:").is_err());
    assert!(parse_attribute("simulcast:send").is_err());
    assert!(parse_attribute("simulcast:foobar 1").is_err());
    assert!(parse_attribute("simulcast:send 1 foobar 2").is_err());
}

#[test]
fn test_parse_attribute_ssrc() {
    assert!(parse_attribute("ssrc:2655508255").is_ok());
    assert!(parse_attribute("ssrc:2655508255 foo").is_ok());
    assert!(parse_attribute("ssrc:2655508255 cname:{735484ea-4f6c-f74a-bd66-7425f8476c2e}")
                .is_ok());

    assert!(parse_attribute("ssrc:").is_err());
    assert!(parse_attribute("ssrc:foo").is_err());
}

#[test]
fn test_parse_attribute_ssrc_group() {
    assert!(parse_attribute("ssrc-group:FID 3156517279 2673335628").is_ok())
}

#[test]
fn test_parse_unknown_attribute() {
    assert!(parse_attribute("unknown").is_err())
}
