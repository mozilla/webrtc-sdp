use std::str::FromStr;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use error::SdpParserError;

#[derive(Clone,Debug,PartialEq)]
pub enum SdpNetType {
    Internet,
}

#[derive(Clone,Debug,PartialEq)]
pub enum SdpAddrType {
    IP4,
    IP6,
}

impl fmt::Display for SdpNetType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IN")
    }
}

impl fmt::Display for SdpAddrType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            SdpAddrType::IP4 => "Ip4",
            SdpAddrType::IP6 => "Ip6",
        };
        write!(f, "{}", printable)
    }
}

pub fn parse_nettype(value: &str) -> Result<SdpNetType, SdpParserError> {
    if value.to_uppercase() != "IN" {
        return Err(SdpParserError::Line {
                       message: "nettype needs to be IN".to_string(),
                       line: value.to_string(),
                   });
    };
    Ok(SdpNetType::Internet)
}

#[test]
fn test_parse_nettype() {
    let internet = parse_nettype("iN");
    assert!(internet.is_ok());
    assert_eq!(internet.unwrap(), SdpNetType::Internet);

    assert!(parse_nettype("").is_err());
    assert!(parse_nettype("FOO").is_err());
}

pub fn parse_addrtype(value: &str) -> Result<SdpAddrType, SdpParserError> {
    Ok(match value.to_uppercase().as_ref() {
           "IP4" => SdpAddrType::IP4,
           "IP6" => SdpAddrType::IP6,
           _ => {
               return Err(SdpParserError::Line {
                              message: "address type needs to be IP4 or IP6".to_string(),
                              line: value.to_string(),
                          })
           }
       })
}

#[test]
fn test_parse_addrtype() {
    let ip4 = parse_addrtype("iP4");
    assert!(ip4.is_ok());
    assert_eq!(ip4.unwrap(), SdpAddrType::IP4);
    let ip6 = parse_addrtype("Ip6");
    assert!(ip6.is_ok());
    assert_eq!(ip6.unwrap(), SdpAddrType::IP6);

    assert!(parse_addrtype("").is_err());
    assert!(parse_addrtype("IP5").is_err());
}

pub fn parse_unicast_addr(addrtype: &SdpAddrType, value: &str) -> Result<IpAddr, SdpParserError> {
    Ok(match *addrtype {
           SdpAddrType::IP4 => {
               IpAddr::V4(match Ipv4Addr::from_str(value) {
                              Ok(n) => n,
                              Err(_) => {
                                  return Err(SdpParserError::Line {
                                                 message: "failed to parse unicast IP4 address attribute"
                                                     .to_string(),
                                                 line: value.to_string(),
                                             })
                              }
                          })
           }
           SdpAddrType::IP6 => {
               IpAddr::V6(match Ipv6Addr::from_str(value) {
                              Ok(n) => n,
                              Err(_) => {
                                  return Err(SdpParserError::Line {
                                                 message: "failed to parse unicast IP6 address attribute"
                                                     .to_string(),
                                                 line: value.to_string(),
                                             })
                              }
                          })
           }
       })
}

pub fn parse_unicast_addr_unknown_type(value: &str) -> Result<IpAddr, SdpParserError> {
    if value.find('.') == None {
        parse_unicast_addr(&SdpAddrType::IP6, value)
    } else {
        parse_unicast_addr(&SdpAddrType::IP4, value)
    }
}

#[test]
fn test_parse_unicast_addr_unknown_type() {
    let ip4 = parse_unicast_addr_unknown_type("127.0.0.1");
    assert!(ip4.is_ok());
    let ip6 = parse_unicast_addr_unknown_type("::1");
    assert!(ip6.is_ok());
}
