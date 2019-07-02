use std::net::IpAddr;
use std::str::FromStr;

use error::SdpParserInternalError;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SdpAddressType {
    IP4 = 4,
    IP6 = 6,
}

impl SdpAddressType {
    pub fn same_protocol(self, addr: &IpAddr) -> bool {
        (addr.is_ipv6() && self == SdpAddressType::IP6)
            || (addr.is_ipv4() && self == SdpAddressType::IP4)
    }
}

pub fn address_to_string(addr: url::Host) -> String {
    match addr {
        url::Host::Domain(s) => format!("IN IP4 {}", s),
        url::Host::Ipv4(ipv4) => format!("IN IP4 {}", ipv4.to_string()),
        url::Host::Ipv6(ipv6) => format!("IN IP6 {}", ipv6.to_string()),
    }
}

pub fn parse_network_type(value: &str) -> Result<(), SdpParserInternalError> {
    if value.to_uppercase() != "IN" {
        return Err(SdpParserInternalError::Generic(
            "nettype needs to be IN".to_string(),
        ));
    };
    Ok(())
}

pub fn parse_address_type(value: &str) -> Result<SdpAddressType, SdpParserInternalError> {
    Ok(match value.to_uppercase().as_ref() {
        "IP4" => SdpAddressType::IP4,
        "IP6" => SdpAddressType::IP6,
        _ => {
            return Err(SdpParserInternalError::Generic(
                "address type needs to be IP4 or IP6".to_string(),
            ));
        }
    })
}

pub fn parse_unicast_address(value: &str) -> Result<IpAddr, SdpParserInternalError> {
    Ok(IpAddr::from_str(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_network_type() -> Result<(), SdpParserInternalError> {
        parse_network_type("iN")?;

        assert!(parse_network_type("").is_err());
        assert!(parse_network_type("FOO").is_err());
        Ok(())
    }

    #[test]
    fn test_parse_address_type() -> Result<(), SdpParserInternalError> {
        let ip4 = parse_address_type("iP4")?;
        assert_eq!(ip4, SdpAddressType::IP4);
        let ip6 = parse_address_type("Ip6")?;
        assert_eq!(ip6, SdpAddressType::IP6);

        assert!(parse_address_type("").is_err());
        assert!(parse_address_type("IP5").is_err());
        Ok(())
    }

    #[test]
    fn test_parse_unicast_address() -> Result<(), SdpParserInternalError> {
        parse_unicast_address("127.0.0.1")?;
        parse_unicast_address("::1")?;
        Ok(())
    }
}
