
extern crate url;
use self::url::{Host, ParseError};
use std::net::{Ipv4Addr, Ipv6Addr};

enum AddressType {
    IpV4,
    IpV6,
}

enum UnicastAddress {
    Fqdn(String),
    IpV4(Ipv4Addr),
    IpV6(Ipv6Addr),
}

enum MulticastAddress {

}

enum Address {
    Unicast(UnicastAddress),
    Multicast(MulticastAddress),
}

enum ConnectionAddress {
    Fqdn{address_type:AddressType, domain:String},
    IpV4(Ipv4Addr),
    IpV6(Ipv6Addr),
}

impl ConnectionAddress {
    fn parse(address_type: &str, string: &str) -> Result<Self, ParseError> {
        panic!()
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;
    use std::net::{Ipv4Addr, Ipv6Addr, AddrParseError};
    use std::error::Error;
    use super::*;

    #[derive(Debug, enum_display_derive::Display)]
    enum ParseTestError {
        Host(ParseError),
        Ip(AddrParseError),
    }
    impl From<ParseError> for ParseTestError {
        fn from(err: ParseError) -> Self {
            ParseTestError::Host(err)
        }
    }
    impl From<AddrParseError> for ParseTestError {
        fn from(err: AddrParseError) -> Self {
            ParseTestError::Ip(err)
        }
    }
    impl Error for ParseTestError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            // Generic error, underlying cause isn't tracked.
            match self {
                ParseTestError::Host(a) => Some(a),
                ParseTestError::Ip(a) => Some(a),
            }
    }
}
    #[test]
    fn test_domain_name_parsing() -> Result<(), ParseTestError> {
        let address = Host::parse("this.is.a.fqdn")?;
        if let Host::Domain(domain) = address {
            assert_eq!(domain , "this.is.a.fqdn");
        } else {
            panic!();
        }
        Ok(())
    }

    #[test]
    fn test_ipv4_address_parsing() -> Result<(), ParseTestError> {
        let address = Host::parse("1.0.0.1")?;
        if let Host::Ipv4(ip) = address {
            assert_eq!(ip, "1.0.0.1".parse::<Ipv4Addr>()?);
        } else {
            panic!();
        }
        Ok(())
    }

    #[test]
    fn test_ipv6_address_parsing() -> Result<(), ParseTestError> {
        let address = Host::parse("[::1]")?;
        if let Host::Ipv6(ip) = address {
            assert_eq!(ip, "::1".parse::<Ipv6Addr>()?);
        } else {
            panic!();
        }
        Ok(())
    }
}