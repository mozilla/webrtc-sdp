use error::SdpParserError;
use SdpLine;

pub fn parse_repeat(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO implement this if it's ever needed
    Err(SdpParserError::Unsupported {
            message: "repeat type is unsupported".to_string(),
            line: value.to_string(),
            line_number: None,
        })
}

#[test]
fn test_repeat_works() {
    // FIXME use a proper r value here
    assert!(parse_repeat("0 0").is_err());
}

pub fn parse_zone(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO implement this if it's ever needed
    Err(SdpParserError::Unsupported {
            message: "zone type is unsupported".to_string(),
            line: value.to_string(),
            line_number: None,
        })
}

#[test]
fn test_zone_works() {
    // FIXME use a proper z value here
    assert!(parse_zone("0 0").is_err());
}

pub fn parse_key(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO implement this if it's ever needed
    Err(SdpParserError::Unsupported {
            message: "key type is unsupported".to_string(),
            line: value.to_string(),
            line_number: None,
        })
}

#[test]
fn test_keys_works() {
    // FIXME use a proper k value here
    assert!(parse_key("12345").is_err());
}

pub fn parse_information(value: &str) -> Result<SdpLine, SdpParserError> {
    Err(SdpParserError::Unsupported {
            message: "information type is unsupported".to_string(),
            line: value.to_string(),
            line_number: None,
        })
}

#[test]
fn test_information_works() {
    assert!(parse_information("foobar").is_err());
}

pub fn parse_uri(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO check if this is really a URI
    Err(SdpParserError::Unsupported {
            message: "uri type is unsupported".to_string(),
            line: value.to_string(),
            line_number: None,
        })
}

#[test]
fn test_uri_works() {
    assert!(parse_uri("http://www.mozilla.org").is_err());
}

pub fn parse_email(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO check if this is really an email address
    Err(SdpParserError::Unsupported {
            message: "email type is unsupported".to_string(),
            line: value.to_string(),
            line_number: None,
        })
}

#[test]
fn test_email_works() {
    assert!(parse_email("nils@mozilla.com").is_err());
}

pub fn parse_phone(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO check if this is really a phone number
    Err(SdpParserError::Unsupported {
            message: "phone type is unsupported".to_string(),
            line: value.to_string(),
            line_number: None,
        })
}

#[test]
fn test_phone_works() {
    assert!(parse_phone("+123456789").is_err());
}
