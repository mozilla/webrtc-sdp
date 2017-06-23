use error::SdpParserError;
use SdpLine;

pub fn parse_repeat(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO implement this if it's ever needed
    println!("repeat: {}", value);
    Ok(SdpLine::Repeat(String::from(value)))
}

#[test]
fn test_repeat_works() {
    // FIXME use a proper r value here
    assert!(parse_repeat("0 0").is_ok());
}

pub fn parse_zone(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO implement this if it's ever needed
    println!("zone: {}", value);
    Ok(SdpLine::Zone(String::from(value)))
}

#[test]
fn test_zone_works() {
    // FIXME use a proper z value here
    assert!(parse_zone("0 0").is_ok());
}

pub fn parse_key(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO implement this if it's ever needed
    println!("key: {}", value);
    Ok(SdpLine::Key(String::from(value)))
}

#[test]
fn test_keys_works() {
    // FIXME use a proper k value here
    assert!(parse_key("12345").is_ok());
}

pub fn parse_information(value: &str) -> Result<SdpLine, SdpParserError> {
    println!("information: {}", value);
    Ok(SdpLine::Information(String::from(value)))
}

#[test]
fn test_information_works() {
    assert!(parse_information("foobar").is_ok());
}

pub fn parse_uri(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO check if this is really a URI
    println!("uri: {}", value);
    Ok(SdpLine::Uri(String::from(value)))
}

#[test]
fn test_uri_works() {
    assert!(parse_uri("http://www.mozilla.org").is_ok());
}

pub fn parse_email(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO check if this is really an email address
    println!("email: {}", value);
    Ok(SdpLine::Email(String::from(value)))
}

#[test]
fn test_email_works() {
    assert!(parse_email("nils@mozilla.com").is_ok());
}

pub fn parse_phone(value: &str) -> Result<SdpLine, SdpParserError> {
    // TODO check if this is really a phone number
    println!("phone: {}", value);
    Ok(SdpLine::Phone(String::from(value)))
}

#[test]
fn test_phone_works() {
    assert!(parse_phone("+123456789").is_ok());
}
