use std::num::ParseIntError;
use std::net::AddrParseError;
use std::fmt;
use std::error;
use std::error::Error;

#[derive(Debug)]
pub enum SdpParserInternalError {
    Generic(String),
    Unsupported(String),
    Integer(ParseIntError),
    Address(AddrParseError),
}

impl fmt::Display for SdpParserInternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SdpParserInternalError::Generic(ref message) => {
                write!(f, "Generic parsing error: {}", message)
            }
            SdpParserInternalError::Unsupported(ref message) => {
                write!(f, "Unsupported parsing error: {}", message)
            }
            SdpParserInternalError::Integer(ref error) => {
                write!(f, "Integer parsing error: {}", error.description())
            }
            SdpParserInternalError::Address(ref error) => {
                write!(f, "IP address parsing error: {}", error.description())
            }
        }
    }
}

impl error::Error for SdpParserInternalError {
    fn description(&self) -> &str {
        match *self {
            SdpParserInternalError::Generic(ref message) |
            SdpParserInternalError::Unsupported(ref message) => message,
            SdpParserInternalError::Integer(ref error) => error.description(),
            SdpParserInternalError::Address(ref error) => error.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            SdpParserInternalError::Integer(ref error) => Some(error),
            SdpParserInternalError::Address(ref error) => Some(error),
            // Can't tell much more about our internal errors
            _ => None,
        }
    }
}

#[test]
fn test_sdp_parser_internal_error_generic() {
    let generic = SdpParserInternalError::Generic("generic message".to_string());
    assert_eq!(format!("{}", generic),
               "Generic parsing error: generic message");
    assert_eq!(generic.description(), "generic message");
    assert!(generic.cause().is_none());
}

#[test]
fn test_sdp_parser_internal_error_unsupported() {
    let unsupported = SdpParserInternalError::Unsupported("unsupported internal message"
                                                              .to_string());
    assert_eq!(format!("{}", unsupported),
               "Unsupported parsing error: unsupported internal message");
    assert_eq!(unsupported.description(), "unsupported internal message");
    assert!(unsupported.cause().is_none());
}

#[test]
fn test_sdp_parser_internal_error_integer() {
    let v = "12a";
    let integer = v.parse::<u64>();
    assert!(integer.is_err());
    let int_err = SdpParserInternalError::Integer(integer.err().unwrap());
    assert_eq!(format!("{}", int_err),
               "Integer parsing error: invalid digit found in string");
    assert_eq!(int_err.description(), "invalid digit found in string");
    assert!(!int_err.cause().is_none());
}

#[test]
fn test_sdp_parser_internal_error_address() {
    let v = "127.0.0.a";
    use std::str::FromStr;
    use std::net::IpAddr;
    let addr = IpAddr::from_str(v);
    assert!(addr.is_err());
    let addr_err = SdpParserInternalError::Address(addr.err().unwrap());
    assert_eq!(format!("{}", addr_err),
               "IP address parsing error: invalid IP address syntax");
    assert_eq!(addr_err.description(), "invalid IP address syntax");
    assert!(!addr_err.cause().is_none());
}

#[derive(Debug)]
pub enum SdpParserError {
    Line {
        error: SdpParserInternalError,
        line: String,
        line_number: usize,
    },
    Unsupported {
        error: SdpParserInternalError,
        line: Option<String>,
        line_number: Option<usize>,
    },
    Sequence { message: String, line_number: usize },
}

impl fmt::Display for SdpParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SdpParserError::Line {
                ref error,
                ref line,
                ref line_number,
            } => {
                write!(f,
                       "Line error: {} in line({}): {}",
                       error.description(),
                       line_number,
                       line)
            }
            SdpParserError::Unsupported {
                ref error,
                ref line,
                ref line_number,
            } => {
                let ln = match *line_number {
                    None => "?".to_string(),
                    Some(x) => x.to_string(),
                };
                let l = match *line {
                    None => "?".to_string(),
                    Some(ref x) => x.to_string(),
                };
                write!(f,
                       "Unsupported: {} in line({}): {}",
                       error.description(),
                       ln,
                       l)
            }
            SdpParserError::Sequence {
                ref message,
                ref line_number,
            } => write!(f, "Sequence error in line({}): {}", line_number, message),
        }
    }
}


impl error::Error for SdpParserError {
    fn description(&self) -> &str {
        match *self {
            SdpParserError::Line { ref error, .. } => error.description(),
            SdpParserError::Unsupported { ref error, .. } => error.description(),
            SdpParserError::Sequence { ref message, .. } => message,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            SdpParserError::Line { ref error, .. } |
            SdpParserError::Unsupported { ref error, .. } => Some(error),
            // Can't tell much more about our internal errors
            _ => None,
        }
    }
}

impl From<ParseIntError> for SdpParserInternalError {
    fn from(err: ParseIntError) -> SdpParserInternalError {
        SdpParserInternalError::Integer(err)
    }
}

impl From<AddrParseError> for SdpParserInternalError {
    fn from(err: AddrParseError) -> SdpParserInternalError {
        SdpParserInternalError::Address(err)
    }
}

#[test]
fn test_sdp_parser_error_line() {
    let line1 = SdpParserError::Line {
        error: SdpParserInternalError::Generic("test message".to_string()),
        line: "test line".to_string(),
        line_number: 13,
    };
    assert_eq!(format!("{}", line1),
               "Line error: test message in line(13): test line");
    assert_eq!(line1.description(), "test message");
    assert!(line1.cause().is_some());
}

#[test]
fn test_sdp_parser_error_unsupported() {
    let unsupported1 = SdpParserError::Unsupported {
        error: SdpParserInternalError::Generic("unsupported message".to_string()),
        line: None,
        line_number: None,
    };
    // TODO how to verify the output of fmt::Display() ?
    println!("{}", unsupported1);
    assert_eq!(unsupported1.description(), "unsupported message");
    assert!(unsupported1.cause().is_some());

    let unsupported2 = SdpParserError::Unsupported {
        error: SdpParserInternalError::Generic("unsupported message".to_string()),
        line: Some("unsupported line".to_string()),
        line_number: None,
    };
    // TODO how to verify the output of fmt::Display() ?
    println!("{}", unsupported2);
    assert_eq!(unsupported2.description(), "unsupported message");
    assert!(unsupported2.cause().is_some());

    let unsupported3 = SdpParserError::Unsupported {
        error: SdpParserInternalError::Generic("unsupported message".to_string()),
        line: None,
        line_number: Some(42),
    };
    // TODO how to verify the output of fmt::Display() ?
    println!("{}", unsupported3);
    assert_eq!(unsupported3.description(), "unsupported message");
    assert!(unsupported3.cause().is_some());

    let unsupported4 = SdpParserError::Unsupported {
        error: SdpParserInternalError::Generic("unsupported message".to_string()),
        line: Some("unsupported line".to_string()),
        line_number: Some(21),
    };
    // TODO how to verify the output of fmt::Display() ?
    println!("{}", unsupported4);
    assert_eq!(unsupported4.description(), "unsupported message");
    assert!(unsupported4.cause().is_some());
}

#[test]
fn test_sdp_parser_error_sequence() {
    let sequence1 = SdpParserError::Sequence {
        message: "sequence message".to_string(),
        line_number: 42,
    };
    assert_eq!(format!("{}", sequence1),
               "Sequence error in line(42): sequence message");
    assert_eq!(sequence1.description(), "sequence message");
    assert!(sequence1.cause().is_none());
}
