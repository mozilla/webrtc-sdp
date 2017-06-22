use std::num::ParseIntError;
use std::net::AddrParseError;
use std::fmt;
use std::error;

#[derive(Debug)]
pub enum SdpParserError {
    Line { message: String, line: String },
    Unsupported { message: String, line: String },
    Sequence {
        message: String,
        line: Option<usize>,
    },
    Integer(ParseIntError),
    Address(AddrParseError),
}

impl fmt::Display for SdpParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SdpParserError::Line {
                ref message,
                ref line,
            } => write!(f, "Line error: {} in line: {}", message, line),
            SdpParserError::Unsupported {
                ref message,
                ref line,
            } => write!(f, "Unsupported: {} in line: {}", message, line),
            SdpParserError::Sequence { ref message, .. } => {
                write!(f, "Sequence error: {}", message)
            }
            SdpParserError::Integer(ref err) => {
                write!(f,
                       "Integer parsing error: {}",
                       error::Error::description(err))
            }
            SdpParserError::Address(ref err) => {
                write!(f,
                       "IP address parsing error: {}",
                       error::Error::description(err))
            }
        }
    }
}

impl error::Error for SdpParserError {
    fn description(&self) -> &str {
        match *self {
            SdpParserError::Line { ref message, .. } |
            SdpParserError::Unsupported { ref message, .. } |
            SdpParserError::Sequence { ref message, .. } => message,
            SdpParserError::Integer(ref err) => error::Error::description(err),
            SdpParserError::Address(ref err) => error::Error::description(err),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            SdpParserError::Integer(ref err) => Some(err),
            SdpParserError::Address(ref err) => Some(err),
            // Can't tell much more about our internal errors
            _ => None,
        }
    }
}

impl From<ParseIntError> for SdpParserError {
    fn from(err: ParseIntError) -> SdpParserError {
        SdpParserError::Integer(err)
    }
}

impl From<AddrParseError> for SdpParserError {
    fn from(err: AddrParseError) -> SdpParserError {
        SdpParserError::Address(err)
    }
}
