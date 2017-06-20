use std::num::ParseIntError;
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
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            SdpParserError::Integer(ref err) => Some(err),
            // TODO is None really the right thing for our own errors?
            _ => None,
        }
    }
}

impl From<ParseIntError> for SdpParserError {
    fn from(err: ParseIntError) -> SdpParserError {
        SdpParserError::Integer(err)
    }
}
