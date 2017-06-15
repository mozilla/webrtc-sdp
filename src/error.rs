use std::num::ParseIntError;

#[derive(Debug)]
pub enum SdpParserError {
    ParserLineError { message: String, line: String },
    ParserUnsupported { message: String, line: String },
    ParserSequence {
        message: String,
        line: Option<usize>,
    },
}

impl From<ParseIntError> for SdpParserError {
    fn from(_: ParseIntError) -> Self {
        // TODO empty line error here makes no sense
        SdpParserError::ParserLineError {
            message: "failed to parse integer".to_string(),
            line: "".to_string(),
        }
    }
}
