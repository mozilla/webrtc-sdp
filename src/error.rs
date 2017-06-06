use std::num::ParseIntError;

#[derive(Debug)]
pub enum SdpParserResult {
    ParserLineError { message: String, line: String },
    ParserUnsupported { message: String, line: String },
    ParserSequence {
        message: String,
        line: Option<usize>,
    },
}

impl From<ParseIntError> for SdpParserResult {
    fn from(_: ParseIntError) -> SdpParserResult {
        // TODO empty line error here makes no sense
        SdpParserResult::ParserLineError {
            message: "failed to parse integer".to_string(),
            line: "".to_string(),
        }
    }
}
