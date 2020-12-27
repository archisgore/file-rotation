use std::fmt;
use std::fmt::{Debug, Formatter, Result as FmtResult};

#[derive(Debug)]
pub enum Error {
    ZeroBytes,
    ZeroLines,
    StdIoError(std::io::Error),
}

impl std::error::Error for Error {}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "FileRotateError:: {}",
            match self {
                Self::ZeroBytes => "Please specify number of bytes > 0.".to_owned(),
                Self::ZeroLines => "Please specify number of lines > 0.".to_owned(),
                Self::StdIoError(e) => format!("std::io::Error: {}", e),
            }
        )
    }
}
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::StdIoError(err)
    }
}
