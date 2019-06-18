use std::error::Error;
use std::{fmt, io};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NotAuthentic;

impl NotAuthentic {
    const fn description() -> &'static str {
        "not authentic"
    }
}

impl Error for NotAuthentic {
    fn description(&self) -> &str {
        Self::description()
    }
}

impl fmt::Display for NotAuthentic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::description())
    }
}

impl From<NotAuthentic> for io::Error {
    fn from(_: NotAuthentic) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, NotAuthentic)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Exceeded;

impl Exceeded {
    const fn description() -> &'static str {
        "data limit exceeded"
    }
}

impl Error for Exceeded {
    fn description(&self) -> &str {
        Self::description()
    }
}

impl fmt::Display for Exceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::description())
    }
}

impl From<Exceeded> for io::Error {
    fn from(_: Exceeded) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, Exceeded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Invalid {
    Key,
    Nonce,
    BufSize,
}

impl Error for Invalid {
    fn description(&self) -> &str {
        match self {
            Invalid::Key => "sio::Invalid::Key",
            Invalid::Nonce => "sio::Invalid::Nonce",
            Invalid::BufSize => "sio::Invalid::BufSize",
        }
    }
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl From<Invalid> for io::Error {
    fn from(e: Invalid) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}
