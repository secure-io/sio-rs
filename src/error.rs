// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

use std::{error::Error, fmt, io};

/// An error indicating that the encrypted data is not authentic - e.g.
/// malisously modified.
///
/// It happens whenever the decryption of some ciphertext fails.
#[derive(Clone, Copy, PartialEq)]
pub struct NotAuthentic;

impl NotAuthentic {
    const fn description() -> &'static str {
        "data is not authentic"
    }
}

impl Error for NotAuthentic {
    #[inline]
    fn description(&self) -> &str {
        Self::description()
    }
}

impl fmt::Debug for NotAuthentic {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", Self::description())
    }
}

impl fmt::Display for NotAuthentic {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::description())
    }
}

impl From<NotAuthentic> for io::Error {
    #[inline]
    fn from(_: NotAuthentic) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, NotAuthentic)
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct Exceeded;

impl Exceeded {
    const fn description() -> &'static str {
        "data limit exceeded"
    }
}

impl Error for Exceeded {
    #[inline]
    fn description(&self) -> &str {
        Self::description()
    }
}

impl fmt::Display for Exceeded {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::description())
    }
}

impl fmt::Debug for Exceeded {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::description())
    }
}

impl From<Exceeded> for io::Error {
    #[inline]
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
