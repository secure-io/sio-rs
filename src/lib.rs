pub use self::aead::{Aad, Algorithm, Key, Nonce};
pub use self::error::{Invalid, NotAuthentic};
pub use self::writer::{Close, DecWriter, EncWriter};

mod aead;
mod error;
mod writer;

#[cfg(feature = "ring")]
pub mod ring;

pub const MAX_BUF_SIZE: usize = (1 << 24) - 1;
pub const BUF_SIZE: usize = 1 << 14;
