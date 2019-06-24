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

#[cfg(test)]
mod tests {

    use super::ring::AES_256_GCM;
    use super::*;
    use std::io::Write;

    #[test]
    fn test_it2() {
        let key: Key<ring::AES_256_GCM> = Key::new([0; AES_256_GCM::KEY_LEN]);

        let nonce = Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]);

        let aad = Aad::from("Some authenticated but not encrypted data".as_bytes());
        let plaintext = "".as_bytes();
        let mut ciphertext: Vec<u8> = Vec::default(); // Store the ciphertext in memory.
        let mut writer = EncWriter::new(&mut ciphertext, &key, nonce, aad);

        writer.write_all(plaintext).unwrap();
        writer.close().unwrap(); // Complete the encryption process explicitly.

        println!("{:?}", ciphertext);
    }

}
