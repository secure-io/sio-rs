use self::aead::Counter;
use std::io;
use std::io::Write;

pub use self::aead::{Aad, Algorithm, Key, Nonce};
pub use self::error::Invalid;

mod aead;
mod error;

#[cfg(feature = "ring")]
pub mod ring;

pub const MAX_BUF_SIZE: usize = (1 << 24) - 1;
pub const BUF_SIZE: usize = 1 << 14;

/// Wraps a writer and encrypts and authenticates everything written to it.
///
/// # Examples
///
/// Let's encrypt a string and store the ciphertext in memory:
///
/// ```
/// use std::io::{Write, Read, copy, repeat};
/// use sio::{Key, Nonce, Aad, EncWriter};
/// use sio::ring;
///
/// let key: Key<ring::AES_256_GCM> = Key::new([0; 32]);
/// let nonce = Nonce::new([0; 8]);
/// let aad = Aad::empty();
///
/// let mut plaintext = repeat('y' as u8).take(5);
/// let mut ciphertext: Vec<u8> = Vec::default();
/// let mut writer = EncWriter::new(ciphertext, &key, nonce, aad);
/// copy(&mut plaintext, &mut writer).and_then(|_| writer.flush()).unwrap();
/// ```
pub struct EncWriter<A: Algorithm, W: Write> {
    inner: W,
    algorithm: A,
    buffer: Vec<u8>,
    buf_size: usize,
    nonce: Counter<A>,
    aad: [u8; 16 + 1], // TODO: replace with [u8; A::TAG_LEN + 1]
    flushed: bool,
}

impl<A: Algorithm, W: Write> EncWriter<A, W> {
    pub fn new(inner: W, key: &Key<A>, nonce: Nonce<A>, aad: Aad) -> Self {
        Self::with_buffer_size(inner, key, nonce, aad, BUF_SIZE).unwrap()
    }

    pub fn with_buffer_size(
        inner: W,
        key: &Key<A>,
        nonce: Nonce<A>,
        aad: Aad,
        buf_size: usize,
    ) -> Result<Self, Invalid> {
        if buf_size == 0 || buf_size > MAX_BUF_SIZE {
            return Err(Invalid::BufSize);
        }
        let algorithm = A::new(key.as_ref());
        let mut nonce = Counter::zero(nonce);
        let mut associated_data = [0; 1 + 16];
        algorithm
            .seal_in_place(
                &nonce.next().unwrap(),
                aad.as_ref(),
                &mut associated_data[1..],
            )
            .unwrap();

        Ok(EncWriter {
            inner: inner,
            algorithm: A::new(key.as_ref()),
            buffer: Vec::with_capacity(buf_size + A::TAG_LEN),
            buf_size: buf_size,
            nonce: nonce,
            aad: associated_data,
            flushed: false,
        })
    }

    fn write_buffer(&mut self) -> io::Result<()> {
        self.buffer.resize(self.buffer.len() + A::TAG_LEN, 0);
        let ciphertext = self.algorithm.seal_in_place(
            &self.nonce.next()?,
            &self.aad,
            self.buffer.as_mut_slice(),
        )?;
        self.inner.write_all(ciphertext)?;
        self.buffer.clear();
        Ok(())
    }
}

impl<A: Algorithm, W: Write> Write for EncWriter<A, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.flushed {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        let n = buf.len();

        let remaining = self.buf_size - self.buffer.len();
        if buf.len() <= remaining {
            return self.buffer.write_all(buf).and(Ok(n));
        }

        self.buffer.extend_from_slice(&buf[..remaining]);
        self.write_buffer()?;

        let buf = &buf[remaining..];
        let chunks = buf.chunks(self.buf_size);
        chunks
            .clone()
            .take(chunks.len() - 1) // Since we take only n-1 elements...
            .try_for_each(|chunk| {
                self.buffer.extend_from_slice(chunk);
                self.write_buffer()
            })?;
        self.buffer.extend_from_slice(chunks.last().unwrap()); // ... there is always a last one.
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.flushed {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        self.flushed = true;
        self.aad[0] = 0x80;
        self.write_buffer().and_then(|()| self.inner.flush())
    }
}

pub struct DecWriter<A: Algorithm, W: Write> {
    inner: W,
    algorithm: A,
    buffer: Vec<u8>,
    buf_size: usize,
    nonce: Counter<A>,
    aad: [u8; 16 + 1], // TODO: replace with [u8; A::TAG_LEN + 1]
    flushed: bool,
}

impl<A: Algorithm, W: Write> DecWriter<A, W> {
    pub fn new(inner: W, key: &Key<A>, nonce: Nonce<A>, aad: Aad) -> Self {
        Self::with_buffer_size(inner, key, nonce, aad, BUF_SIZE).unwrap()
    }

    pub fn with_buffer_size(
        inner: W,
        key: &Key<A>,
        nonce: Nonce<A>,
        aad: Aad,
        buf_size: usize,
    ) -> Result<Self, Invalid> {
        if buf_size == 0 || buf_size > MAX_BUF_SIZE {
            return Err(Invalid::BufSize);
        }
        let algorithm = A::new(key.as_ref());
        let mut nonce = Counter::zero(nonce);
        let mut associated_data = [0; 1 + 16];
        algorithm
            .seal_in_place(
                &nonce.next().unwrap(),
                aad.as_ref(),
                &mut associated_data[1..],
            )
            .unwrap();

        Ok(DecWriter {
            inner: inner,
            algorithm: A::new(key.as_ref()),
            buffer: Vec::with_capacity(buf_size + A::TAG_LEN),
            buf_size: buf_size,
            nonce: nonce,
            aad: associated_data,
            flushed: false,
        })
    }

    fn write_buffer(&mut self) -> io::Result<()> {
        let plaintext = self.algorithm.open_in_place(
            &self.nonce.next()?,
            &self.aad,
            self.buffer.as_mut_slice(),
        )?;
        self.inner.write_all(plaintext)?;
        self.buffer.clear();
        Ok(())
    }
}

impl<A: Algorithm, W: Write> Write for DecWriter<A, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.flushed {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        let n = buf.len();

        let remaining = self.buf_size + A::TAG_LEN - self.buffer.len();
        if buf.len() <= remaining {
            return self.buffer.write_all(buf).and(Ok(n));
        }

        self.buffer.extend_from_slice(&buf[..remaining]);
        self.write_buffer()?;

        let buf = &buf[remaining..];
        let chunks = buf.chunks(self.buf_size + A::TAG_LEN);
        chunks
            .clone()
            .take(chunks.len() - 1) // Since we take only n-1 elements...
            .try_for_each(|chunk| {
                self.buffer.extend_from_slice(chunk);
                self.write_buffer()
            })?;
        self.buffer.extend_from_slice(chunks.last().unwrap()); // ... there is always a last one.
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.flushed {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        self.flushed = true;
        self.aad[0] = 0x80;
        self.write_buffer().and_then(|()| self.inner.flush())
    }
}

#[cfg(test)]
mod tests {
    use super::ring::AES_256_GCM;
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn test_it() {
        let key: Key<ring::AES_256_GCM> = Key::new([0; AES_256_GCM::KEY_LEN]);

        let enc_nonce = Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]);
        let dec_nonce = Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]);

        let dw =
            DecWriter::with_buffer_size(io::stdout(), &key, enc_nonce, Aad::empty(), 100).unwrap();
        let mut ew = EncWriter::with_buffer_size(dw, &key, dec_nonce, Aad::empty(), 100).unwrap();

        std::io::copy(&mut std::io::repeat('a' as u8).take(2000), &mut ew).unwrap();
        ew.flush().unwrap();
    }
}
