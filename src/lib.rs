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
/// `EncWriter` splits data into fixed-size fragments and encrypts and
/// authenticates each fragment separately. It appends any remaining data
/// to its in-memory buffer until it has gathered a complete fragment.
/// Therefore, using an `std::io::BufWriter` in addition usually does not
/// improve the performance of write calls. The only exception may be cases
/// when the buffer size of the `BufWriter` is significantly larger than the
/// fragment size of the `EncWriter`.
///
/// When the `EncWriter` is dropped, any buffered content will be encrypted
/// as well as authenticated and written out. However, any errors that happen
/// in the process of flushing the buffer when the `EncWriter` is dropped will
/// be ignored. Therefore, code should call `close` explicitly to ensure that
/// all encrypted data has been written out successfully.
///
/// # Examples
///
/// Let's encrypt a string and store the ciphertext in memory:
///
/// ```
/// use std::io::{Write, Read};
/// use sio::{Key, Nonce, Aad, EncWriter};
/// use sio::ring::AES_256_GCM;
///
/// // Load your secret keys from a secure location or derive
/// // them using a secure (password-based) key-derivation-function, like Argon2id.
/// // Obviously, don't use this all-zeros key for anything real.
/// let key: Key<AES_256_GCM> = Key::new([0; Key::<AES_256_GCM>::SIZE]);
///
/// // Make sure you use an unique key-nonce combination!
/// // Reusing a nonce value for the same secret key breaks
/// // the security of the encryption algorithm.
/// let nonce = Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]);
///
/// // You must be able to re-generate this aad to decrypt
/// // the ciphertext again. Usually, it's stored together with
/// // the encrypted data.
/// let aad = Aad::from("Some authenticated but not encrypted data".as_bytes());
///
/// let mut plaintext = "Some example plaintext".as_bytes();
///
/// let mut ciphertext: Vec<u8> = Vec::default();  // Store the ciphertext in memory.
/// let mut writer = EncWriter::new(ciphertext, &key, nonce, aad);
///
/// writer.write_all(plaintext).unwrap();
/// writer.close().unwrap(); // Complete the encryption process explicitly.
/// ```
pub struct EncWriter<A: Algorithm, W: Write> {
    inner: W,
    algorithm: A,
    buffer: Vec<u8>,
    buf_size: usize,
    nonce: Counter<A>,
    aad: [u8; 16 + 1], // TODO: replace with [u8; A::TAG_LEN + 1]

    // If an error occurs, we must fail any subsequent write of flush operation.
    // If set to true, this flag tells the write and flush implementation to fail
    // immediately.
    errored: bool,

    // If `close` has been called explicitly, we must not try to close the
    // EncWriter again. This flag tells the Drop impl if it should skip the
    // close.
    closed: bool,

    // If the inner writer panics in a call to write, we don't want to
    // write the buffered data a second time in BufWriter's destructor. This
    // flag tells the Drop impl if it should skip the close.
    panicked: bool,
}

impl<A: Algorithm, W: Write> EncWriter<A, W> {
    /// Creates a new `EncWriter` with a default buffer size of 16 KiB.
    ///
    /// Anything written to the `EncWriter` gets encrypted and authenticated
    /// using the provided `key` and `nonce`. The `aad` is only authenticated
    /// and neither encrypted nor written to the `inner` writer.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Write, Read};
    /// use sio::{Key, Nonce, Aad, EncWriter};
    /// use sio::ring::AES_256_GCM;
    ///
    /// // Load your secret keys from a secure location or derive
    /// // them using a secure (password-based) key-derivation-function, like Argon2id.
    /// // Obviously, don't use this all-zeros key for anything real.
    /// let key: Key<AES_256_GCM> = Key::new([0; Key::<AES_256_GCM>::SIZE]);
    ///
    /// // Make sure you use an unique key-nonce combination!
    /// // Reusing a nonce value for the same secret key breaks
    /// // the security of the encryption algorithm.
    /// let nonce = Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]);
    ///
    /// // You must be able to re-generate this aad to decrypt
    /// // the ciphertext again. Usually, it's stored together with
    /// // the encrypted data.
    /// let aad = Aad::from("Some authenticated but not encrypted data".as_bytes());
    //////
    /// let mut ciphertext: Vec<u8> = Vec::default();  // Store the ciphertext in memory.
    /// let mut writer = EncWriter::new(ciphertext, &key, nonce, aad);
    ///
    /// // Perform some write and flush operations
    /// // ...
    ///
    /// writer.close().unwrap(); // Complete the encryption process explicitly.
    /// ```
    pub fn new(inner: W, key: &Key<A>, nonce: Nonce<A>, aad: Aad) -> Self {
        Self::with_buffer_size(inner, key, nonce, aad, BUF_SIZE).unwrap()
    }

    /// Creates a new `EncWriter` with the specified buffer size as fragment
    /// size. The `buf_size` must not be `0` nor greater than `MAX_BUF_SIZE`.
    ///
    /// Anything written to the `EncWriter` gets encrypted and authenticated
    /// using the provided `key` and `nonce`. The `aad` is only authenticated
    /// and neither encrypted nor written to the `inner` writer.
    ///
    /// It's important to always use the same buffer/fragment size for
    /// encrypting and decrypting. Trying to decrypt data that has been
    /// encrypted with a different fragment size will fail. Therefore,
    /// the buffer size is usually fixed for one (kind of) application.
    ///
    /// # Examples
    ///
    /// Creating an `EncWriter` with a fragment size of 64 KiB.
    ///
    /// ```
    /// use std::io::{Write, Read};
    /// use sio::{Key, Nonce, Aad, EncWriter};
    /// use sio::ring::AES_256_GCM;
    ///
    /// // Load your secret keys from a secure location or derive
    /// // them using a secure (password-based) key-derivation-function, like Argon2id.
    /// // Obviously, don't use this all-zeros key for anything real.
    /// let key: Key<AES_256_GCM> = Key::new([0; Key::<AES_256_GCM>::SIZE]);
    ///
    /// // Make sure you use an unique key-nonce combination!
    /// // Reusing a nonce value for the same secret key breaks
    /// // the security of the encryption algorithm.
    /// let nonce = Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]);
    ///
    /// // You must be able to re-generate this aad to decrypt
    /// // the ciphertext again. Usually, it's stored together with
    /// // the encrypted data.
    /// let aad = Aad::from("Some authenticated but not encrypted data".as_bytes());
    //////
    /// let mut ciphertext: Vec<u8> = Vec::default();  // Store the ciphertext in memory.
    /// let mut writer = EncWriter::with_buffer_size(ciphertext, &key, nonce, aad, 64 * 1024).unwrap();
    ///
    /// // Perform some write and flush operations
    /// // ...
    ///
    /// writer.close().unwrap(); // Complete the encryption process explicitly.
    /// ```
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
            errored: false,
            closed: false,
            panicked: false,
        })
    }

    /// Completes the encryption process, writes the last ciphertext
    /// fragment to the inner writer and ensures that all buffered
    /// contents reach their destination.
    pub fn close(mut self) -> io::Result<()> {
        self.close_internal()
    }

    fn close_internal(&mut self) -> io::Result<()> {
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        self.closed = true;
        self.aad[0] = 0x80; // For the last fragment change the AAD

        self.panicked = true;
        let r = self.write_buffer().and_then(|()| self.inner.flush());
        self.panicked = false;

        self.errored = r.is_err();
        r
    }

    // Encrypt and authenticate the buffer and write the ciphertext
    // to the inner writer.
    fn write_buffer(&mut self) -> io::Result<()> {
        self.buffer.resize(self.buffer.len() + A::TAG_LEN, 0);
        let ciphertext = self.algorithm.seal_in_place(
            &self.nonce.next()?,
            &self.aad,
            self.buffer.as_mut_slice(),
        )?;

        self.panicked = true;
        let r = self.inner.write_all(ciphertext);
        self.panicked = false;

        self.buffer.clear();
        r
    }
}

impl<A: Algorithm, W: Write> Write for EncWriter<A, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }

        let r: io::Result<usize> = {
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
        };
        self.errored = r.is_err();
        r
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write(buf).and(Ok(()))
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        self.panicked = true;
        let r = self.inner.flush();
        self.panicked = false;

        self.errored = r.is_err();
        r
    }
}

impl<A: Algorithm, W: Write> Drop for EncWriter<A, W> {
    fn drop(&mut self) {
        if !self.panicked && !self.closed {
            // dtors should not panic, so we ignore a failed close
            let _r = self.close_internal();
        }
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
    use std::io::Read;

    #[test]
    fn test_it() {
        let key: Key<ring::AES_256_GCM> = Key::new([0; AES_256_GCM::KEY_LEN]);

        let enc_nonce = Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]);
        let dec_nonce = Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]);

        let dw =
            DecWriter::with_buffer_size(io::stdout(), &key, enc_nonce, Aad::empty(), 100).unwrap();
        let mut ew = EncWriter::with_buffer_size(dw, &key, dec_nonce, Aad::empty(), 100).unwrap();

        std::io::copy(&mut std::io::repeat('a' as u8).take(2000), &mut ew).unwrap();
        ew.close().unwrap();
    }
}
