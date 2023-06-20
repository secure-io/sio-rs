// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

use super::{Aad, Algorithm, Invalid, Key, Nonce, BUF_SIZE, MAX_BUF_SIZE};
use std::io;
use std::io::Write;
use std::thread::panicking;

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
/// use std::io::Write;
/// use sio::{Key, Nonce, Aad, EncWriter, CHACHA20_POLY1305};
///
/// // Load your secret keys from a secure location or derive
/// // them using a secure (password-based) key-derivation-function, like Argon2id.
/// // Obviously, don't use this all-zeros key for anything real.
/// let key: Key<CHACHA20_POLY1305> = Key::new([0; Key::<CHACHA20_POLY1305>::SIZE]);
///
/// // Make sure you use an unique key-nonce combination!
/// // Reusing a nonce value for the same secret key breaks
/// // the security of the encryption algorithm.
/// let nonce = Nonce::new([0; Nonce::SIZE]);
///
/// // You must be able to re-generate this aad to decrypt
/// // the ciphertext again. Usually, it's stored together with
/// // the encrypted data.
/// let aad = Aad::from("Some authenticated but not encrypted data".as_bytes());
///
/// let plaintext = "Some example plaintext".as_bytes();
///
/// let mut ciphertext: Vec<u8> = Vec::default();  // Store the ciphertext in memory.
/// let mut writer = EncWriter::new(ciphertext, &key, nonce, aad);
///
/// writer.write_all(plaintext).unwrap();
/// writer.close().unwrap(); // Complete the encryption process explicitly.
/// ```
pub struct EncWriter<A: Algorithm, W: Write + internal::Close> {
    inner: W,
    algorithm: A,
    buffer: Vec<u8>,
    pos: usize,
    buf_size: usize,
    aad: [u8; 16 + 1], // TODO: replace with [u8; A::TAG_LEN + 1]

    // If an error occurs, we must fail any subsequent write of flush operation.
    // If set to true, this flag tells the write and flush implementation to fail
    // immediately.
    errored: bool,

    // If `close` has been called explicitly, we must not try to close the
    // EncWriter again. This flag tells the Drop impl if it should skip the
    // close.
    closed: bool,
}

impl<A: Algorithm, W: Write + internal::Close> EncWriter<A, W> {
    /// Creates a new `EncWriter` with a default buffer size of 16 KiB.
    ///
    /// Anything written to the `EncWriter` gets encrypted and authenticated
    /// using the provided `key` and `nonce`. The `aad` is only authenticated
    /// and neither encrypted nor written to the `inner` writer.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Write;
    /// use sio::{Key, Nonce, Aad, EncWriter, CHACHA20_POLY1305};
    ///
    /// // Load your secret keys from a secure location or derive
    /// // them using a secure (password-based) key-derivation-function, like Argon2id.
    /// // Obviously, don't use this all-zeros key for anything real.
    /// let key: Key<CHACHA20_POLY1305> = Key::new([0; Key::<CHACHA20_POLY1305>::SIZE]);
    ///
    /// // Make sure you use an unique key-nonce combination!
    /// // Reusing a nonce value for the same secret key breaks
    /// // the security of the encryption algorithm.
    /// let nonce = Nonce::new([0; Nonce::SIZE]);
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
    pub fn new(inner: W, key: &Key<A>, nonce: Nonce, aad: Aad<A>) -> Self {
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
    /// use std::io::Write;
    /// use sio::{Key, Nonce, Aad, EncWriter, CHACHA20_POLY1305};
    ///
    /// // Load your secret keys from a secure location or derive
    /// // them using a secure (password-based) key-derivation-function, like Argon2id.
    /// // Obviously, don't use this all-zeros key for anything real.
    /// let key: Key<CHACHA20_POLY1305> = Key::new([0; Key::<CHACHA20_POLY1305>::SIZE]);
    ///
    /// // Make sure you use an unique key-nonce combination!
    /// // Reusing a nonce value for the same secret key breaks
    /// // the security of the encryption algorithm.
    /// let nonce = Nonce::new([0; Nonce::SIZE]);
    ///
    /// // You must be able to re-generate this aad to decrypt
    /// // the ciphertext again. Usually, it's stored together with
    /// // the encrypted data.
    /// let aad = Aad::from("Some authenticated but not encrypted data".as_bytes());
    ///
    /// let mut ciphertext: Vec<u8> = Vec::default();  // Store the ciphertext in memory.
    /// let mut writer = EncWriter::with_buffer_size(
    ///     &mut ciphertext,
    ///     &key,
    ///     nonce,
    ///     aad,
    ///     64 * 1024,
    /// )
    /// .unwrap();
    ////
    /// // Perform some write and flush operations
    /// // ...
    ///
    /// writer.close().unwrap(); // Complete the encryption process explicitly.
    /// ```
    pub fn with_buffer_size(
        inner: W,
        key: &Key<A>,
        nonce: Nonce,
        aad: Aad<A>,
        buf_size: usize,
    ) -> Result<Self, Invalid> {
        if buf_size == 0 || buf_size > MAX_BUF_SIZE {
            return Err(Invalid::BufSize);
        }
        let mut algorithm = A::new(key.as_ref(), nonce);
        let mut associated_data = Default::default();
        algorithm
            .seal_in_place(aad.as_ref(), &mut associated_data)
            .unwrap();
        associated_data.insert(0, 0);

        Ok(EncWriter {
            inner,
            algorithm,
            buffer: vec![0; buf_size],
            pos: 0,
            buf_size,
            aad: associated_data.try_into().unwrap(),
            errored: false,
            closed: false,
        })
    }

    #[must_use = "An EncWriter must be closed to successfully complete the encryption process. Ignoring this result may cause incomplete ciphertext data."]
    #[inline(always)]
    pub fn close(mut self) -> io::Result<()> {
        internal::Close::close(&mut self)
    }

    #[inline(always)]
    pub fn closer(self) -> impl Write + Close {
        Closer::wrap(self)
    }

    /// Encrypt and authenticate the buffer and write the ciphertext
    /// to the inner writer.
    fn write_buffer(&mut self, len: usize) -> io::Result<()> {
        self.buffer.truncate(len);
        let ciphertext = match self.algorithm.seal_in_place(&self.aad, &mut self.buffer) {
            Ok(ciphertext) => ciphertext,
            Err(err) => {
                self.errored = true;
                return Err(err.into());
            }
        };

        match self.inner.write_all(ciphertext) {
            Ok(v) => Ok(v),
            Err(err) => {
                self.errored = true;
                Err(err)
            }
        }
    }
}

impl<A: Algorithm, W: Write + internal::Close> Write for EncWriter<A, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }

        let n = buf.len();
        let remaining = self.buf_size - self.pos;
        if n <= remaining {
            self.buffer[self.pos..self.pos + n].copy_from_slice(buf);
            self.pos += n;
            return Ok(n);
        }

        self.buffer[self.pos..self.buf_size].copy_from_slice(&buf[..remaining]);
        self.write_buffer(self.buf_size)?;
        self.pos = 0;
        let buf = &buf[remaining..];

        let chunks = buf.chunks(self.buf_size);
        chunks
            .clone()
            .take(chunks.len() - 1) // Since we take only n-1 elements...
            .try_for_each(|chunk| {
                self.buffer[..self.buf_size].copy_from_slice(chunk);
                self.write_buffer(self.buf_size)
            })?;

        let last = chunks.last().unwrap(); // ... thereis always a last one.
        self.buffer[..last.len()].copy_from_slice(last); // ... there is always a last one.
        self.pos = last.len();
        Ok(n)
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write(buf).and(Ok(()))
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        let r = self.inner.flush();
        self.errored = r.is_err();
        r
    }
}

impl<A: Algorithm, W: Write + internal::Close> internal::Close for EncWriter<A, W> {
    fn close(&mut self) -> io::Result<()> {
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        self.closed = true;
        self.aad[0] = 0x80; // For the last fragment change the AAD

        self.write_buffer(self.pos)
            .and_then(|()| self.inner.close())
    }
}

impl<A: Algorithm, W: Write + internal::Close> Drop for EncWriter<A, W> {
    fn drop(&mut self) {
        // We must not check whether the EncWriter has been closed if
        // we encountered an error during a write or flush call.
        if !self.errored && !self.closed {
            // We don't want to panic again if some code (between
            // EncWriter::new(...) and EncWriter.close()) already
            // panic'd. Otherwise we would cause a "double-panic".
            if !panicking() {
                panic!("EncWriter must be closed explicitly via the close method before being dropped!")
            }
        }
    }
}

/// Wraps a writer and decrypts and verifies everything written to it.
///
/// `DecWriter` splits data into fixed-size ciphertext fragments, produced
/// by `EncWriter`, and decrypts and verifies each fragment separately. It
/// appends any remaining data to its in-memory buffer until it has gathered
/// a complete ciphertext fragment. Therefore, using an `std::io::BufWriter`
/// in addition usually does not improve the performance of write calls. The
/// only exception may be cases when the buffer size of the `BufWriter` is
/// significantly larger than the fragment size of the `DecWriter`.
///
/// When the `DecWriter` is dropped, any buffered content will be decrypted
/// as well as verified and written out. However, any errors that happen
/// in the process of flushing the buffer when the `DecWriter` is dropped will
/// be ignored. This includes any error indicating that the ciphertext is not
/// authentic! Therefore, code should *always* call `close` explicitly to ensure
/// that all ciphertext as been decrypted, verified and written out successfully.
///
/// # Examples
///
/// Let's decrypt a string and store the plaintext in memory:
///
/// ```
/// use std::io::Write;
/// use sio::{Key, Nonce, Aad, DecWriter, CHACHA20_POLY1305};
///
/// // Load your secret keys from a secure location or derive
/// // them using a secure (password-based) key-derivation-function, like Argon2id.
/// // Obviously, don't use this all-zeros key for anything real.
/// let key: Key<CHACHA20_POLY1305> = Key::new([0; Key::<CHACHA20_POLY1305>::SIZE]);
///
/// // Use the same nonce that was used during encryption.
/// let nonce = Nonce::new([0; Nonce::SIZE]);
///
/// // Use the same associated data (AAD) that was used during encryption.
/// let aad = Aad::from("Some authenticated but not encrypted data".as_bytes());
///
/// let mut plaintext: Vec<u8> = Vec::default();  // Store the plaintext in memory.
/// let mut writer = DecWriter::new(&mut plaintext, &key, nonce, aad);
///
/// // Passing the ciphertext as raw bytes.
/// writer.write(&[17, 137, 205, 68, 28, 113, 101, 52, 193, 68, 213, 16, 104,
///                80, 203, 255, 183, 120, 46, 225, 192, 178, 253, 57, 67, 75,
///                53, 57, 45, 94]).unwrap();
///
/// writer.close().unwrap(); // Complete the decryption process explicitly!
///
/// println!("{}", String::from_utf8_lossy(plaintext.as_slice())); // Let's print the plaintext.
/// ```
pub struct DecWriter<A: Algorithm, W: Write + internal::Close> {
    inner: W,
    algorithm: A,
    buffer: Box<[u8]>,
    pos: usize,
    buf_size: usize,
    aad: [u8; 16 + 1], // TODO: replace with [u8; A::TAG_LEN + 1]

    // If an error occurs, we must fail any subsequent write of flush operation.
    // If set to true, this flag tells the write and flush implementation to fail
    // immediately.
    errored: bool,

    // If `close` has been called explicitly, we must not try to close the
    // EncWriter again. This flag tells the Drop impl if it should skip the
    // close.
    closed: bool,
}

impl<A: Algorithm, W: Write + internal::Close> DecWriter<A, W> {
    /// Creates a new `DecWriter` with a default buffer size of 16 KiB.
    ///
    /// Anything written to the `DecWriter` gets decrypted and verified
    /// using the provided `key` and `nonce`. The `aad` is only verified
    /// and neither decrypted nor written to the `inner` writer.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Write;
    /// use sio::{Key, Nonce, Aad, DecWriter, CHACHA20_POLY1305};
    ///
    /// // Load your secret keys from a secure location or derive
    /// // them using a secure (password-based) key-derivation-function, like Argon2id.
    /// // Obviously, don't use this all-zeros key for anything real.
    /// let key: Key<CHACHA20_POLY1305> = Key::new([0; Key::<CHACHA20_POLY1305>::SIZE]);
    ///
    /// // Use the same nonce that was used during encryption.
    /// let nonce = Nonce::new([0; Nonce::SIZE]);
    ///
    /// // Use the same associated data (AAD) that was used during encryption.
    /// let aad = Aad::from("Some authenticated but not encrypted data".as_bytes());
    ///
    /// let mut plaintext: Vec<u8> = Vec::default();  // Store the plaintext in memory.
    /// let mut writer = DecWriter::new(&mut plaintext, &key, nonce, aad);
    ///
    /// // Perform some write and flush operations
    /// // ...
    /// // For example:
    /// writer.write(&[17, 137, 205, 68, 28, 113, 101, 52, 193, 68, 213, 16, 104,
    ///                80, 203, 255, 183, 120, 46, 225, 192, 178, 253, 57, 67, 75,
    ///                53, 57, 45, 94]).unwrap();
    ///
    /// writer.close().unwrap(); // Complete the decryption process explicitly!
    ///
    /// println!("{}", String::from_utf8_lossy(plaintext.as_slice())); // Let's print the plaintext.
    /// ```
    pub fn new(inner: W, key: &Key<A>, nonce: Nonce, aad: Aad<A>) -> Self {
        Self::with_buffer_size(inner, key, nonce, aad, BUF_SIZE).unwrap()
    }

    /// Creates a new `DecWriter` with the specified buffer size as fragment
    /// size. The `buf_size` must not be `0` nor greater than `MAX_BUF_SIZE`
    /// and must match the buffer size used to encrypt the data.
    ///
    /// Anything written to the `DecWriter` gets decrypted and verified
    /// using the provided `key` and `nonce`. The `aad` is only verified
    /// and neither decrypted nor written to the `inner` writer.
    ///
    /// It's important to always use the same buffer/fragment size for
    /// encrypting and decrypting. Trying to decrypt data that has been
    /// encrypted with a different fragment size will fail. Therefore,
    /// the buffer size is usually fixed for one (kind of) application.
    ///
    /// # Examples
    ///
    /// Creating an `DecWriter` with a fragment size of 64 KiB.
    ///
    /// ```
    /// use std::io::Write;
    /// use sio::{Key, Nonce, Aad, DecWriter, CHACHA20_POLY1305};
    ///
    /// // Load your secret keys from a secure location or derive
    /// // them using a secure (password-based) key-derivation-function, like Argon2id.
    /// // Obviously, don't use this all-zeros key for anything real.
    /// let key: Key<CHACHA20_POLY1305> = Key::new([0; Key::<CHACHA20_POLY1305>::SIZE]);
    ///
    /// // Use the same nonce that was used for encryption.
    /// let nonce = Nonce::new([0; Nonce::SIZE]);
    ///
    /// // Use the same associated data (AAD) that was used for encryption.
    /// let aad = Aad::from("Some authenticated but not encrypted data".as_bytes());
    ///
    /// let mut plaintext: Vec<u8> = Vec::default();  // Store the plaintext in memory.
    /// let mut writer = DecWriter::with_buffer_size(
    ///     &mut plaintext,
    ///     &key,
    ///     nonce,
    ///     aad,
    ///     64 * 1024,
    /// )
    /// .unwrap();
    ///
    /// // Perform some write and flush operations
    /// // ...
    /// // For example:
    /// writer.write(&[17, 137, 205, 68, 28, 113, 101, 52, 193, 68, 213, 16, 104,
    ///                80, 203, 255, 183, 120, 46, 225, 192, 178, 253, 57, 67, 75,
    ///                53, 57, 45, 94]).unwrap();
    ///
    /// writer.close().unwrap(); // Complete the decryption process explicitly!
    ///
    /// println!("{}", String::from_utf8_lossy(plaintext.as_slice())); // Let's print the plaintext.
    /// ```
    pub fn with_buffer_size(
        inner: W,
        key: &Key<A>,
        nonce: Nonce,
        aad: Aad<A>,
        buf_size: usize,
    ) -> Result<Self, Invalid> {
        if buf_size == 0 || buf_size > MAX_BUF_SIZE {
            return Err(Invalid::BufSize);
        }
        let mut algorithm = A::new(key.as_ref(), nonce);
        let mut associated_data = Vec::with_capacity(16 + 1);
        algorithm
            .seal_in_place(aad.as_ref(), &mut associated_data)
            .unwrap();
        associated_data.insert(0, 0);

        Ok(DecWriter {
            inner,
            algorithm,
            buffer: vec![0; buf_size + A::TAG_LEN].into_boxed_slice(),
            pos: 0,
            buf_size,
            aad: associated_data.try_into().unwrap(),
            errored: false,
            closed: false,
        })
    }

    #[must_use = "A DecWriter must be closed to successfully complete the decryption process. Ignoring this result may cause incomplete plaintext data."]
    #[inline(always)]
    pub fn close(mut self) -> io::Result<()> {
        internal::Close::close(&mut self)
    }

    #[inline(always)]
    pub fn closer(self) -> impl Write + Close {
        Closer::wrap(self)
    }

    /// Decrypt and verifies the buffer and write the plaintext
    /// to the inner writer.
    fn write_buffer(&mut self, len: usize) -> io::Result<()> {
        let plaintext = match self
            .algorithm
            .open_in_place(&self.aad, &mut self.buffer[..len])
        {
            Ok(plaintext) => plaintext,
            Err(err) => {
                self.errored = true;
                return Err(err.into());
            }
        };

        match self.inner.write_all(plaintext) {
            Ok(v) => Ok(v),
            Err(err) => {
                self.errored = true;
                Err(err)
            }
        }
    }
}

impl<A: Algorithm, W: Write + internal::Close> Write for DecWriter<A, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }

        let n = buf.len();
        let remaining = self.buf_size + A::TAG_LEN - self.pos;
        if n <= remaining {
            self.buffer[self.pos..self.pos + n].copy_from_slice(buf);
            self.pos += n;
            return Ok(n);
        }

        self.buffer[self.pos..].copy_from_slice(&buf[..remaining]);
        self.write_buffer(self.buf_size + A::TAG_LEN)?;
        self.pos = 0;
        let buf = &buf[remaining..];

        let chunks = buf.chunks(self.buf_size + A::TAG_LEN);
        chunks
            .clone()
            .take(chunks.len() - 1) // Since we take only n-1 elements...
            .try_for_each(|chunk| {
                self.buffer.copy_from_slice(chunk);
                self.write_buffer(self.buf_size + A::TAG_LEN)
            })?;

        let last = chunks.last().unwrap(); // ... there is always a last one.
        self.buffer[..last.len()].copy_from_slice(last);
        self.pos = last.len();
        Ok(n)
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write(buf).and(Ok(()))
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        let r = self.inner.flush();
        self.errored = r.is_err();
        r
    }
}

impl<A: Algorithm, W: Write + internal::Close> internal::Close for DecWriter<A, W> {
    fn close(&mut self) -> io::Result<()> {
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        self.closed = true;
        self.aad[0] = 0x80; // For the last fragment change the AAD

        self.write_buffer(self.pos)
            .and_then(|()| self.inner.close())
    }
}

impl<A: Algorithm, W: Write + internal::Close> Drop for DecWriter<A, W> {
    fn drop(&mut self) {
        // We must not check whether the DecWriter has been closed if
        // we encountered an error during a write or flush call.
        if !self.errored && !self.closed {
            // We don't want to panic again if some code (between
            // DecWriter::new(...) and DecWriter.close()) already
            // panic'd. Otherwise we would cause a "double-panic".
            if !panicking() {
                panic!("DecWriter must be closed explicitly via the close method before being dropped!")
            }
        }
    }
}

mod internal {
    pub trait Close {
        fn close(&mut self) -> std::io::Result<()>;
    }
}

/// A trait implemented by objects that should be closed before they are dropped.
/// Any writer that should be wrapped by `EncWriter` or `DecWriter` must implement
/// this trait.
///
/// Implementations of `Close` should be composable such that closing the outer
/// object triggers its cleanup logic and then, if successful, invokes the `close`
/// method of the inner object. Therefore, closing any object within a chain
/// of objects should trigger a `close` of the object one hierarchy-level further
/// down.
///
/// In general, `close` should only be called once. If `close` returns an error callers
/// must not assume anything about the state of the object. The behavior of further `close`
/// calls is implementation-dependent. In any case, callers must not try to modifed the state
/// of the `Close` implementation after calling `close` once. Doing so is a logical error and
/// implementations may `panic` in this case.
///
/// # Relation between `Close` and `EncWriter` / `DecWriter`.
///
/// Both, `EncWriter` and `DecWriter`, **must** be closed to complete the encryption /
/// decryption process and handle any error that might occur when processing remaining data.
/// If an `EncWriter` or `DecWriter` gets dropped before being closed (and no `write` error
/// has occurred before) then dropping it will panic. Not closing an `EncWriter` produces
/// ciphertext data that cannot be decrypted reliably. Even worse, not closing a `DecWriter`,
/// produces incomplete, and therefore, not authentic plaintext data. Therefore, not closing
/// these writers is a security-critical and logical error.
///
/// However, `EncWriter` as well as `DecWriter` don't implement `Close` directly. Instead, both
/// provide a separate `close` method that takes ownership of the writer, and therefore,
/// ensures that the `EncWriter` / `DecWriter` is not used later on through Rust's
/// ownership system. In particular, this prevents e.g. write-after-close bugs at compile
/// time. However, you may need to opt-out of this guarantees in certain situations - in
/// particular when composing more than one `EncWriter` / `DecWriter` with other `Write`
/// implementations. For example, when inserting a `std::io::BufWriter` between two `EncWriter`s.
/// Then you need to convert the inner `EncWriter` into a type that implements `Close`. Otherwise,
/// you will get a compiler error indicating that the `Close` trait-bound is not satisfied when
/// calling the `close` method of the outer `EncWriter`. You can achieve this by calling the
/// `closer` method.
/// ```
/// use sio::{Aad, EncWriter, Key, Nonce, CHACHA20_POLY1305};
/// use std::io;
///
/// fn main() -> io::Result<()> {
///    let outer_key: Key<CHACHA20_POLY1305> = Key::new([0; Key::<CHACHA20_POLY1305>::SIZE]);
///    let inner_key: Key<CHACHA20_POLY1305> = Key::new([1; Key::<CHACHA20_POLY1305>::SIZE]);
///
///    let writer = EncWriter::new(
///        io::BufWriter::new(EncWriter::new(
///            io::sink(),
///            &inner_key,
///            Nonce::new([0; Nonce::SIZE]),
///            Aad::empty(),
///        ).closer() // Without this `closer` call the code would not compile.
///        ),
///        &outer_key,
///        Nonce::new([0; Nonce::SIZE]),
///        Aad::empty(),
///    );
///
///    writer.close()
/// }
/// ```
/// By calling `closer` you get an implementation of `Close` that preserves the
/// "no write-after-close" guarantee of `EncWriter` / `DecWriter` using runtime
/// checks. In particular, trying to perform a write after calling close once
/// causes a panic. Therefore, you should use `closer` with caution and only when
/// really needed.
pub trait Close {
    fn close(&mut self) -> io::Result<()>;
}

impl<T: Close + ?Sized> internal::Close for T {
    #[inline(always)]
    fn close(&mut self) -> io::Result<()> {
        Close::close(self)
    }
}

struct Closer<W: Write + internal::Close> {
    inner: W,
    closed: bool,
    errored: bool,
}

impl<W: Write + internal::Close> Closer<W> {
    #[inline(always)]
    pub fn wrap(inner: W) -> Self {
        Self {
            inner,
            closed: false,
            errored: false,
        }
    }
}

impl<W: Write + internal::Close> Write for Closer<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            panic!("write must not be called after close");
        }
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        match self.inner.write(buf) {
            Ok(n) => Ok(n),
            Err(val) => {
                self.errored = true;
                Err(val)
            }
        }
    }

    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write + internal::Close> Close for Closer<W> {
    #[inline]
    fn close(&mut self) -> io::Result<()> {
        if self.errored {
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        if self.closed {
            Ok(())
        } else {
            self.closed = true;
            let r = internal::Close::close(&mut self.inner);
            self.errored = r.is_err();
            r
        }
    }
}
