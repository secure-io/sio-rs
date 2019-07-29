use super::writer::Close;
use std::io;
use std::io::Write;

impl<T: Close + ?Sized> Close for &mut T {
    #[inline(always)]
    fn close(&mut self) -> io::Result<()> {
        Close::close(*self)
    }
}

impl Close for Vec<u8> {
    #[inline(always)]
    fn close(&mut self) -> io::Result<()> {
        self.flush()
    }
}

impl Close for io::Sink {
    #[inline(always)]
    fn close(&mut self) -> io::Result<()> {
        self.flush()
    }
}

impl<W: Close + ?Sized> Close for Box<W> {
    #[inline(always)]
    fn close(&mut self) -> io::Result<()> {
        self.as_mut().close()
    }
}

impl<W: Write + Close> Close for io::BufWriter<W> {
    #[inline]
    fn close(&mut self) -> io::Result<()> {
        self.flush().and_then(|_| self.get_mut().close())
    }
}

impl<W: Write + Close> Close for io::LineWriter<W> {
    #[inline]
    fn close(&mut self) -> io::Result<()> {
        self.flush().and_then(|_| self.get_mut().close())
    }
}

/// NopCloser wraps a writer and implements the `Close` trait by
/// performing a `flush` when the `close` method is called. It should
/// only be used to wrap a writer which does not implement the `Close`
/// trait.
///
/// # Examples
///
/// ```
/// use std::{io, io::Write};
/// use sio::{Key, Nonce, Aad, EncWriter, AES_256_GCM, NopCloser};
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
/// let plaintext = "Some example plaintext".as_bytes();
///
/// let mut ciphertext: Vec<u8> = Vec::default();  // Store the ciphertext in memory.
/// let mut writer = EncWriter::new(
///         NopCloser::wrap(io::stdout()), // Without wrapping STDOUT the code would not compile.
///         &key,
///         nonce,
///         aad,
/// );
///
/// writer.write_all(plaintext).expect("There could be your error handling");
///
/// // Complete the encryption process explicitly.
/// writer.close().expect("There could be your error handling");
/// ```
pub struct NopCloser<W: Write>(W);

impl<W: Write> NopCloser<W> {
    /// Wraps a writer.
    #[inline(always)]
    pub fn wrap(w: W) -> Self {
        Self(w)
    }
}

impl<W: Write> From<W> for NopCloser<W> {
    #[inline(always)]
    fn from(w: W) -> Self {
        Self::wrap(w)
    }
}

impl<W: Write> Write for NopCloser<W> {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<W: Write> Close for NopCloser<W> {
    #[inline(always)]
    fn close(&mut self) -> io::Result<()> {
        self.flush()
    }
}

impl<W: Write> AsRef<W> for NopCloser<W> {
    #[inline(always)]
    fn as_ref(&self) -> &W {
        &self.0
    }
}

impl<W: Write> AsMut<W> for NopCloser<W> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut W {
        &mut self.0
    }
}
