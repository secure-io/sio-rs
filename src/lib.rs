pub mod aead;

use self::aead::Algorithm;

use std::io;
use std::marker::PhantomData;

const MAX_BUF_SIZE: usize = (1 << 24) - 1;
const BUF_SIZE: usize = 1 << 14;

pub struct Stream<A: Algorithm> {
    algorithm: A,
    buf_size: usize,
}

impl<A: Algorithm> Stream<A> {
    pub fn new(algorithm: A, buf_size: usize) -> Stream<A> {
        Stream {
            algorithm: algorithm,
            buf_size: buf_size,
        }
    }

    pub fn nonce_len(&self) -> usize {
        self.algorithm.nonce_len() - 4
    }

    pub fn encrypt_writer<W: io::Write>(
        inner: W,
        nonce: Nonce<A>,
        associated_data: Aad,
    ) -> EncWriter<W> {
        EncWriter { inner: inner }
    }

    pub fn decrypt_writer<W: io::Write>(
        inner: W,
        nonce: Nonce<A>,
        associated_data: Aad,
    ) -> DecWriter<W> {
        DecWriter { inner: inner }
    }

    pub fn encrypt_reader<R: io::Read>(
        inner: R,
        nonce: Nonce<A>,
        associated_data: Aad,
    ) -> EncReader<R> {
        EncReader { inner: inner }
    }

    pub fn decrypt_reader<R: io::Read>(
        inner: R,
        nonce: Nonce<A>,
        associated_data: Aad,
    ) -> DecReader<R> {
        DecReader { inner: inner }
    }
}

pub struct Key<'a, A: Algorithm>(&'a [u8], PhantomData<A>);

impl<'a, A: Algorithm> Key<'a, A> {
    #[inline]
    pub fn from(key: &'a [u8]) -> Self {
        Key(key, PhantomData)
    }
}

pub struct Nonce<'a, A: Algorithm>(&'a [u8], PhantomData<A>);

impl<'a, A: Algorithm> Nonce<'a, A> {
    #[inline]
    pub fn from(nonce: &'a [u8]) -> Self {
        Nonce(nonce, PhantomData)
    }
}

pub struct Aad<'a>(&'a [u8]);

impl<'a> Aad<'a> {
    #[inline]
    pub fn from(associated_data: &'a [u8]) -> Self {
        Aad(associated_data)
    }
}

impl Aad<'static> {
    pub fn empty() -> Self {
        Self::from(&[])
    }
}

pub struct EncWriter<W: io::Write> {
    inner: W,
}

impl<W: io::Write> EncWriter<W> {
    pub fn new<A: Algorithm>(
        inner: W,
        algorithm: A,
        key: Key<A>,
        nonce: Nonce<A>,
        associated_data: Aad,
        buf_size: usize,
    ) -> Self {
        EncWriter { inner: inner }
    }
}

impl<W: io::Write> io::Write for EncWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct DecWriter<W: io::Write> {
    inner: W,
}

impl<W: io::Write> DecWriter<W> {
    pub fn new<A: Algorithm>(
        inner: W,
        algorithm: A,
        key: Key<A>,
        nonce: Nonce<A>,
        associated_data: Aad,
        buf_size: usize,
    ) -> Self {
        DecWriter { inner: inner }
    }
}

impl<W: io::Write> io::Write for DecWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct EncReader<R: io::Read> {
    inner: R,
}

impl<R: io::Read> EncReader<R> {
    pub fn new<A: Algorithm>(
        inner: R,
        algorithm: A,
        key: Key<A>,
        nonce: Nonce<A>,
        associated_data: Aad,
        buf_size: usize,
    ) -> Self {
        EncReader { inner: inner }
    }
}

impl<R: io::Read> io::Read for EncReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

pub struct DecReader<R: io::Read> {
    inner: R,
}

impl<R: io::Read> DecReader<R> {
    pub fn new<A: Algorithm>(
        inner: R,
        algorithm: A,
        key: Key<A>,
        nonce: Nonce<A>,
        associated_data: Aad,
        buf_size: usize,
    ) -> Self {
        DecReader { inner: inner }
    }
}

impl<R: io::Read> io::Read for DecReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
