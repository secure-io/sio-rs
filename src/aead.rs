use super::error::{Exceeded, Invalid, NotAuthentic};
use std::marker::PhantomData;

pub trait Algorithm {
    const KEY_LEN: usize;
    const NONCE_LEN: usize;
    const TAG_LEN: usize;

    fn new(key: &[u8; 32]) -> Self;

    fn seal_in_place<'a>(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        in_out: &'a mut [u8],
    ) -> Result<&'a [u8], Invalid>;

    fn open_in_place<'a>(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        in_out: &'a mut [u8],
    ) -> Result<&'a [u8], NotAuthentic>;
}

pub struct Key<A: Algorithm>([u8; 32], PhantomData<A>);

impl<A: Algorithm> Key<A> {
    pub const SIZE: usize = A::KEY_LEN;

    pub fn new(bytes: [u8; 32]) -> Self {
        Key(bytes, PhantomData)
    }
}

impl<A: Algorithm> AsRef<[u8; 32]> for Key<A> {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct Nonce<A: Algorithm>([u8; 8], PhantomData<A>);

impl<A: Algorithm> Nonce<A> {
    pub const SIZE: usize = A::NONCE_LEN - 4;

    pub fn new(bytes: [u8; 8]) -> Self {
        Nonce(bytes, PhantomData)
    }
}

impl<A: Algorithm> AsRef<[u8; 8]> for Nonce<A> {
    fn as_ref(&self) -> &[u8; 8] {
        &self.0
    }
}

#[repr(transparent)]
pub struct Aad<'a>(&'a [u8]);

impl<'a> Aad<'a> {
    #[inline]
    pub const fn from(aad: &'a [u8]) -> Self {
        Aad(aad)
    }
}

impl Aad<'static> {
    #[inline]
    pub fn empty() -> Self {
        Self::from(&[])
    }
}

impl<'a> AsRef<[u8]> for Aad<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) struct Counter<A: Algorithm> {
    nonce: [u8; 8],
    seq_num: u32,
    phantom_data: PhantomData<A>,
}

impl<A: Algorithm> Counter<A> {
    pub fn zero(nonce: Nonce<A>) -> Self {
        Counter {
            nonce: nonce.0,
            seq_num: 0,
            phantom_data: PhantomData,
        }
    }

    pub fn next(&mut self) -> Result<[u8; 12], Exceeded> {
        let seq_num = self.seq_num.checked_add(1).ok_or(Exceeded)?;

        let mut nonce = [0; 12];
        &nonce[..8].copy_from_slice(self.nonce.as_ref());
        nonce[8..].copy_from_slice(self.seq_num.to_le_bytes().as_ref());
        self.seq_num = seq_num;
        Ok(nonce)
    }
}
