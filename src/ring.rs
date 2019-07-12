// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

extern crate ring;

use super::aead::Algorithm;
use super::error::{Invalid, NotAuthentic};
use ring::aead;

#[allow(non_camel_case_types)]
pub struct AES_256_GCM {
    seal_key: aead::SealingKey,
    open_key: aead::OpeningKey,
}

impl Algorithm for AES_256_GCM {
    const KEY_LEN: usize = 256 / 8;
    const NONCE_LEN: usize = 96 / 8;
    const TAG_LEN: usize = 128 / 8;

    fn new(key: &[u8; Self::KEY_LEN]) -> Self {
        Self {
            seal_key: aead::SealingKey::new(&aead::AES_256_GCM, key).unwrap(),
            open_key: aead::OpeningKey::new(&aead::AES_256_GCM, key).unwrap(),
        }
    }

    fn seal_in_place<'a>(
        &self,
        nonce: &[u8; Self::NONCE_LEN],
        aad: &[u8],
        in_out: &'a mut [u8],
    ) -> Result<&'a [u8], Invalid> {
        match aead::seal_in_place(
            &self.seal_key,
            aead::Nonce::assume_unique_for_key(*nonce),
            aead::Aad::from(aad),
            in_out,
            Self::TAG_LEN,
        ) {
            Ok(len) => Ok(&in_out[..len]),
            Err(_) => Err(Invalid::BufSize),
        }
    }

    fn open_in_place<'a>(
        &self,
        nonce: &[u8; Self::NONCE_LEN],
        aad: &[u8],
        in_out: &'a mut [u8],
    ) -> Result<&'a [u8], NotAuthentic> {
        match aead::open_in_place(
            &self.open_key,
            aead::Nonce::assume_unique_for_key(*nonce),
            aead::Aad::from(aad),
            0,
            in_out,
        ) {
            Ok(val) => Ok(val),
            Err(_) => Err(NotAuthentic),
        }
    }
}

#[allow(non_camel_case_types)]
pub struct CHACHA20_POLY1305 {
    seal_key: aead::SealingKey,
    open_key: aead::OpeningKey,
}

impl Algorithm for CHACHA20_POLY1305 {
    const KEY_LEN: usize = 256 / 8;
    const NONCE_LEN: usize = 96 / 8;
    const TAG_LEN: usize = 128 / 8;

    fn new(key: &[u8; Self::KEY_LEN]) -> Self {
        Self {
            seal_key: aead::SealingKey::new(&aead::CHACHA20_POLY1305, key).unwrap(),
            open_key: aead::OpeningKey::new(&aead::CHACHA20_POLY1305, key).unwrap(),
        }
    }

    fn seal_in_place<'a>(
        &self,
        nonce: &[u8; Self::NONCE_LEN],
        aad: &[u8],
        in_out: &'a mut [u8],
    ) -> Result<&'a [u8], Invalid> {
        match aead::seal_in_place(
            &self.seal_key,
            aead::Nonce::assume_unique_for_key(*nonce),
            aead::Aad::from(aad),
            in_out,
            Self::TAG_LEN,
        ) {
            Ok(len) => Ok(&in_out[..len]),
            Err(_) => Err(Invalid::BufSize),
        }
    }

    fn open_in_place<'a>(
        &self,
        nonce: &[u8; Self::NONCE_LEN],
        aad: &[u8],
        in_out: &'a mut [u8],
    ) -> Result<&'a [u8], NotAuthentic> {
        match aead::open_in_place(
            &self.open_key,
            aead::Nonce::assume_unique_for_key(*nonce),
            aead::Aad::from(aad),
            0,
            in_out,
        ) {
            Ok(val) => Ok(val),
            Err(_) => Err(NotAuthentic),
        }
    }
}
