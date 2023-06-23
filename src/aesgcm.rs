// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

extern crate ring;

use crate::aead::{Algorithm, Counter};
use crate::error::{Invalid, NotAuthentic};
use crate::Nonce;
use ring::aead::{self, BoundKey};

#[allow(non_camel_case_types)]
pub struct AES_256_GCM {
    seal_key: aead::SealingKey<Counter>,
    open_key: aead::OpeningKey<Counter>,
}

impl Algorithm for AES_256_GCM {
    const KEY_LEN: usize = 256 / 8;
    const NONCE_LEN: usize = 96 / 8;
    const TAG_LEN: usize = 128 / 8;

    fn new(key: &[u8; Self::KEY_LEN], nonce: Nonce) -> Self {
        Self {
            seal_key: aead::SealingKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, key).unwrap(),
                Counter::zero(nonce),
            ),
            open_key: aead::OpeningKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, key).unwrap(),
                Counter::one(nonce),
            ),
        }
    }

    fn seal_in_place<'a>(
        &mut self,
        aad: &[u8],
        in_out: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], Invalid> {
        match self
            .seal_key
            .seal_in_place_append_tag(aead::Aad::from(aad), in_out)
        {
            Ok(()) => Ok(in_out.as_slice()),
            Err(_) => Err(Invalid::BufSize),
        }
    }

    fn open_in_place<'a>(
        &mut self,
        aad: &[u8],
        in_out: &'a mut [u8],
    ) -> Result<&'a [u8], NotAuthentic> {
        match self.open_key.open_in_place(aead::Aad::from(aad), in_out) {
            Ok(val) => Ok(val),
            Err(_) => Err(NotAuthentic),
        }
    }
}
