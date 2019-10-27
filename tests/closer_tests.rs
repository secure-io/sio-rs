// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

use sio::*;
use std::{io, io::Write};

#[cfg(feature = "aesgcm")]
type AEAD = AES_256_GCM;

#[cfg(not(feature = "aesgcm"))]
type AEAD = CHACHA20_POLY1305;

struct BadSink;

impl io::Write for BadSink {
    fn write(&mut self, _b: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Other))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Other))
    }
}

impl Close for BadSink {
    fn close(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Other))
    }
}

#[test]
#[should_panic]
fn enc_writer_missing_close() {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let _ = EncWriter::new(
        Vec::default(),
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
}

#[test]
#[should_panic]
fn enc_writer_missing_close_after_write() {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = EncWriter::new(
        Vec::default(),
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
    let _ = writer.write_all(b"Hello World");
}

#[test]
fn enc_writer_missing_close_after_error() {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = EncWriter::new(
        BadSink,
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
    let _ = writer.write_all(&[0; BUF_SIZE + 1]);
}

#[test]
#[should_panic]
fn enc_writer_missing_close_after_panic() {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let _ = EncWriter::new(
        Vec::default(),
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
    panic!();
}

#[test]
#[should_panic]
fn dec_writer_missing_close() {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let _ = DecWriter::new(
        Vec::default(),
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
}

#[test]
#[should_panic]
fn dec_writer_missing_close_after_write() {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = DecWriter::new(
        Vec::default(),
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
    let _ = writer.write_all(b"Hello World");
}

#[test]
fn dec_writer_missing_close_after_error() {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = DecWriter::new(
        io::sink(),
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
    let _ = writer.write_all(&[0; BUF_SIZE + AEAD::TAG_LEN + 1]);
}

#[test]
#[should_panic]
fn dec_writer_missing_close_after_panic() {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let _ = DecWriter::new(
        Vec::default(),
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
    panic!();
}
