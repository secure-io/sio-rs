// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

#![feature(test)]

use sio::*;
use std::{io, io::Write};

extern crate test;
use test::Bencher;

#[allow(clippy::upper_case_acronyms)]
#[cfg(feature = "aesgcm")]
type AEAD = AES_256_GCM;

#[allow(clippy::upper_case_acronyms)]
#[cfg(not(feature = "aesgcm"))]
type AEAD = CHACHA20_POLY1305;

fn buffer_size() -> usize {
    const BUFFER_SIZE: &str = "SIO_BUF_SIZE";
    if let Ok(value) = std::env::var(BUFFER_SIZE) {
        let value: usize = value
            .as_str()
            .parse()
            .expect(format!("'{}' is not a number", BUFFER_SIZE).as_str());
        1024 * value
    } else {
        sio::BUF_SIZE
    }
}

#[bench]
fn encrypt_write_1k(b: &mut Bencher) -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = EncWriter::with_buffer_size(
        io::sink(),
        &key,
        Nonce::new([0; Nonce::SIZE]),
        Aad::empty(),
        buffer_size(),
    )
    .expect("Failed to create EncWriter");

    let buf: &[u8] = &[0; 1 * 1024];
    b.bytes = 1 * 1024;
    b.iter(|| {
        writer.write_all(buf).expect("encryption failed");
    });
    writer.close()
}

#[bench]
fn encrypt_write_64k(b: &mut Bencher) -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = EncWriter::with_buffer_size(
        io::sink(),
        &key,
        Nonce::new([0; Nonce::SIZE]),
        Aad::empty(),
        buffer_size(),
    )
    .expect("Failed to create EncWriter");

    let buf: &[u8] = &[0; 64 * 1024];
    b.bytes = 64 * 1024;
    b.iter(|| {
        writer.write_all(buf).expect("encryption failed");
    });
    writer.close()
}

#[bench]
fn encrypt_write_512k(b: &mut Bencher) -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = EncWriter::with_buffer_size(
        io::sink(),
        &key,
        Nonce::new([0; Nonce::SIZE]),
        Aad::empty(),
        buffer_size(),
    )
    .expect("Failed to create EncWriter");

    let buf: &[u8] = &[0; 512 * 1024];
    b.bytes = 512 * 1024;
    b.iter(|| {
        writer.write_all(buf).expect("encryption failed");
    });
    writer.close()
}

#[bench]
fn encrypt_write_1mb(b: &mut Bencher) -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = EncWriter::with_buffer_size(
        io::sink(),
        &key,
        Nonce::new([0; Nonce::SIZE]),
        Aad::empty(),
        buffer_size(),
    )
    .expect("Failed to create EncWriter");

    let buf: &[u8] = &[0; 1024 * 1024];
    b.bytes = 1024 * 1024;
    b.iter(|| {
        writer.write_all(buf).expect("encryption failed");
    });
    writer.close()
}

#[bench]
fn decrypt_write_1k(b: &mut Bencher) -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = EncWriter::with_buffer_size(
        DecWriter::with_buffer_size(
            io::sink(),
            &key,
            Nonce::new([0; Nonce::SIZE]),
            Aad::empty(),
            buffer_size(),
        )
        .expect("Failed to create DecWriter"),
        &key,
        Nonce::new([0; Nonce::SIZE]),
        Aad::empty(),
        buffer_size(),
    )
    .expect("Failed to create EncWriter");
    let buf: &[u8] = &[0; 512];

    b.bytes = 1024;
    b.iter(|| {
        writer.write_all(buf).expect("decryption failed");
    });
    writer.close()
}

#[bench]
fn decrypt_write_64k(b: &mut Bencher) -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = EncWriter::with_buffer_size(
        DecWriter::with_buffer_size(
            io::sink(),
            &key,
            Nonce::new([0; Nonce::SIZE]),
            Aad::empty(),
            buffer_size(),
        )
        .expect("Failed to create DecWriter"),
        &key,
        Nonce::new([0; Nonce::SIZE]),
        Aad::empty(),
        buffer_size(),
    )
    .expect("Failed to create EncWriter");
    let buf: &[u8] = &[0; 32 * 1024];

    b.bytes = 64 * 1024;
    b.iter(|| {
        writer.write_all(buf).expect("decryption failed");
    });
    writer.close()
}

#[bench]
fn decrypt_write_512k(b: &mut Bencher) -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = EncWriter::with_buffer_size(
        DecWriter::with_buffer_size(
            io::sink(),
            &key,
            Nonce::new([0; Nonce::SIZE]),
            Aad::empty(),
            buffer_size(),
        )
        .expect("Failed to create DecWriter"),
        &key,
        Nonce::new([0; Nonce::SIZE]),
        Aad::empty(),
        buffer_size(),
    )
    .expect("Failed to create EncWriter");
    let buf: &[u8] = &[0; 256 * 1024];

    b.bytes = 512 * 1024;
    b.iter(|| {
        writer.write_all(buf).expect("decryption failed");
    });
    writer.close()
}

#[bench]
fn decrypt_write_1mb(b: &mut Bencher) -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);
    let mut writer = EncWriter::with_buffer_size(
        DecWriter::with_buffer_size(
            io::sink(),
            &key,
            Nonce::new([0; Nonce::SIZE]),
            Aad::empty(),
            buffer_size(),
        )
        .expect("Failed to create DecWriter"),
        &key,
        Nonce::new([0; Nonce::SIZE]),
        Aad::empty(),
        buffer_size(),
    )
    .expect("Failed to create EncWriter");

    let buf: &[u8] = &[0; 512 * 1024];
    b.bytes = 1024 * 1024;
    b.iter(|| {
        writer.write_all(buf).expect("decryption failed");
    });
    writer.close()
}
