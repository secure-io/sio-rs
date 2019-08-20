// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

use sio::*;
use std::{io, io::Write};

#[cfg(feature = "aesgcm")]
type AEAD = AES_256_GCM;

#[cfg(not(feature = "aesgcm"))]
type AEAD = CHACHA20_POLY1305;

#[test]
fn write() -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);

    let data = [0; 1 << 20];
    let mut plaintext = Vec::with_capacity(data.len());
    let mut ciphertext = Vec::with_capacity(data.len());

    let mut writer = EncWriter::new(
        &mut ciphertext,
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
    let half = data.len() / 2;
    writer
        .write_all(&data[..half])
        .and_then(|()| writer.write_all(&data[half..]))
        .and_then(|()| writer.close())?;

    let mut writer = DecWriter::new(
        &mut plaintext,
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
    let half = ciphertext.len() / 2;
    writer
        .write_all(&ciphertext.as_slice()[..half])
        .and_then(|()| writer.write_all(&ciphertext.as_slice()[half..]))
        .and_then(|()| writer.close())?;

    assert_eq!(data.as_ref(), plaintext.as_slice());
    Ok(())
}

#[test]
fn write_empty() -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);

    let data = [0; 0];
    let mut plaintext = Vec::new();
    let mut ciphertext = Vec::with_capacity(AEAD::TAG_LEN);

    EncWriter::new(
        &mut ciphertext,
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    )
    .close()
    .expect("The encryption failed");

    assert_eq!(ciphertext.len(), AEAD::TAG_LEN);
    let mut writer = DecWriter::new(
        &mut plaintext,
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
    writer
        .write_all(ciphertext.as_slice())
        .and_then(|_| writer.close())?;

    assert_eq!(data.as_ref(), plaintext.as_slice());
    Ok(())
}

#[test]
fn close() -> io::Result<()> {
    let key: Key<AEAD> = Key::new([0; Key::<AEAD>::SIZE]);

    let data = [0; 1 << 20];
    let mut plaintext = Vec::with_capacity(data.len());

    let mut writer = EncWriter::new(
        io::BufWriter::new(
            DecWriter::new(
                &mut plaintext,
                &key,
                Nonce::new([0; Nonce::<AEAD>::SIZE]),
                Aad::empty(),
            )
            .closer(),
        ),
        &key,
        Nonce::new([0; Nonce::<AEAD>::SIZE]),
        Aad::empty(),
    );
    writer.write_all(&data).and_then(|_| writer.close())?;

    assert_eq!(data.as_ref(), plaintext.as_slice());
    Ok(())
}
