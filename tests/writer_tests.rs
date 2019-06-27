use sio::ring::AES_256_GCM;
use sio::*;
use std::io::Write;

#[test]
fn write() {
    let key: Key<AES_256_GCM> = Key::new([0; Key::<AES_256_GCM>::SIZE]);

    let data = [0; 1 << 20];
    let mut plaintext = Vec::with_capacity(data.len());
    let mut ciphertext = Vec::with_capacity(data.len());

    let mut writer = EncWriter::new(
        &mut ciphertext,
        &key,
        Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]),
        Aad::empty(),
    );
    let half = data.len() / 2;
    writer
        .write_all(&data[..half])
        .and_then(|()| writer.write_all(&data[half..]))
        .and_then(|()| writer.close())
        .expect("The encryption failed");

    let mut writer = DecWriter::new(
        &mut plaintext,
        &key,
        Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]),
        Aad::empty(),
    );
    let half = ciphertext.len() / 2;
    writer
        .write_all(&ciphertext.as_slice()[..half])
        .and_then(|()| writer.write_all(&ciphertext.as_slice()[half..]))
        .and_then(|()| writer.close())
        .expect("The decryption failed");

    assert_eq!(data.as_ref(), plaintext.as_slice());
}

#[test]
fn write_empty() {
    let key: Key<AES_256_GCM> = Key::new([0; Key::<AES_256_GCM>::SIZE]);

    let data = [0; 0];
    let mut plaintext = Vec::new();
    let mut ciphertext = Vec::with_capacity(AES_256_GCM::TAG_LEN);

    EncWriter::new(
        &mut ciphertext,
        &key,
        Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]),
        Aad::empty(),
    )
    .close()
    .expect("The encryption failed");

    assert_eq!(ciphertext.len(), AES_256_GCM::TAG_LEN);

    let mut writer = DecWriter::new(
        &mut plaintext,
        &key,
        Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]),
        Aad::empty(),
    );
    writer
        .write_all(ciphertext.as_slice())
        .and_then(|()| writer.close())
        .expect("The decryption failed");

    assert_eq!(data.as_ref(), plaintext.as_slice());
}

#[test]
fn close() {
    let key: Key<AES_256_GCM> = Key::new([0; Key::<AES_256_GCM>::SIZE]);

    let data = [0; 1 << 20];
    let mut plaintext = Vec::with_capacity(data.len());

    let mut writer = EncWriter::new(
        DecWriter::new(
            &mut plaintext,
            &key,
            Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]),
            Aad::empty(),
        ),
        &key,
        Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]),
        Aad::empty(),
    );
    writer
        .write_all(&data)
        .and_then(|()| writer.close())
        .expect("The en/decryption failed");

    assert_eq!(data.as_ref(), plaintext.as_slice());
}
