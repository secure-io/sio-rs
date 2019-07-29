// Copyright (c) 2019 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

//! Authenticated encryption for I/O streams.
//!
//! The `sio` crate implements authenticated encryption for the `Read` and `Write` traits.
//! Therefore, it provides wrapper types for encryption (`EncWriter`) and decryption (`DecWriter`).
//!
//! The most core part of this crate is the `Algorithm` trait, which represents
//! an authenticated encryption algorithm ([AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))).
//! However, you only have to care about it when providing your own algorithm implementations.  
//!
//! # Feature Flags
//!
//! <table>
//! <tr><th>Feature
//!     <th>Description
//! <tr><td><code>ring (default)</code>
//!     <td>Use <a href="https://briansmith.org/rustdoc/ring/"><code>ring</code></a> to provide
//!     default implementations of AES-256-GCM and ChaCha20-Poly1305 based on Google's
//!     <a href="https://github.com/google/boringssl">BoringSSL</a> by implementing the
//!     <code>Algorithm</code> trait.
//! <tr><td><code>debug_panic</code>
//!     <td>This feature only affects debug builds and should only be enabled when debugging a
//!     panic. Both, <code>EncWriter</code> and <code>DecWriter</code> must be closed explicitly.
//!     Otherwise, dropping them causes a panic. Take a look at the <code>Close</code> trait for
//!     more details. When this feature is enabled, dropping an <code>EncWriter</code> or
//!     <code>DecWriter</code> without closing it explicitly does not trigger a panic in debug mode.
//!     This may be useful when debugging a panic of some other code.
//! </table>
//!
//! # Introduction
//!
//! The `sio` crate implements a (stream-based) secure channel construction to encrypt data.
//! It splits a data stream into fixed-sized chunks (fragments) and encrypts each fragment
//! separately using an authenticated encryption algorithm. The main advantage of using a
//! channel construction instead of applying the authenticated encryption algorithm directly
//! is that encryption as well as decryption can happen "online" and only requires a constant
//! amount of RAM - even for very large data streams. Here, "online" means that you don't need
//! to en/decrypt the entire data in one atomic operation but instead process it as continuous
//! stream. In general, this cannot be done securely with an authenticated encryption algorithm.
//!
//! For encrypting a data stream you have to provide three parameters:
//!   - The secret key represented by the `Key` type.
//!   - A nonce value represented by the `Nonce` type.
//!   - Some associated data represented by the `Aad` type.
//!
//! There is also an optional fourth parameter (buffer/fragment size) which we will cover later.
//!
//! Now, there is one important rule that must never be violated by your code since security
//! crucially depends on it:
//! <p style="margin-left: 40px; margin-right: 50px; border:1px; border-style:solid; border-color:#000000; padding: 0.3em">
//!      When encrypting a data stream you must use a new <code>key</code> <b>or</b> a new
//!      <code>nonce</code> value such that this particular <code>key</code>-<code>nonce</code>
//!      combination has <b>never</b> been used before.
//! </p>
//!
//! In general, the authenticated encryption algorithm (used by the channel construction) assumes
//! that, given the same key, the nonce value does never repeat. Violating this assumption breaks
//! the security properties and potentially allows decrypting or forging data without knowing the
//! secret key. Therefore, you have to make sure that you use a key-nonce combination only once.
//! But don't worry, there are best practices for dealing with keys and nonce values which can help
//! here.
//!
//! Next, we will take a look at some examples for encryption and decryption.
//!
//! # Encryption
//!
//! You can encrypt data by wrapping a writer with an `EncWriter`. The `EncWriter` is generic over
//! an authenticated encryption algorithm and takes a `Key`, a `Nonce` and some `Aad`.
//! ```norun
//! use std::io;
//! use std::io::Write;
//! use std::fs::File;
//! use sio::{EncWriter, Key, Nonce, Aad, AES_256_GCM, NopCloser};
//!
//! fn main() -> io::Result<()> {
//!     // Obviously, do NOT use this demo key for anything real!
//!     let secret_key: Key::<AES_256_GCM> = Key::new([0; Key::<AES_256_GCM>::SIZE]);
//!     
//!     let mut f = EncWriter::new(
//!        NopCloser::wrap(File::create("foo.txt")?),
//!        &secret_key,
//!        Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]),
//!        Aad::empty(),
//!     );
//!
//!     f.write_all(b"Hello World")?;
//!     f.close()
//! }
//! ```
//! Here, we try to create and wrap the file `foo.txt` and encrypt the string
//! `"Hello World"` using the [`AES_256_GCM`](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
//! algorithm before writing it to the file. Note that we call a `close` method
//! after writing. This is very important and you should take a look at the
//! `Close` trait for a detailed explanation about why this call is necessary.
//!
//! # Decryption
//!
//! Similarly, you can decrypt data by using a `DecWriter` instead of an `EncWriter`. The
//! `DecWriter` is also generic over an authenticated encryption algorithm and expects the
//! same `Key`, `Nonce` and `Aad` used before to encrypt the data.
//! ```norun
//! use std::io;
//! use std::io::{Read, Write};
//! use std::fs::File;
//! use sio::{DecWriter, Key, Nonce, Aad, AES_256_GCM, NopCloser};
//!
//! fn main() -> io::Result<()> {
//!     // Obviously, do NOT use this demo key for anything real!
//!     let secret_key: Key::<AES_256_GCM> = Key::new([0; Key::<AES_256_GCM>::SIZE]);
//!     
//!     let mut out = DecWriter::new(
//!        NopCloser::wrap(io::stdout()),
//!        &secret_key,
//!        Nonce::new([0; Nonce::<AES_256_GCM>::SIZE]),
//!        Aad::empty(),
//!     );
//!     
//!     io::copy(&mut File::open("foo.txt")?, &mut out)?;
//!     out.close()
//! }
//! ```
//! Here, we wrap the standard output file descriptor (STDOUT) with a `DecWriter`
//! such that everything written to `out` gets decrypted and verified before passed to
//! STDOUT. Than, we open the `foo.txt` file again and copy its content to `out`. Observe
//! that we invoke a `close` method at the end again. Refer to the `Close` trait for an
//! explanation about why this call is necessary.

pub use self::aead::{Aad, Algorithm, Key, Nonce};
pub use self::error::{Invalid, NotAuthentic};
pub use self::utils::NopCloser;
pub use self::writer::{Close, DecWriter, EncWriter};

mod aead;
mod error;
mod utils;
mod writer;

#[cfg(feature = "ring")]
mod ring;

#[cfg(feature = "ring")]
pub use self::ring::AES_256_GCM;

#[cfg(feature = "ring")]
pub use self::ring::CHACHA20_POLY1305;

pub const MAX_BUF_SIZE: usize = (1 << 24) - 1;
pub const BUF_SIZE: usize = 1 << 14;
