# Secure IO

[![Crate](https://img.shields.io/badge/crates.io-v0.2.0-orange.svg)](https://crates.io/crates/sio)
[![Build Status](https://travis-ci.org/secure-io/sio-rs.svg?branch=master)](https://travis-ci.org/secure-io/sio-rs)

# Secure IO

The `sio` crate implements provable secure authenticated encryption for continuous byte streams.  
It splits a data stream into `L` bytes long fragments and en/decrypts each fragment with an unique
key-nonce combination using an [AEAD](https://golang.org/pkg/crypto/cipher/#AEAD). For the last 
fragment the construction prefixes the associated data with the `0x80` byte (instead of `0x00`)
to prevent truncation attacks. 

![`sio` encryption scheme](https://github.com/secure-io/sio/blob/master/img/channel_construction.svg)

The `sio` crate follows semantic versioning and hasn't reached a stable v1.0.0, yet. So
newer versions may cause major breaking API changes. However, we try to avoid such changes - if not really
needed.

### How to use `sio`?

1. Add it as dependency to your `Cargo.toml`: `sio = "0.2.0"`.
2. Use it within your application or crate:
   ```
   extern crate sio

   use sio;
   ```

For a comprehensive overview of the API please take a look at [docs.rs](https://docs.rs/sio/0.2.0/sio/).

