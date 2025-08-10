// Copyright © 2023 Denis Morel

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License and
// a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

use std::io::{BufRead, BufWriter, Write};

use rust_ev_crypto_primitives::{
    argon2::{Argon2Error, Argon2id, ARGON2_SALT_SIZE},
    basic_crypto_functions::{BasisCryptoError, Decrypter, Encrypter, CRYPTER_TAG_SIZE},
    random::{random_bytes, RandomError},
    symmetric_authenticated_encryption::AUTH_ENCRPYTION_NONCE_SIZE,
    ByteArray,
};
use thiserror::Error;

const ENCRYPTED_BLOCK_SIZE: usize = 512;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error with dataset
pub struct StreamSymEncryptionError(#[from] StreamSymEncryptionErrorEncrypOrDecrypt);

#[derive(Error, Debug)]
/// Error with dataset
enum StreamSymEncryptionErrorEncrypOrDecrypt {
    #[error("Error stream encryption in gen_stream_ciphertext")]
    Encrypt {
        source: StreamSymEncryptionErrorRepr,
    },
    #[error("Error stream decryption in get_stream_plaintext")]
    Decrypt {
        source: StreamSymEncryptionErrorRepr,
    },
}

#[derive(Error, Debug)]
enum StreamSymEncryptionErrorRepr {
    #[error("IO Error reading the buffer: {msg}")]
    IORead {
        msg: &'static str,
        source: std::io::Error,
    },
    #[error("Byte length error {0}")]
    ByteLengthError(String),
    #[error("Error creating decrypter")]
    Decrypter { source: BasisCryptoError },
    #[error("Error decrypting the ciphertext")]
    Decrypt { source: BasisCryptoError },
    #[error("IO Error writing the buffer: {msg}")]
    IOWrite {
        msg: &'static str,
        source: std::io::Error,
    },
    #[error("Argon2 error: {msg}")]
    Argon2 { msg: String, source: Argon2Error },
    #[error("Error generating the nonce")]
    Nonce { source: RandomError },
    #[error("Error creating encrypter")]
    Encrypter { source: BasisCryptoError },
    #[error("Error encrypting the plaintext")]
    Encrypt { source: BasisCryptoError },
}

/// Algorithm 7.3
pub fn gen_stream_ciphertext<W: ?Sized + Write>(
    input_reader: &mut dyn BufRead,
    password: &str,
    associated_data: &ByteArray,
    target_writer: &mut BufWriter<W>,
) -> Result<(), StreamSymEncryptionError> {
    gen_stream_ciphertext_impl(input_reader, password, associated_data, target_writer)
        .map_err(|e| StreamSymEncryptionErrorEncrypOrDecrypt::Encrypt { source: e })
        .map_err(StreamSymEncryptionError::from)
}

fn gen_stream_ciphertext_impl<W: ?Sized + Write>(
    input_reader: &mut dyn BufRead,
    password: &str,
    associated_data: &ByteArray,
    target_writer: &mut BufWriter<W>,
) -> Result<(), StreamSymEncryptionErrorRepr> {
    // derived_key and salt)
    let (derive_key, salt) = Argon2id::new_standard()
        .gen_argon2id(&ByteArray::from(password))
        .map_err(|e| StreamSymEncryptionErrorRepr::Argon2 {
            msg: "Error in gen_argon2id".to_string(),
            source: e,
        })?;

    // nonce
    let nonce = random_bytes(AUTH_ENCRPYTION_NONCE_SIZE)
        .map_err(|e| StreamSymEncryptionErrorRepr::Nonce { source: e })?;

    // Get encrypter
    let mut encrypter = Encrypter::new(&nonce, &derive_key, associated_data)
        .map_err(|e| StreamSymEncryptionErrorRepr::Encrypter { source: e })?;

    // Write salt
    target_writer.write_all(salt.to_bytes()).map_err(|e| {
        StreamSymEncryptionErrorRepr::IOWrite {
            msg: "Writing the plaintext",
            source: e,
        }
    })?;

    // Write nonce
    target_writer.write_all(nonce.to_bytes()).map_err(|e| {
        StreamSymEncryptionErrorRepr::IOWrite {
            msg: "Writing the plaintext",
            source: e,
        }
    })?;

    // Stream encrypt
    loop {
        let mut temp_buffer = vec![0; ENCRYPTED_BLOCK_SIZE];
        let count = input_reader.read(&mut temp_buffer).map_err(|e| {
            StreamSymEncryptionErrorRepr::IORead {
                msg: "Reading data in the buffer",
                source: e,
            }
        })?;
        temp_buffer.truncate(count);
        if count < ENCRYPTED_BLOCK_SIZE {
            let ciphertext = encrypter
                .encrypt_and_finalize_with_tag(&ByteArray::from_bytes(&temp_buffer))
                .map_err(|e| StreamSymEncryptionErrorRepr::Encrypt { source: e })?;
            target_writer
                .write_all(ciphertext.to_bytes())
                .map_err(|e| StreamSymEncryptionErrorRepr::IOWrite {
                    msg: "Writing the plaintext",
                    source: e,
                })?;
            break;
        }
        let ciphertext = encrypter
            .encrypt(&ByteArray::from_bytes(&temp_buffer))
            .map_err(|e| StreamSymEncryptionErrorRepr::Encrypt { source: e })?;
        target_writer
            .write_all(ciphertext.to_bytes())
            .map_err(|e| StreamSymEncryptionErrorRepr::IOWrite {
                msg: "Writing the plaintext",
                source: e,
            })?;
    }
    target_writer
        .flush()
        .map_err(|e| StreamSymEncryptionErrorRepr::IOWrite {
            msg: "flushing the BufWriter",
            source: e,
        })
}

pub fn get_stream_plaintext<W: ?Sized + Write>(
    input_reader: &mut dyn BufRead,
    password: &str,
    associated_data: &ByteArray,
    target_writer: &mut BufWriter<W>,
) -> Result<(), StreamSymEncryptionError> {
    get_stream_plaintext_impl(input_reader, password, associated_data, target_writer)
        .map_err(|e| StreamSymEncryptionErrorEncrypOrDecrypt::Decrypt { source: e })
        .map_err(StreamSymEncryptionError::from)
}

fn get_stream_plaintext_impl<W: ?Sized + Write>(
    input_reader: &mut dyn BufRead,
    password: &str,
    associated_data: &ByteArray,
    target_writer: &mut BufWriter<W>,
) -> Result<(), StreamSymEncryptionErrorRepr> {
    let mut salt_buf: Vec<u8> = vec![0; ARGON2_SALT_SIZE as usize];
    let mut nonce_buf: Vec<u8> = vec![0; AUTH_ENCRPYTION_NONCE_SIZE as usize];

    // Getting salt
    let bytes_red =
        input_reader
            .read(&mut salt_buf)
            .map_err(|e| StreamSymEncryptionErrorRepr::IORead {
                msg: "Reading salt",
                source: e,
            })?;
    if bytes_red != ARGON2_SALT_SIZE as usize {
        return Err(StreamSymEncryptionErrorRepr::ByteLengthError(format!(
            "size of bytes read {bytes_red} for salt wrong. Expected: {ARGON2_SALT_SIZE}"
        )));
    }
    let salt = ByteArray::from_bytes(&salt_buf);

    // Getting nonce
    let bytes_red =
        input_reader
            .read(&mut nonce_buf)
            .map_err(|e| StreamSymEncryptionErrorRepr::IORead {
                msg: "Reading nonce",
                source: e,
            })?;
    if bytes_red != AUTH_ENCRPYTION_NONCE_SIZE as usize {
        return Err(StreamSymEncryptionErrorRepr::ByteLengthError(format!(
            "size of bytes read {bytes_red} for nonce wrong. Expected: {AUTH_ENCRPYTION_NONCE_SIZE}"
        )));
    }
    let nonce = ByteArray::from_bytes(&nonce_buf);

    // Get derived_key
    let derive_key = Argon2id::new_standard()
        .get_argon2id(&ByteArray::from(password), &salt)
        .map_err(|e| StreamSymEncryptionErrorRepr::Argon2 {
            msg: "Error in get_argon2id".to_string(),
            source: e,
        })?;

    // Get decrypter
    let mut decrypter = Decrypter::new(&nonce, &derive_key, associated_data)
        .map_err(|e| StreamSymEncryptionErrorRepr::Decrypter { source: e })?;

    // Stream decrypt
    let mut next_buffer = vec![0; ENCRYPTED_BLOCK_SIZE];
    let mut count_next =
        input_reader
            .read(&mut next_buffer)
            .map_err(|e| StreamSymEncryptionErrorRepr::IORead {
                msg: "Reading data in the buffer",
                source: e,
            })?;
    next_buffer.truncate(count_next);
    loop {
        let temp_buffer = next_buffer.clone();
        let count = count_next;
        next_buffer = vec![0; ENCRYPTED_BLOCK_SIZE];
        count_next = input_reader.read(&mut next_buffer).map_err(|e| {
            StreamSymEncryptionErrorRepr::IORead {
                msg: "Reading data in the buffer",
                source: e,
            }
        })?;
        //println!("count: {count}");
        //println!("count_next: {count_next}");
        next_buffer.truncate(count_next);
        // End of stream. The last 16 bytes are the tag and must be delivered completly
        if count + count_next < ENCRYPTED_BLOCK_SIZE + CRYPTER_TAG_SIZE {
            let input = ByteArray::from(&temp_buffer).new_append(&ByteArray::from(&next_buffer));
            /*println!(
                "Enter end case. count={count}. count_next={count_next}. Len new input={}",
                input.len()
            );*/
            let plaintext = decrypter
                .decrypt_and_finalize_with_tag(&input)
                .map_err(|e| StreamSymEncryptionErrorRepr::Decrypt { source: e })?;
            target_writer.write_all(plaintext.to_bytes()).map_err(|e| {
                StreamSymEncryptionErrorRepr::IOWrite {
                    msg: "Writing the plaintext",
                    source: e,
                }
            })?;
            break;
        }
        let plaintext = decrypter
            .decrypt(&ByteArray::from_bytes(&temp_buffer))
            .map_err(|e| StreamSymEncryptionErrorRepr::Decrypt { source: e })?;
        target_writer.write_all(plaintext.to_bytes()).map_err(|e| {
            StreamSymEncryptionErrorRepr::IOWrite {
                msg: "Writing the plaintext",
                source: e,
            }
        })?;
    }
    target_writer
        .flush()
        .map_err(|e| StreamSymEncryptionErrorRepr::IOWrite {
            msg: "flushing the BufWriter",
            source: e,
        })
}

#[cfg(test)]
mod test {
    use std::io::BufReader;

    use rust_ev_crypto_primitives::{alphabets::ALPHABET_USER_FRIENDLY, random::gen_random_string};

    use super::*;
    use crate::{
        test_data::{get_test_data_stream, get_test_data_stream_path},
        test_json_data::{json_array_value_to_array_string, json_value_to_bytearray_base64},
    };

    fn generate_random_string(len: usize) -> String {
        gen_random_string(len, &ALPHABET_USER_FRIENDLY).unwrap()
    }

    #[test]
    fn test_get_stream_plaintext() {
        for tc in get_test_data_stream("get-stream-plaintext.json")
            .as_array()
            .unwrap()
            .iter()
            .take(1)
        {
            let salt = json_value_to_bytearray_base64(&tc["input"]["salt"]);
            let nonce = json_value_to_bytearray_base64(&tc["input"]["nonce"]);
            let password = tc["input"]["password"].as_str().unwrap();
            let associated_data_input =
                json_array_value_to_array_string(&tc["input"]["associated"]);
            let ciphertext_input = json_value_to_bytearray_base64(&tc["input"]["C"]);
            let ciphertext = salt.new_append(&nonce).new_append(&ciphertext_input);
            let associated_data = associated_data_input
                .iter()
                .map(|d| ByteArray::from(d.as_str()))
                .fold(ByteArray::default(), |acc, d| acc.new_append(&d));
            let mut buf_writer = BufWriter::new(vec![]);
            get_stream_plaintext(
                &mut ciphertext.to_bytes(),
                password,
                &associated_data,
                &mut buf_writer,
            )
            .unwrap();
            let res = buf_writer.into_inner().unwrap();
            let expected = json_value_to_bytearray_base64(&tc["output"]["P"])
                .to_bytes()
                .to_vec();
            println!("len res: {}", res.len());
            println!("len expected: {}", expected.len());
        }
    }

    #[test]
    fn test_stream_decrypt() {
        let path = get_test_data_stream_path().join("test_data.bin");
        let password = "password".to_string();
        let aad = ByteArray::default();
        let f = std::fs::File::open(&path).unwrap();
        let mut reader = BufReader::new(f);
        let mut plaintext_writer = BufWriter::new(vec![]);
        let res = get_stream_plaintext(&mut reader, &password, &aad, &mut plaintext_writer);
        assert!(res.is_ok(), "{:?}", res.unwrap_err())
    }

    #[test]
    fn test_stream_encryp_decrypt() {
        let plaintext = generate_random_string(5001);
        let password = "password".to_string();
        let aad = ByteArray::default();
        let plaintext_bytes = ByteArray::from(plaintext.as_str());
        let mut ciphertext_writer = BufWriter::new(vec![]);
        gen_stream_ciphertext(
            &mut plaintext_bytes.to_bytes(),
            &password,
            &aad,
            &mut ciphertext_writer,
        )
        .unwrap();
        let ciphertext = ciphertext_writer.into_inner().unwrap();
        let mut plaintext_writer = BufWriter::new(vec![]);
        get_stream_plaintext(
            &mut ciphertext.as_slice(),
            &password,
            &aad,
            &mut plaintext_writer,
        )
        .unwrap();
        let res_plaintext = plaintext_writer.into_inner().unwrap();
        assert_eq!(ByteArray::from(&res_plaintext), plaintext_bytes)
    }
}
