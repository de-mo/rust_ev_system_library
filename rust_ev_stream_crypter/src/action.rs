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

use crate::CrytperSubcommand;
use anyhow::{bail, Context};
use rust_ev_system_library::{
    chanel_security::stream::{gen_stream_ciphertext, get_stream_plaintext},
    rust_ev_crypto_primitives::prelude::{argon2::Argon2idParameters, ByteArray},
};
use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::Path,
};
use tracing::{error, info};

fn validate_input_file(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        let msg = format!("Input path does not exists {:?}", path);
        tracing::error!(msg);
        bail!(msg)
    }
    if !path.is_file() {
        let msg = format!("Input path is not a file {:?}", path);
        tracing::error!(msg);
        bail!(msg)
    }
    Ok(())
}

fn validate_output_file(path: &Path, replace: bool) -> anyhow::Result<()> {
    if !path.parent().unwrap().exists() {
        let msg = format!(
            "Output directory doesn't exists {:?}",
            path.parent().unwrap()
        );
        tracing::error!(msg);
        bail!(msg)
    }
    if path.exists() {
        if replace {
            if path.is_dir() {
                let msg = format!("Output path is a directory {:?}", path);
                tracing::error!(msg);
                bail!(msg)
            } else {
                std::fs::remove_file(path).context("cannont remove the file")?
            }
        } else {
            let msg = format!(
                "Output path already exists and the file must not be replaced {:?}",
                path
            );
            tracing::error!(msg);
            bail!(msg)
        }
    }
    Ok(())
}

fn prepare_buf_reader(path: &Path) -> anyhow::Result<BufReader<File>> {
    let f = File::open(path)?;
    Ok(BufReader::new(f))
}

fn prepare_buf_writer(path: &Path) -> anyhow::Result<BufWriter<File>> {
    let f = File::create(path)?;
    Ok(BufWriter::new(f))
}

pub fn encrypt(inputs: &CrytperSubcommand) -> anyhow::Result<()> {
    validate_input_file(&inputs.input)?;
    validate_output_file(&inputs.output, inputs.replace)?;
    let mut reader = prepare_buf_reader(&inputs.input)?;
    let mut writer = prepare_buf_writer(&inputs.output)?;
    info!("Start encryption");
    let res = gen_stream_ciphertext(
        &mut reader,
        &inputs.password,
        &ByteArray::default(),
        &mut writer,
        Argon2idParameters::default(),
    );
    if let Err(e) = res {
        error!("Error encrypting");
        return Err(e.into());
    }
    info!("Encrypting finished");
    Ok(())
}

pub fn decrypt(inputs: &CrytperSubcommand) -> anyhow::Result<()> {
    validate_input_file(&inputs.input)?;
    validate_output_file(&inputs.output, inputs.replace)?;
    let mut reader = prepare_buf_reader(&inputs.input)?;
    let mut writer = prepare_buf_writer(&inputs.output)?;
    info!("Start decryption");
    let res = get_stream_plaintext(
        &mut reader,
        &inputs.password,
        &ByteArray::default(),
        &mut writer,
        Argon2idParameters::default(),
    );
    if let Err(e) = res {
        error!("Error decrypting");
        return Err(e.into());
    }
    info!("Decrypting finished");
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::Local;
    use std::{io::Write, path::PathBuf};

    const TEST_DATA_DIRNAME: &str = "test_data";
    const TEMP_DIRNAME: &str = "temp";
    const TEST_FILE_NAME: &str = "test_file.txt";

    fn get_root() -> PathBuf {
        PathBuf::from(".")
    }

    fn get_test_data_path() -> PathBuf {
        get_root().join(TEST_DATA_DIRNAME)
    }

    fn get_temp_path() -> PathBuf {
        get_root().join(TEMP_DIRNAME)
    }

    fn get_test_file_path() -> PathBuf {
        get_test_data_path().join(TEST_FILE_NAME)
    }

    #[test]
    fn test_validate_input_file() {
        assert!(validate_input_file(&get_test_file_path()).is_ok());
        assert!(validate_input_file(&get_test_data_path().join("toto.txt")).is_err());
        assert!(validate_input_file(&get_test_data_path()).is_err());
    }

    #[test]
    fn test_validate_output_file() {
        assert!(validate_output_file(&get_temp_path().join("toto.txt"), false).is_ok());
        assert!(validate_output_file(&get_temp_path().join("toto.txt"), true).is_ok());
        assert!(validate_output_file(&get_root().join("toto").join("toto.txt"), true).is_err());
        assert!(validate_output_file(&get_temp_path(), true).is_err());
        {
            let mut f = std::fs::File::create(get_temp_path().join("toto.txt")).unwrap();
            f.write_all(b"12345").unwrap();
        }
        assert!(validate_output_file(&get_temp_path().join("toto.txt"), false).is_err());
        assert!(validate_output_file(&get_temp_path().join("toto.txt"), true).is_ok());
        assert!(!get_temp_path().join("toto.txt").exists())
    }

    #[test]
    fn test_encrypt_decrypt() {
        let password = "password";
        let output_encrypted_filename = format!(
            "{}_{}.bin",
            TEST_FILE_NAME,
            Local::now().format("%Y-%m-%d-%H:%M:%S")
        );
        let output_decrypted_filename = format!("{}.txt", &output_encrypted_filename);
        let output_encrypted_path = get_temp_path().join(&output_encrypted_filename);
        let output_decrypted_path = get_temp_path().join(output_decrypted_filename);
        let encrypt_inputs = CrytperSubcommand {
            input: get_test_file_path(),
            output: output_encrypted_path.clone(),
            password: password.to_string(),
            replace: false,
        };
        let decrypt_inputs = CrytperSubcommand {
            input: output_encrypted_path.clone(),
            output: output_decrypted_path.clone(),
            password: password.to_string(),
            replace: false,
        };
        assert!(encrypt(&encrypt_inputs).is_ok());
        assert!(output_encrypted_path.exists());
        let res = decrypt(&decrypt_inputs);
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        assert!(output_decrypted_path.exists());
        assert_eq!(
            std::fs::read_to_string(get_test_file_path()).unwrap(),
            std::fs::read_to_string(output_decrypted_path).unwrap()
        );
    }
}
