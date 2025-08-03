// Copyright © 2023 Denis Morel

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License and
// a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

mod xml_signature;

use rust_ev_crypto_primitives::{
    basic_crypto_functions::{sha256, verify, BasisCryptoError, PublicKey},
    ByteArray,
};
use std::io::Cursor;
use thiserror::Error;
use xml_canonicalization::Canonicalizer;
use xml_signature::XMLSignature;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error with dataset
pub struct XMLSignatureError(#[from] XMLSignatureErrorSignOrVerify);

#[derive(Error, Debug)]
#[allow(dead_code)]
/// Error with dataset
enum XMLSignatureErrorSignOrVerify {
    #[error("Error signing the xml")]
    Sign { source: XMLSignatureErrorRepr },
    #[error("Error verifying the xml")]
    Verify { source: XMLSignatureErrorRepr },
}

#[derive(Error, Debug)]
enum XMLSignatureErrorRepr {
    #[error("Error collecting the xml signature")]
    GetXMLSignature {
        source: xml_signature::XMLSignatureError,
    },
    #[error("Error canonicalizing")]
    C14N { source: Box<dyn std::error::Error> },
    #[error("Error calculating digest")]
    SHA256 { source: BasisCryptoError },
    #[error("Error verfiying the signature")]
    Verify { source: BasisCryptoError },
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum VerifyXMLSignatureResult {
    Success,
    DigestWrong,
    SignatureWrong,
}

pub fn verify_xml_signature(
    d_signed: &str,
    pk: &PublicKey,
) -> Result<VerifyXMLSignatureResult, XMLSignatureError> {
    verify_xml_signature_impl(d_signed, pk)
        .map_err(|e| XMLSignatureErrorSignOrVerify::Verify { source: e })
        .map_err(XMLSignatureError)
}

fn canonicalize(xml: &str) -> Result<String, XMLSignatureErrorRepr> {
    let mut result = vec![];
    Canonicalizer::read_from_str(xml)
        .write_to_writer(Cursor::new(&mut result))
        .canonicalize(true)
        .map_err(|e| XMLSignatureErrorRepr::C14N {
            source: Box::new(e),
        })?;
    Ok(String::from_utf8_lossy(&result).to_string())
}

fn verify_xml_signature_impl(
    d_signed: &str,
    pk: &PublicKey,
) -> Result<VerifyXMLSignatureResult, XMLSignatureErrorRepr> {
    let d_can = canonicalize(d_signed)?;
    let xml_signature = XMLSignature::from_str(&d_can)
        .map_err(|e| XMLSignatureErrorRepr::GetXMLSignature { source: e })?;
    let si = &xml_signature.signature.signed_info;
    let si_can = xml_signature.find_canonalized_signed_info_str().unwrap();
    let t = xml_signature.remove_signature_from_orig();
    let d_prime = sha256(&ByteArray::from(t.as_str()))
        .map_err(|e| XMLSignatureErrorRepr::SHA256 { source: e })?;
    let d = &si.reference.digest_value;
    if &d_prime != d {
        return Ok(VerifyXMLSignatureResult::DigestWrong);
    }
    match verify(
        pk,
        &ByteArray::from(si_can.as_str()),
        &xml_signature.signature.signature_value,
    )
    .map_err(|e| XMLSignatureErrorRepr::Verify { source: e })?
    {
        true => Ok(VerifyXMLSignatureResult::Success),
        false => Ok(VerifyXMLSignatureResult::SignatureWrong),
    }
}

#[cfg(test)]
mod test_data {
    use std::path::PathBuf;

    use crate::test_data::{get_test_data_xml, get_test_data_xml_path};

    const CONFIG_FILENAME: &str = "configuration-anonymized.xml";
    const ECH0222_FILENAME: &str = "eCH-0222_v3-0_NE_20231124_TT05.xml";
    const KEYSTORE_FILENAME: &str = "local_direct_trust_keystore_verifier.p12";
    const KEYSTORE_PWD_FILENAME: &str = "local_direct_trust_pw_verifier.txt";

    pub fn get_test_data_config() -> String {
        get_test_data_xml(CONFIG_FILENAME)
    }

    pub fn get_test_data_ech0222() -> String {
        get_test_data_xml(ECH0222_FILENAME)
    }

    pub fn get_verifier_keystore_path() -> PathBuf {
        get_test_data_xml_path().join(KEYSTORE_FILENAME)
    }

    pub fn get_verifier_keystore_pwd_path() -> PathBuf {
        get_test_data_xml_path().join(KEYSTORE_PWD_FILENAME)
    }
}

#[cfg(test)]
mod test {
    use super::{test_data::*, *};
    use rust_ev_crypto_primitives::direct_trust::Keystore;

    fn get_public_key(ca: &str) -> PublicKey {
        let keystore = Keystore::from_pkcs12(
            &get_verifier_keystore_path(),
            &get_verifier_keystore_pwd_path(),
        )
        .unwrap();
        keystore
            .public_certificate(ca)
            .unwrap()
            .signing_certificate()
            .public_key()
            .unwrap()
    }

    #[test]
    fn test_config() {
        let data = get_test_data_config();
        let res = verify_xml_signature(data.as_str(), &get_public_key("canton"));
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        assert_eq!(res.unwrap(), VerifyXMLSignatureResult::Success);
    }

    #[test]
    fn test_ech0222() {
        let data = get_test_data_ech0222();
        let res = verify_xml_signature(data.as_str(), &get_public_key("sdm_tally"));
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        assert_eq!(res.unwrap(), VerifyXMLSignatureResult::Success);
    }
}
