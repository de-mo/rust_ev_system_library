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

mod xml_signature;

use rust_ev_crypto_primitives::{
    basic_crypto_functions::{sha256, sign, verify, BasisCryptoError, PublicKey, Secretkey},
    ByteArray, EncodeTrait,
};
use std::io::Cursor;
use thiserror::Error;
use xml_canonicalization::Canonicalizer;
use xml_signature::{SignedInfo, XMLWithXMLSignature, XMLWithXMLSignatureError};
use xot::{NamespaceId, Node, PrefixId, Xot};

#[derive(Error, Debug)]
#[error(transparent)]
/// Error with tthe xml signature
pub struct XMLSignatureError(#[from] XMLSignatureErrorSignOrVerify);

#[derive(Error, Debug)]
#[allow(dead_code)]
/// Error with dataset
enum XMLSignatureErrorSignOrVerify {
    #[error("Error signing the xml")]
    Sign { source: XMLSignatureErrorRepr },
    #[error("Error verifying the xml")]
    Verify { source: XMLSignatureErrorRepr },
    #[error("Error calculating the digest")]
    Digest { source: XMLSignatureErrorRepr },
}

#[derive(Error, Debug)]
enum XMLSignatureErrorRepr {
    #[error("Error collecting the xml signature")]
    GetXMLSignature { source: XMLWithXMLSignatureError },
    #[error("Error calculating the digest")]
    Digest { source: Box<XMLSignatureError> },
    #[error("Error parsing the xml")]
    Parse { source: XMLWithXMLSignatureError },
    #[error("No Signature found")]
    NoSignature,
    #[error("Error canonicalizing")]
    C14N { source: Box<dyn std::error::Error> },
    #[error("Error calculating digest")]
    SHA256 { source: BasisCryptoError },
    #[error("Error verfiying the signature")]
    Verify { source: BasisCryptoError },
    #[error("IO Error: {msg}")]
    IO {
        msg: &'static str,
        source: std::io::Error,
    },
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
/// Result of the verification of the xml signature
pub enum VerifyXMLSignatureResult {
    /// Verification is successful
    Success,
    /// The digest in the xml signature ist wrong
    DigestWrong,
    /// The signature ist wrong
    SignatureWrong,
}

impl VerifyXMLSignatureResult {
    pub fn is_ok(&self) -> bool {
        self == &VerifyXMLSignatureResult::Success
    }
}

/// Verify the xml signature, according to the specifications of Swiss Post
pub fn verify_xml_signature(
    d_signed: &str,
    pk: &PublicKey,
) -> Result<VerifyXMLSignatureResult, XMLSignatureError> {
    verify_xml_signature_impl(d_signed, pk)
        .map_err(|e| XMLSignatureErrorSignOrVerify::Verify { source: e })
        .map_err(XMLSignatureError)
}

/// Generate the xml signature stream, according to the specifications of Swiss Post
pub fn gen_xml_signature(d: &str, sk: &Secretkey) -> Result<String, XMLSignatureError> {
    gen_xml_signature_impl(d, sk)
        .map_err(|e| XMLSignatureErrorSignOrVerify::Sign { source: e })
        .map_err(XMLSignatureError)
}

/// Collect the digest
///
/// If the xml signature exists: get the digest in the xml signature
/// Else: calculation the digest
pub fn collect_xml_digest(xml: &str) -> Result<ByteArray, XMLSignatureError> {
    collect_xml_digest_impl(xml)
        .map_err(|e| XMLSignatureErrorSignOrVerify::Digest { source: e })
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
    println!("{}", d_can);
    let xml_signature = XMLWithXMLSignature::from_str(&d_can)
        .map_err(|e| XMLSignatureErrorRepr::GetXMLSignature { source: e })?;
    if !xml_signature.has_signature() {
        return Err(XMLSignatureErrorRepr::NoSignature);
    }
    let si = &xml_signature.unwrap_signature().signed_info;
    let si_can = get_canonalized_signed_info_str(
        xml_signature.find_signed_info_str().unwrap(),
        &xml_signature.unwrap_signature_content().namespace_prefix,
        &xml_signature.unwrap_signature_content().namespace_uri,
    );
    let t = xml_signature.remove_signature_from_orig();
    println!("{}", &t);
    let d_prime = sha256(&ByteArray::from(t.as_str()))
        .map_err(|e| XMLSignatureErrorRepr::SHA256 { source: e })?;
    let d = &si.reference.digest_value;
    if &d_prime != d {
        return Ok(VerifyXMLSignatureResult::DigestWrong);
    }
    match verify(
        pk,
        &ByteArray::from(si_can.as_str()),
        &xml_signature.unwrap_signature().signature_value,
    )
    .map_err(|e| XMLSignatureErrorRepr::Verify { source: e })?
    {
        true => Ok(VerifyXMLSignatureResult::Success),
        false => Ok(VerifyXMLSignatureResult::SignatureWrong),
    }
}

fn gen_xml_signature_impl(d: &str, sk: &Secretkey) -> Result<String, XMLSignatureErrorRepr> {
    let mut si = SignedInfo::default();
    let d_transformed = XMLWithXMLSignature::from_str(&d)
        .map_err(|e| XMLSignatureErrorRepr::Parse { source: e })?
        .remove_signature_from_orig();
    let d_can = canonicalize(&d_transformed)?;
    println!("{}", d_can);
    let digest = sha256(&ByteArray::from(d_can.as_str()))
        .map_err(|e| XMLSignatureErrorRepr::SHA256 { source: e })?;
    si.set_digest_value(&digest);
    let namespace_prefix = "ds";
    let namespace_uri = "http://www.w3.org/2000/09/xmldsig#";
    let xml_sig = integrate_signature_xml(&d_transformed, &si, namespace_prefix, namespace_uri);
    let si_can = get_canonalized_signed_info_str(&xml_sig, namespace_prefix, namespace_uri);
    let signature = sign(sk, &ByteArray::from(si_can.as_str())).unwrap();
    let res = xml_sig.replace(
        "TO_REPLACE_WITH_SIGNATURE",
        signature.base64_encode().unwrap().as_str(),
    );
    Ok(res)
}

fn get_canonalized_signed_info_str(
    xml: &str,
    namespace_prefix: &str,
    namespace_uri: &str,
) -> String {
    xml.replace(
        format!("<{namespace_prefix}:SignedInfo>").as_str(),
        format!("<{namespace_prefix}:SignedInfo xmlns:{namespace_prefix}=\"{namespace_uri}\">")
            .as_str(),
    )
}

fn collect_xml_digest_impl(xml: &str) -> Result<ByteArray, XMLSignatureErrorRepr> {
    let xml_with_sig = XMLWithXMLSignature::from_str(xml)
        .map_err(|e| XMLSignatureErrorRepr::GetXMLSignature { source: e })?;
    match xml_with_sig.has_signature() {
        true => Ok(xml_with_sig
            .unwrap_signature()
            .signed_info
            .reference
            .digest_value
            .clone()),
        false => sha256(&ByteArray::from(canonicalize(xml)?.as_str()))
            .map_err(|e| XMLSignatureErrorRepr::SHA256 { source: e }),
    }
}

fn integrate_signature_xml(
    xml: &str,
    sig_info: &SignedInfo,
    namespace_prefix: &str,
    namespace_uri: &str,
) -> String {
    let mut xot = Xot::new();
    let document = xot.parse(xml).unwrap();
    let root = xot.document_element(document).unwrap();
    let alg_attribute_name = xot.add_name("Algorithm");
    let prefix = xot.add_prefix(namespace_prefix);
    let namespace = xot.add_namespace(namespace_uri);
    let namespace_node = xot.new_namespace_node(prefix, namespace);
    xot.append_namespace_node(root, namespace_node).unwrap();
    let name = xot.add_name_ns("Signature", namespace);
    let signature_el = xot.new_element(name);
    let name = xot.add_name_ns("SignedInfo", namespace);
    let sig_info_el = xot.new_element(name);
    let name = xot.add_name_ns("CanonicalizationMethod", namespace);
    let elt = xot.new_element(name);
    let attr = xot.new_attribute_node(alg_attribute_name, sig_info.canonicalization_method.clone());
    xot.append_attribute_node(elt, attr).unwrap();
    xot.append(sig_info_el, elt).unwrap();
    let name = xot.add_name_ns("SignatureMethod", namespace);
    let elt = xot.new_element(name);
    let attr = xot.new_attribute_node(alg_attribute_name, sig_info.signature_method.clone());
    xot.append_attribute_node(elt, attr).unwrap();
    xot.append(sig_info_el, elt).unwrap();
    let name = xot.add_name_ns("Reference", namespace);
    let ref_elt = xot.new_element(name);
    let name = xot.add_name("URI");
    let attr = xot.new_attribute_node(name, String::new());
    xot.append_attribute_node(ref_elt, attr).unwrap();
    let name = xot.add_name_ns("Transforms", namespace);
    let transforms_elt = xot.new_element(name);
    for tr in sig_info.reference.transforms.iter() {
        let name = xot.add_name_ns("Transform", namespace);
        let elt = xot.new_element(name);
        let attr = xot.new_attribute_node(alg_attribute_name, tr.clone());
        xot.append_attribute_node(elt, attr).unwrap();
        xot.append(transforms_elt, elt).unwrap();
    }
    xot.append(ref_elt, transforms_elt).unwrap();
    let name = xot.add_name_ns("DigestMethod", namespace);
    let elt = xot.new_element(name);
    let attr = xot.new_attribute_node(alg_attribute_name, sig_info.reference.digest_method.clone());
    xot.append_attribute_node(elt, attr).unwrap();
    xot.append(ref_elt, elt).unwrap();
    let name = xot.add_name_ns("DigestValue", namespace);
    let elt = xot.new_element(name);
    //println!("SIGN: Digest bytes: {:?}", sig_info.reference.digest_value);
    /*println!(
        "SIGN: Digest base64: {:?}",
        sig_info
            .reference
            .digest_value
            .base64_encode()
            .unwrap()
            .as_str()
    );*/
    xot.append_text(
        elt,
        sig_info
            .reference
            .digest_value
            .base64_encode()
            .unwrap()
            .as_str(),
    )
    .unwrap();
    xot.append(ref_elt, elt).unwrap();
    xot.append(sig_info_el, ref_elt).unwrap();
    xot.append(signature_el, sig_info_el).unwrap();
    let name = xot.add_name_ns("SignatureValue", namespace);
    let elt = xot.new_element(name);
    xot.append_text(elt, "TO_REPLACE_WITH_SIGNATURE").unwrap();
    xot.append(signature_el, elt).unwrap();
    let node_to_append = get_node_to_add_signature(&mut xot, root).unwrap();
    xot.append(node_to_append, signature_el).unwrap();
    xot.to_string(root).unwrap()
}

fn get_node_to_add_signature(xot: &mut Xot, root: Node) -> Option<Node> {
    XMLType::detect_type(xot, root).map(|t| t.get_node_to_add_signature(xot, root))
}

enum XMLType {
    Ech0222,
    Config,
}

impl XMLType {
    fn detection_str(&self) -> &str {
        match self {
            XMLType::Ech0222 => "http://www.ech.ch/xmlns/eCH-0222",
            XMLType::Config => "www.evoting.ch/xmlns/config",
        }
    }

    fn str_to_self(s: &str) -> Option<Self> {
        match s {
            s if s.contains(Self::Ech0222.detection_str()) => Some(Self::Ech0222),
            s if s.contains(Self::Config.detection_str()) => Some(Self::Config),
            _ => None,
        }
    }

    fn detect_type(xot: &Xot, root: Node) -> Option<Self> {
        let ns = xot.namespace_declarations(root);
        ns.iter()
            .find_map(|(_, ns)| Self::str_to_self(xot.namespace_str(*ns)))
    }

    fn get_prefix_namespace(&self, xot: &Xot, root: Node) -> Option<(PrefixId, NamespaceId)> {
        let ns = xot.namespace_declarations(root);
        ns.into_iter()
            .find(|(_, ns)| xot.namespace_str(*ns).contains(self.detection_str()))
    }

    fn get_node_to_add_signature(&self, xot: &mut Xot, root: Node) -> Node {
        match self {
            XMLType::Ech0222 => {
                let raw_data_delivery = xot.last_child(root).unwrap();
                let last_in_raw_data_delivery = xot.last_child(raw_data_delivery).unwrap();
                if xot.local_name_str(xot.node_name(last_in_raw_data_delivery).unwrap())
                    == "extension"
                {
                    return last_in_raw_data_delivery;
                }
                let (prefix, namespace) = self.get_prefix_namespace(xot, root).unwrap();
                let ext_name = xot.add_name_ns("extension", namespace);
                let ext_node = xot.new_element(ext_name);
                xot.append(raw_data_delivery, ext_node).unwrap();
                ext_node
            }
            XMLType::Config => root,
        }
    }
}

#[cfg(test)]
mod test_data {
    use std::path::PathBuf;

    use crate::test_data::{get_test_data_xml, get_test_data_xml_path};

    const CONFIG_FILENAME: &str = "configuration-anonymized.xml";
    const ECH0222_FILENAME: &str = "eCH-0222_v3-0_NE_20231124_TT05.xml";
    const ECH0222_WITHOUT_SIG_FILENAME: &str = "eCH-0222_v3-0_NE_20231124_TT05_without_sig.xml";
    const VERIFIER_KEYSTORE_FILENAME: &str = "local_direct_trust_keystore_verifier.p12";
    const VERIFIER_KEYSTORE_PWD_FILENAME: &str = "local_direct_trust_pw_verifier.txt";
    const CANTON_KEYSTORE_FILENAME: &str = "local_direct_trust_keystore_canton.p12";
    const CANTON_KEYSTORE_PWD_FILENAME: &str = "local_direct_trust_pw_canton.txt";
    const TALLY_KEYSTORE_FILENAME: &str = "local_direct_trust_keystore_sdm_tally.p12";
    const TALLY_KEYSTORE_PWD_FILENAME: &str = "local_direct_trust_pw_sdm_tally.txt";

    pub fn get_test_data_config() -> String {
        get_test_data_xml(CONFIG_FILENAME)
    }

    pub fn get_test_data_ech0222() -> String {
        get_test_data_xml(ECH0222_FILENAME)
    }

    pub fn get_test_data_ech0222_without_sig() -> String {
        get_test_data_xml(ECH0222_WITHOUT_SIG_FILENAME)
    }

    pub fn get_verifier_keystore_path() -> PathBuf {
        get_test_data_xml_path().join(VERIFIER_KEYSTORE_FILENAME)
    }

    pub fn get_verifier_keystore_pwd_path() -> PathBuf {
        get_test_data_xml_path().join(VERIFIER_KEYSTORE_PWD_FILENAME)
    }

    pub fn get_canton_keystore_path() -> PathBuf {
        get_test_data_xml_path().join(CANTON_KEYSTORE_FILENAME)
    }

    pub fn get_canton_keystore_pwd_path() -> PathBuf {
        get_test_data_xml_path().join(CANTON_KEYSTORE_PWD_FILENAME)
    }

    pub fn get_tally_keystore_path() -> PathBuf {
        get_test_data_xml_path().join(TALLY_KEYSTORE_FILENAME)
    }

    pub fn get_tally_keystore_pwd_path() -> PathBuf {
        get_test_data_xml_path().join(TALLY_KEYSTORE_PWD_FILENAME)
    }
}

#[cfg(test)]
mod test {
    use super::{test_data::*, *};
    use rust_ev_crypto_primitives::direct_trust::Keystore;
    use std::path::{Path, PathBuf};

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

    fn get_private_key(path: &Path, pwd: &Path) -> Secretkey {
        let keystore = Keystore::from_pkcs12(path, pwd).unwrap();
        keystore
            .secret_key_certificate()
            .unwrap()
            .signing_certificate()
            .secret_key()
            .clone()
            .unwrap()
    }

    #[test]
    fn test_verify_config() {
        let data = get_test_data_config();
        let res = verify_xml_signature(data.as_str(), &get_public_key("canton"));
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        assert_eq!(res.unwrap(), VerifyXMLSignatureResult::Success);
    }

    #[test]
    fn test_verify_ech0222() {
        let data = get_test_data_ech0222();
        let res = verify_xml_signature(data.as_str(), &get_public_key("sdm_tally"));
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        assert_eq!(res.unwrap(), VerifyXMLSignatureResult::Success);
    }

    #[test]
    fn test_ech0222_digest() {
        let data = get_test_data_ech0222();
        let data_without_sig = get_test_data_ech0222_without_sig();
        assert!(XMLWithXMLSignature::from_str(&data).is_ok());
        assert!(XMLWithXMLSignature::from_str(&data_without_sig).is_ok());
        assert_eq!(
            collect_xml_digest(&data).unwrap(),
            collect_xml_digest(&data_without_sig).unwrap()
        );
    }

    #[test]
    #[ignore = "Not working (problem with tabs and position of namespace declaration of ds"]
    fn test_sign_ech0222() {
        let data_without_sig = get_test_data_ech0222_without_sig();
        let sk = get_private_key(&get_tally_keystore_path(), &get_tally_keystore_pwd_path());
        let signed_xml_res = gen_xml_signature(&data_without_sig, &sk);
        assert!(signed_xml_res.is_ok(), "{:?}", signed_xml_res.unwrap_err());
        //println!("{}", signed_xml_res.as_ref().unwrap());
        let res = verify_xml_signature(&signed_xml_res.unwrap(), &get_public_key("sdm_tally"));
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        assert_eq!(res.unwrap(), VerifyXMLSignatureResult::Success);
    }

    #[test]
    #[ignore = "Not working (problem with tabs and position of namespace declaration of ds"]
    fn test_sign_ech0222_with_sig() {
        let data_without_sig = get_test_data_ech0222();
        let sk = get_private_key(&get_tally_keystore_path(), &get_tally_keystore_pwd_path());
        let signed_xml_res = gen_xml_signature(&data_without_sig, &sk);
        assert!(signed_xml_res.is_ok(), "{:?}", signed_xml_res.unwrap_err());
        let res = verify_xml_signature(&signed_xml_res.unwrap(), &get_public_key("sdm_tally"));
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        assert_eq!(res.unwrap(), VerifyXMLSignatureResult::Success);
    }

    #[test]
    #[ignore = "Not working (problem with tabs and position of namespace declaration of ds"]
    fn test_sign_config() {
        let data_without_sig = get_test_data_config();
        let sk = get_private_key(&get_canton_keystore_path(), &get_canton_keystore_pwd_path());
        let signed_xml_res = gen_xml_signature(&data_without_sig, &sk);
        assert!(signed_xml_res.is_ok(), "{:?}", signed_xml_res.unwrap_err());
        let res = verify_xml_signature(&signed_xml_res.unwrap(), &get_public_key("canton"));
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        assert_eq!(res.unwrap(), VerifyXMLSignatureResult::Success);
    }
}
