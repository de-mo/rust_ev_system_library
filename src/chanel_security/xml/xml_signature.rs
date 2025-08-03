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

use regex::Regex;
use roxmltree::{Document, Error as RoXMLTreeError, Node};
use rust_ev_crypto_primitives::{ByteArray, DecodeTrait};
use thiserror::Error;

#[derive(Error, Debug)]
/// Error with dataset
pub enum XMLWithXMLSignatureError {
    #[error("Error parsing the string")]
    Parse { source: RoXMLTreeError },
    #[error("Signature not found")]
    SignatureNotFound,
    #[error("Tag {0} not found")]
    TagNotFound(&'static str),
    #[error("Attribute {0} not found for tag {1}")]
    AttributeNotFound(&'static str, &'static str),
    #[error("No text for Tag {0} not found")]
    TextMissing(&'static str),
    #[error("Error deserializing SignedInfo")]
    DeSignedInfo { source: Box<Self> },
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Reference {
    pub uri: String,
    pub transforms: Vec<String>,
    pub digest_method: String,
    pub digest_value: ByteArray,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SignedInfo {
    pub canonicalization_method: String,
    pub signature_method: String,
    pub reference: Reference,
}

#[derive(Debug)]
pub struct Signature {
    pub signed_info: SignedInfo,
    pub signature_value: ByteArray,
}

#[derive(Debug)]
pub struct XMLWithXMLSignature<'a> {
    input: &'a str,
    pub signature: Signature,
    pub namespace_uri: String,
    pub namespace_prefix: String,
}

impl<'a> XMLWithXMLSignature<'a> {
    pub fn from_str(xml_doc_as_str: &'a str) -> Result<Self, XMLWithXMLSignatureError> {
        let doc = Document::parse(xml_doc_as_str)
            .map_err(|e| XMLWithXMLSignatureError::Parse { source: e })?;
        let signature = Signature::from_roxmltree_doc(&doc)?;
        let node = doc
            .root()
            .descendants()
            .find(|n| n.has_tag_name("Signature"))
            .unwrap();
        let uri = node.tag_name().namespace().unwrap();
        let prefix = node.lookup_prefix(uri).unwrap();
        Ok(Self {
            input: xml_doc_as_str,
            signature,
            namespace_uri: uri.to_string(),
            namespace_prefix: prefix.to_string(),
        })
    }

    pub fn input(&self) -> &str {
        self.input
    }

    pub fn remove_signature_from_orig(&self) -> String {
        match self.find_signature_str() {
            Some(s) => self.input().replace(s, ""),
            None => self.input().to_string(),
        }
    }

    fn find_signature_str(&self) -> Option<&str> {
        let rule = r"(<|<[^<]+:)Signature(.|\n|\r|\t)*(</|</\S+:)Signature>";
        let re = Regex::new(rule).unwrap();
        re.find(self.input()).map(|m| m.as_str())
    }

    fn find_signed_info_str(&self) -> Option<&str> {
        let rule = r"(<|<[^<]+:)SignedInfo(.|\n|\r|\t)*(</|</\S+:)SignedInfo>";
        let re = Regex::new(rule).unwrap();
        re.find(self.input()).map(|m| m.as_str())
    }

    pub fn get_canonalized_signed_info_str(&self) -> Option<String> {
        match self.find_signed_info_str() {
            Some(s) => Some(
                s.replace(
                    "<ds:SignedInfo>",
                    format!(
                        "<ds:SignedInfo xmlns:{}=\"{}\">",
                        self.namespace_prefix, self.namespace_uri
                    )
                    .as_str(),
                ),
            ),
            None => None,
        }
    }
}

impl Signature {
    pub fn from_roxmltree_doc(document: &Document<'_>) -> Result<Self, XMLWithXMLSignatureError> {
        let node = &document
            .descendants()
            .find(|n| n.has_tag_name("Signature"))
            .ok_or(XMLWithXMLSignatureError::SignatureNotFound)?;
        Self::from_roxmltree_node(&node)
    }

    fn from_roxmltree_node(node: &Node<'_, '_>) -> Result<Self, XMLWithXMLSignatureError> {
        let mut signature_value_str = text_from_child_node("SignatureValue", node)?.to_string();
        signature_value_str.retain(|c| !c.is_whitespace());
        Ok(Self {
            signed_info: SignedInfo::from_roxmltree_node(&find_child("SignedInfo", node)?)
                .map_err(|e| XMLWithXMLSignatureError::DeSignedInfo {
                    source: Box::new(e),
                })?,
            signature_value: ByteArray::base64_decode(signature_value_str.as_str()).unwrap(),
        })
    }
}

fn find_child<'a, 'input, 'b>(
    tag: &'static str,
    node: &'b Node<'a, 'input>,
) -> Result<Node<'a, 'input>, XMLWithXMLSignatureError> {
    node.children()
        .find(|n| n.has_tag_name(tag))
        .ok_or(XMLWithXMLSignatureError::TagNotFound(tag))
}

fn text_from_child_node<'a, 'input, 'b>(
    tag: &'static str,
    node: &'b Node<'a, 'input>,
) -> Result<&'a str, XMLWithXMLSignatureError> {
    let n = find_child(tag, node)?;
    n.text().ok_or(XMLWithXMLSignatureError::TextMissing(tag))
}

fn attribute_from_child_node<'a, 'input, 'b>(
    tag: &'static str,
    attribute_name: &'static str,
    node: &'b Node<'a, 'input>,
) -> Result<&'a str, XMLWithXMLSignatureError> {
    let n = find_child(tag, node)?;
    n.attribute(attribute_name)
        .ok_or(XMLWithXMLSignatureError::AttributeNotFound(
            attribute_name,
            tag,
        ))
}

impl SignedInfo {
    pub fn from_roxmltree_node(node: &Node) -> Result<Self, XMLWithXMLSignatureError> {
        Ok(Self {
            canonicalization_method: attribute_from_child_node(
                "CanonicalizationMethod",
                "Algorithm",
                node,
            )?
            .to_string(),
            signature_method: attribute_from_child_node("SignatureMethod", "Algorithm", node)?
                .to_string(),
            reference: Reference::from_roxmltree_node(&find_child("Reference", node)?)?,
        })
    }
}

impl Reference {
    pub fn from_roxmltree_node(node: &Node) -> Result<Self, XMLWithXMLSignatureError> {
        Ok(Self {
            uri: node
                .attribute("URI")
                .ok_or(XMLWithXMLSignatureError::AttributeNotFound(
                    "URI",
                    "Reference",
                ))?
                .to_string(),
            transforms: find_child("Transforms", node)?
                .children()
                .map(|n| {
                    n.attribute("Algorithm")
                        .ok_or(XMLWithXMLSignatureError::AttributeNotFound(
                            "Algorithm",
                            "Transform",
                        ))
                        .map(|s| s.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?,
            digest_method: attribute_from_child_node("DigestMethod", "Algorithm", node)?
                .to_string(),
            digest_value: ByteArray::base64_decode(text_from_child_node("DigestValue", node)?)
                .unwrap(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::chanel_security::xml::test_data::{get_test_data_config, get_test_data_ech0222};

    use super::*;

    #[test]
    fn test_find_signature_str() {
        let data = get_test_data_config();
        let xml_signature = XMLWithXMLSignature::from_str(data.as_str()).unwrap();
        let res_config = xml_signature.find_signature_str();
        assert!(res_config.is_some());
        assert!(res_config.unwrap().starts_with("<ds:Signature"));
        assert!(res_config.unwrap().ends_with("</ds:Signature>"));
        let data = get_test_data_ech0222();
        let xml_signature = XMLWithXMLSignature::from_str(data.as_str()).unwrap();
        let res_config = xml_signature.find_signature_str();
        assert!(res_config.is_some());
        assert!(res_config.unwrap().starts_with("<ds:Signature"));
        assert!(res_config.unwrap().ends_with("</ds:Signature>"));
    }

    #[test]
    fn test_find_signed_info_str() {
        let data = get_test_data_config();
        let xml_signature = XMLWithXMLSignature::from_str(data.as_str()).unwrap();
        let res_config = xml_signature.find_signed_info_str();
        assert!(res_config.is_some());
        assert!(res_config.unwrap().starts_with("<ds:SignedInfo"));
        assert!(res_config.unwrap().ends_with("</ds:SignedInfo>"));
        let data = get_test_data_ech0222();
        let xml_signature = XMLWithXMLSignature::from_str(data.as_str()).unwrap();
        let res_config = xml_signature.find_signed_info_str();
        assert!(res_config.is_some());
        assert!(res_config.unwrap().starts_with("<ds:SignedInfo"));
        assert!(res_config.unwrap().ends_with("</ds:SignedInfo>"));
    }

    #[test]
    fn test_from_str() {
        let data = get_test_data_config();
        let res = XMLWithXMLSignature::from_str(&data);
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        let res = XMLWithXMLSignature::from_str(&data);
        assert!(res.is_ok(), "{:?}", res.unwrap_err())
    }
}
