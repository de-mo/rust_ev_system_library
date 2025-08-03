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

use regex::Regex;
use roxmltree::{Document, Error as RoXMLTreeError, Node};
use rust_ev_crypto_primitives::{ByteArray, DecodeTrait};
use thiserror::Error;

#[derive(Error, Debug)]
/// Error with dataset
pub enum XMLSignatureError {
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
pub struct XMLSignature<'a> {
    pub input: &'a str,
    pub signature: Signature,
}

impl<'a> XMLSignature<'a> {
    pub fn from_str(xml_doc_as_str: &'a str) -> Result<Self, XMLSignatureError> {
        Ok(Self {
            input: xml_doc_as_str,
            signature: Signature::from_xml_str(xml_doc_as_str)?,
        })
    }

    pub fn remove_signature_from_orig(&self) -> String {
        match self.find_signature_str() {
            Some(s) => self.input.replace(s, ""),
            None => self.input.to_string(),
        }
    }

    fn find_signature_str(&self) -> Option<&str> {
        let rule = r"(<|<[^<]+:)Signature(.|\n|\r|\t)*(</|</\S+:)Signature>";
        let re = Regex::new(rule).unwrap();
        re.find(self.input).map(|m| m.as_str())
    }

    pub fn find_signed_info_str(&self) -> Option<&str> {
        let rule = r"(<|<[^<]+:)SignedInfo(.|\n|\r|\t)*(</|</\S+:)SignedInfo>";
        let re = Regex::new(rule).unwrap();
        re.find(self.input).map(|m| m.as_str())
    }

    pub fn find_canonalized_signed_info_str(&self) -> Option<String> {
        match self.find_signed_info_str() {
            Some(s) => Some(s.replace(
                "<ds:SignedInfo>",
                "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">",
            )),
            None => None,
        }
    }
}

impl Signature {
    pub fn from_xml_str(xml: &str) -> Result<Self, XMLSignatureError> {
        let doc = Document::parse(xml).map_err(|e| XMLSignatureError::Parse { source: e })?;
        let node = Signature::find_signature_node(&doc.root())
            .ok_or(XMLSignatureError::SignatureNotFound)?;
        Self::from_roxmltree(&node)
    }

    fn find_signature_node<'a, 'input>(node: &Node<'a, 'input>) -> Option<Node<'a, 'input>> {
        node.descendants().find(|n| n.has_tag_name("Signature"))
    }

    fn from_roxmltree(node: &Node<'_, '_>) -> Result<Self, XMLSignatureError> {
        let mut signature_value_str = text_from_child_node("SignatureValue", node)?.to_string();
        signature_value_str.retain(|c| !c.is_whitespace());
        Ok(Self {
            signed_info: SignedInfo::from_roxmltree_node(&find_child("SignedInfo", node)?)
                .map_err(|e| XMLSignatureError::DeSignedInfo {
                    source: Box::new(e),
                })?,
            signature_value: ByteArray::base64_decode(signature_value_str.as_str()).unwrap(),
        })
    }
}

fn find_child<'a, 'input, 'b>(
    tag: &'static str,
    node: &'b Node<'a, 'input>,
) -> Result<Node<'a, 'input>, XMLSignatureError> {
    node.children()
        .find(|n| n.has_tag_name(tag))
        .ok_or(XMLSignatureError::TagNotFound(tag))
}

fn text_from_child_node<'a, 'input, 'b>(
    tag: &'static str,
    node: &'b Node<'a, 'input>,
) -> Result<&'a str, XMLSignatureError> {
    let n = find_child(tag, node)?;
    n.text().ok_or(XMLSignatureError::TextMissing(tag))
}

fn attribute_from_child_node<'a, 'input, 'b>(
    tag: &'static str,
    attribute_name: &'static str,
    node: &'b Node<'a, 'input>,
) -> Result<&'a str, XMLSignatureError> {
    let n = find_child(tag, node)?;
    n.attribute(attribute_name)
        .ok_or(XMLSignatureError::AttributeNotFound(attribute_name, tag))
}

impl SignedInfo {
    pub fn from_roxmltree_node(node: &Node) -> Result<Self, XMLSignatureError> {
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
    pub fn from_roxmltree_node(node: &Node) -> Result<Self, XMLSignatureError> {
        Ok(Self {
            uri: node
                .attribute("URI")
                .ok_or(XMLSignatureError::AttributeNotFound("URI", "Reference"))?
                .to_string(),
            transforms: find_child("Transforms", node)?
                .children()
                .map(|n| {
                    n.attribute("Algorithm")
                        .ok_or(XMLSignatureError::AttributeNotFound(
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
        let xml_signature = XMLSignature::from_str(data.as_str()).unwrap();
        let res_config = xml_signature.find_signature_str();
        assert!(res_config.is_some());
        assert!(res_config.unwrap().starts_with("<ds:Signature"));
        assert!(res_config.unwrap().ends_with("</ds:Signature>"));
        let data = get_test_data_ech0222();
        let xml_signature = XMLSignature::from_str(data.as_str()).unwrap();
        let res_config = xml_signature.find_signature_str();
        assert!(res_config.is_some());
        assert!(res_config.unwrap().starts_with("<ds:Signature"));
        assert!(res_config.unwrap().ends_with("</ds:Signature>"));
    }

    #[test]
    fn test_find_signed_info_str() {
        let data = get_test_data_config();
        let xml_signature = XMLSignature::from_str(data.as_str()).unwrap();
        let res_config = xml_signature.find_signed_info_str();
        assert!(res_config.is_some());
        assert!(res_config.unwrap().starts_with("<ds:SignedInfo"));
        assert!(res_config.unwrap().ends_with("</ds:SignedInfo>"));
        let data = get_test_data_ech0222();
        let xml_signature = XMLSignature::from_str(data.as_str()).unwrap();
        let res_config = xml_signature.find_signed_info_str();
        assert!(res_config.is_some());
        assert!(res_config.unwrap().starts_with("<ds:SignedInfo"));
        assert!(res_config.unwrap().ends_with("</ds:SignedInfo>"));
    }

    #[test]
    fn test_signature_from() {
        let data = get_test_data_config();
        let res = Signature::from_xml_str(data.as_str());
        assert!(res.is_ok(), "{:?}", res.unwrap_err());
        let data = get_test_data_ech0222();
        let res = Signature::from_xml_str(data.as_str());
        assert!(res.is_ok(), "{:?}", res.unwrap_err())
    }
}
