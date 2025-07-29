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

use super::{ElectoralModelError, ElectoralModelErrorRepr};
use rust_ev_crypto_primitives::HashableMessage;
use std::{collections::HashSet, fmt::Display};

const BLANK: &str = "BLANK";
const WRITE_IN: &str = "WRITE_IN";

/// Element in pTable according the spefication of Swiss Post
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PTableElement {
    pub actual_voting_option: String,
    pub encoded_voting_option: usize,
    pub semantic_information: String,
    pub correctness_information: String,
}

/// pTable according the spefication of Swiss Post
pub type PTable = Vec<PTableElement>;

impl Display for PTableElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "({},{},{},{})",
            self.actual_voting_option,
            self.encoded_voting_option,
            self.semantic_information,
            self.correctness_information
        )
    }
}

impl PTableTrait for PTable {
    fn get_elements(&self) -> &[PTableElement] {
        self.as_slice()
    }
}

pub trait PTableTrait {
    /// Get the slice of elements
    fn get_elements(&self) -> &[PTableElement];

    /// Algorithm 3.3
    fn get_encoded_voting_options(
        &self,
        v_prime: &[&str],
    ) -> Result<Vec<usize>, ElectoralModelError> {
        let m_prime = v_prime.len();
        if m_prime > self.n() {
            return Err(ElectoralModelError::from(
                ElectoralModelErrorRepr::GetEncodedVotingOptionsInput(format!(
                    "m' {m_prime} must be less or equal n"
                )),
            ));
        }
        for v_prime_i in v_prime.iter() {
            if !self.contains_actual_voting_option(v_prime_i) {
                return Err(ElectoralModelError::from(
                    ElectoralModelErrorRepr::GetEncodedVotingOptionsInput(format!(
                        "Voting option {v_prime_i} not in pTable"
                    )),
                ));
            }
        }
        if m_prime != v_prime.iter().collect::<HashSet<_>>().len() {
            return Err(ElectoralModelError::from(
                ElectoralModelErrorRepr::GetEncodedVotingOptionsInput(
                    "Voting options are not distinct".to_string(),
                ),
            ));
        }
        Ok(self
            .get_elements()
            .iter()
            .filter(|e| m_prime == 0 || v_prime.contains(&e.actual_voting_option.as_str()))
            .map(|e| e.encoded_voting_option)
            .collect())
    }

    /// Algorithm 3.4
    fn get_actual_voting_options(
        &self,
        p_prime: &[usize],
    ) -> Result<Vec<&String>, ElectoralModelError> {
        let m_prime = p_prime.len();
        if m_prime > self.n() {
            return Err(ElectoralModelError::from(
                ElectoralModelErrorRepr::GetActualVotingOptionsInput(format!(
                    "m' {m_prime} must be less or equal n"
                )),
            ));
        }
        for p_prime_i in p_prime.iter() {
            if !self.contains_encoded_voting_option(p_prime_i) {
                return Err(ElectoralModelError::from(
                    ElectoralModelErrorRepr::GetActualVotingOptionsInput(format!(
                        "Voting option {p_prime_i} not in pTable"
                    )),
                ));
            }
        }
        if m_prime != p_prime.iter().collect::<HashSet<_>>().len() {
            return Err(ElectoralModelError::from(
                ElectoralModelErrorRepr::GetActualVotingOptionsInput(
                    "Voting options are not distinct".to_string(),
                ),
            ));
        }
        Ok(self
            .get_elements()
            .iter()
            .filter(|e| m_prime == 0 || p_prime.contains(&e.encoded_voting_option))
            .map(|e| &e.actual_voting_option)
            .collect())
    }

    /// Algorithm 3.5
    fn get_semantic_information(&self) -> Vec<&String> {
        self.get_elements()
            .iter()
            .map(|e| &e.semantic_information)
            .collect()
    }

    /// Algorithm 3.6
    fn get_correctness_information<'a>(
        &'a self,
        v_prime: &[&str],
    ) -> Result<Vec<&'a String>, ElectoralModelError> {
        let m_prime = v_prime.len();
        if m_prime > self.n() {
            return Err(ElectoralModelError::from(
                ElectoralModelErrorRepr::GetCorrectnessInformationInput(format!(
                    "m' {m_prime} must be less or equal n"
                )),
            ));
        }
        for v_prime_i in v_prime.iter() {
            if !self.contains_actual_voting_option(v_prime_i) {
                return Err(ElectoralModelError::from(
                    ElectoralModelErrorRepr::GetCorrectnessInformationInput(format!(
                        "Voting option {v_prime_i} not in pTable"
                    )),
                ));
            }
        }
        if m_prime != v_prime.iter().collect::<HashSet<_>>().len() {
            return Err(ElectoralModelError::from(
                ElectoralModelErrorRepr::GetCorrectnessInformationInput(
                    "Voting options are not distinct".to_string(),
                ),
            ));
        }
        Ok(self
            .get_elements()
            .iter()
            .filter(|e| m_prime == 0 || v_prime.contains(&e.actual_voting_option.as_str()))
            .map(|e| &e.correctness_information)
            .collect())
    }

    ///  Algorithm 3.7
    fn get_blank_correctness_information(&self) -> Result<Vec<&str>, ElectoralModelError> {
        let res = self
            .get_elements()
            .iter()
            .filter(|e| e.semantic_information.starts_with(BLANK))
            .map(|e| e.correctness_information.as_str())
            .collect::<Vec<_>>();
        if res.is_empty() {
            return Err(ElectoralModelError::from(
                ElectoralModelErrorRepr::GetBlankCorrectnessInformationOutput(
                    "No blank found".to_string(),
                ),
            ));
        }
        Ok(res)
    }

    ///  Algorithm 3.8
    fn get_write_in_encoded_voting_options(&self) -> Vec<usize> {
        self.get_elements()
            .iter()
            .filter(|e| e.semantic_information.starts_with(WRITE_IN))
            .map(|e| e.encoded_voting_option)
            .collect::<Vec<_>>()
    }

    ///  Algorithm 3.9
    fn get_psi(&self) -> Result<usize, ElectoralModelError> {
        Ok(self.get_blank_correctness_information()?.len())
    }

    ///  Algorithm 3.10
    fn get_delta(&self) -> usize {
        self.get_write_in_encoded_voting_options().len() + 1
    }

    /// Size of pTable
    fn n(&self) -> usize {
        self.get_elements().len()
    }

    /// Test if pTable contains the given acutal voting Option
    fn contains_actual_voting_option(&self, actual_voting_option: &str) -> bool {
        self.get_elements()
            .iter()
            .any(|e| e.actual_voting_option == actual_voting_option)
    }

    /// Test if pTable contains the given encoded voting Option
    fn contains_encoded_voting_option(&self, encoded_voting_option: &usize) -> bool {
        self.get_elements()
            .iter()
            .any(|e| &e.encoded_voting_option == encoded_voting_option)
    }
}

impl<'a> From<&'a PTableElement> for HashableMessage<'a> {
    fn from(value: &'a PTableElement) -> Self {
        Self::from(vec![
            Self::from(&value.actual_voting_option),
            Self::from(&value.encoded_voting_option),
            Self::from(&value.semantic_information),
            Self::from(&value.correctness_information),
        ])
    }
}

#[cfg(test)]
pub(super) mod test {
    use serde_json::Value;

    use super::*;
    use crate::test_data::get_prime_tables_1;

    fn json_to_p_table_element(value: &Value) -> PTableElement {
        PTableElement {
            actual_voting_option: value["actualVotingOption"].as_str().unwrap().to_string(),
            encoded_voting_option: value["encodedVotingOption"].as_u64().unwrap() as usize,
            semantic_information: value["semanticInformation"].as_str().unwrap().to_string(),
            correctness_information: value["correctnessInformation"]
                .as_str()
                .unwrap()
                .to_string(),
        }
    }

    pub fn json_to_p_table(value: &Value) -> PTable {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(json_to_p_table_element)
            .collect()
    }
    #[test]
    fn test_get_write_in_encoded_voting_options() {
        let json = get_prime_tables_1();
        let p_table = json_to_p_table(&json["pTable"]);
        print!("{:?}", p_table);
        assert_eq!(p_table.get_write_in_encoded_voting_options(), vec![43])
    }
}
