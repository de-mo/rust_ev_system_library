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

use super::ElectoralModelError;
use std::collections::HashSet;

const BLANK: &str = "BLANK";
const WRITE_IN: &str = "WRITE_IN";

#[derive(Debug, Clone)]
pub struct PTableElement {
    pub actual_voting_option: String,
    pub encoded_voting_option: usize,
    pub semantic_infomation: String,
    pub correctness_information: String,
}
#[derive(Debug, Clone)]
pub struct PTable(pub Vec<PTableElement>);

impl PTable {
    /// Algorithm 3.3
    pub fn get_encoded_voting_options(
        &self,
        v_prime: &[&str],
    ) -> Result<Vec<usize>, ElectoralModelError> {
        let m_prime = v_prime.len();
        if m_prime > self.n() {
            return Err(ElectoralModelError::GetEncodedVotingOptionsInput(format!(
                "m' {m_prime} must be less or equal n"
            )));
        }
        for v_prime_i in v_prime.iter() {
            if !self.contains_actual_voting_option(v_prime_i) {
                return Err(ElectoralModelError::GetEncodedVotingOptionsInput(format!(
                    "Voting option {v_prime_i} not in pTable"
                )));
            }
        }
        if m_prime != v_prime.iter().collect::<HashSet<_>>().len() {
            return Err(ElectoralModelError::GetEncodedVotingOptionsInput(
                "Voting options are not distinct".to_string(),
            ));
        }
        Ok(self
            .0
            .iter()
            .filter(|e| m_prime == 0 || v_prime.contains(&e.actual_voting_option.as_str()))
            .map(|e| e.encoded_voting_option)
            .collect())
    }

    /// Algorithm 3.4
    pub fn get_actual_voting_options(
        &self,
        p_prime: &[usize],
    ) -> Result<Vec<String>, ElectoralModelError> {
        let m_prime = p_prime.len();
        if m_prime > self.n() {
            return Err(ElectoralModelError::GetActualVotingOptionsInput(format!(
                "m' {m_prime} must be less or equal n"
            )));
        }
        for p_prime_i in p_prime.iter() {
            if !self.contains_encoded_voting_option(p_prime_i) {
                return Err(ElectoralModelError::GetActualVotingOptionsInput(format!(
                    "Voting option {p_prime_i} not in pTable"
                )));
            }
        }
        if m_prime != p_prime.iter().collect::<HashSet<_>>().len() {
            return Err(ElectoralModelError::GetActualVotingOptionsInput(
                "Voting options are not distinct".to_string(),
            ));
        }
        Ok(self
            .0
            .iter()
            .filter(|e| m_prime == 0 || p_prime.contains(&e.encoded_voting_option))
            .map(|e| e.actual_voting_option.clone())
            .collect())
    }

    /// Algorithm 3.6
    pub fn get_correctness_information(
        &self,
        v_prime: &[&str],
    ) -> Result<Vec<String>, ElectoralModelError> {
        let m_prime = v_prime.len();
        if m_prime > self.n() {
            return Err(ElectoralModelError::GetCorrectnessInformationInput(
                format!("m' {m_prime} must be less or equal n"),
            ));
        }
        for v_prime_i in v_prime.iter() {
            if !self.contains_actual_voting_option(v_prime_i) {
                return Err(ElectoralModelError::GetCorrectnessInformationInput(
                    format!("Voting option {v_prime_i} not in pTable"),
                ));
            }
        }
        if m_prime != v_prime.iter().collect::<HashSet<_>>().len() {
            return Err(ElectoralModelError::GetCorrectnessInformationInput(
                "Voting options are not distinct".to_string(),
            ));
        }
        Ok(self
            .0
            .iter()
            .filter(|e| m_prime == 0 || v_prime.contains(&e.actual_voting_option.as_str()))
            .map(|e| e.correctness_information.clone())
            .collect())
    }

    ///  Algorithm 3.7
    pub fn get_blank_correctness_information(&self) -> Result<Vec<&str>, ElectoralModelError> {
        let res = self
            .0
            .iter()
            .filter(|e| e.semantic_infomation.starts_with(BLANK))
            .map(|e| e.correctness_information.as_str())
            .collect::<Vec<_>>();
        if res.is_empty() {
            return Err(ElectoralModelError::GetBlankCorrectnessInformationOutput(
                "No blank found".to_string(),
            ));
        }
        Ok(res)
    }

    ///  Algorithm 3.8
    pub fn get_write_in_encoded_voting_options(&self) -> Vec<usize> {
        self.0
            .iter()
            .filter(|e| e.semantic_infomation.starts_with(WRITE_IN))
            .map(|e| e.encoded_voting_option)
            .collect::<Vec<_>>()
    }

    ///  Algorithm 3.9
    pub fn get_psi(&self) -> Result<usize, ElectoralModelError> {
        Ok(self.get_blank_correctness_information()?.len())
    }

    ///  Algorithm 3.10
    pub fn get_delta(&self) -> usize {
        self.get_write_in_encoded_voting_options().len() + 1
    }

    /// Size of pTable
    pub fn n(&self) -> usize {
        self.0.len()
    }

    /// Test if pTable contains the given acutal voting Option
    pub fn contains_actual_voting_option(&self, actual_voting_option: &str) -> bool {
        self.0
            .iter()
            .any(|e| e.actual_voting_option == actual_voting_option)
    }

    /// Test if pTable contains the given encoded voting Option
    pub fn contains_encoded_voting_option(&self, encoded_voting_option: &usize) -> bool {
        self.0
            .iter()
            .any(|e| &e.encoded_voting_option == encoded_voting_option)
    }
}

#[cfg(test)]
mod test_json_data {
    use super::{PTable, PTableElement};
    use serde_json::Value;

    fn json_to_p_table_element(value: &Value) -> PTableElement {
        PTableElement {
            actual_voting_option: value["actualVotingOption"].as_str().unwrap().to_string(),
            encoded_voting_option: value["encodedVotingOption"].as_u64().unwrap() as usize,
            semantic_infomation: value["semanticInformation"].as_str().unwrap().to_string(),
            correctness_information: value["correctnessInformation"]
                .as_str()
                .unwrap()
                .to_string(),
        }
    }

    pub fn json_to_p_table(value: &Value) -> PTable {
        PTable(
            value
                .as_array()
                .unwrap()
                .iter()
                .map(json_to_p_table_element)
                .collect(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::test_json_data::json_to_p_table;
    use crate::test_json_data::get_prime_tables_1;

    #[test]
    fn test_get_write_in_encoded_voting_options() {
        let json = get_prime_tables_1();
        let p_table = json_to_p_table(&json["pTable"]);
        print!("{:?}", p_table);
        assert_eq!(p_table.get_write_in_encoded_voting_options(), vec![43])
    }
}
