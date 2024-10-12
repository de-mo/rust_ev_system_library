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

use rust_ev_crypto_primitives::{
    elgamal::EncryptionParameters, EncodeTrait, HashError, HashableMessage, RecursiveHashTrait,
};
use thiserror::Error;

use super::PTable;

/// Enum representing the errors during the algorithms regardinf election event context
#[derive(Error, Debug)]
pub enum ElectionEventContextError {
    #[error(transparent)]
    HashError(#[from] HashError),
}

/// Context for Verification card sets. Fields according specification of Swiss Post.
pub struct VerificationCardSetContext<'f, 'g, 'h, 'i, 'j, 'k, 'l, 'm> {
    pub vcs: &'f str,
    pub vcs_alias: &'g str,
    pub vcs_desc: &'h str,
    pub bb: &'i str,
    pub t_s_bb: &'j str,
    pub t_f_bb: &'k str,
    pub test_ballot_box: bool,
    pub upper_n_upper_e: usize,
    pub grace_period: usize,
    pub p_table: &'l PTable,
    pub encryption_parameters: &'m EncryptionParameters,
}

/// Context for GetHashElectionEventContext. Fields according specification of Swiss Post.
pub struct GetHashElectionEventContextContext<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, 'i, 'j, 'k, 'l, 'm> {
    pub encryption_parameters: &'a EncryptionParameters,
    pub ee: &'b str,
    pub ee_alias: &'b str,
    pub ee_descr: &'c str,
    pub vcs_contexts: Vec<VerificationCardSetContext<'f, 'g, 'h, 'i, 'j, 'k, 'l, 'm>>,
    pub t_s_ee: &'d str,
    pub t_f_ee: &'e str,
    pub n_max: usize,
    pub phi_max: usize,
    pub delta_max: usize,
}

/// Algorithm 3.2
///
/// Return a [Vec<String>] with the unsuccessfully verifications. Empty if the verification is ok
///
/// Error [ElectionEventContextError] if something is going wrong
pub fn get_hash_election_event_context(
    context: &GetHashElectionEventContextContext,
) -> Result<String, ElectionEventContextError> {
    Ok(HashableMessage::from(context)
        .recursive_hash()
        .map_err(ElectionEventContextError::HashError)?
        .base64_encode()
        .unwrap())
}

impl<'hash> From<&'hash PTable> for HashableMessage<'hash> {
    fn from(value: &'hash PTable) -> Self {
        HashableMessage::from(
            value
                .0
                .iter()
                .map(|e| {
                    HashableMessage::from(vec![
                        HashableMessage::from(&e.actual_voting_option),
                        HashableMessage::from(&e.encoded_voting_option),
                        HashableMessage::from(&e.semantic_information),
                        HashableMessage::from(&e.correctness_information),
                    ])
                })
                .collect::<Vec<_>>(),
        )
    }
}

impl<'f, 'g, 'h, 'i, 'j, 'k, 'l, 'm, 'hash>
    From<&'hash VerificationCardSetContext<'f, 'g, 'h, 'i, 'j, 'k, 'l, 'm>>
    for HashableMessage<'hash>
where
    'hash: 'f + 'g + 'h + 'i + 'j + 'k + 'l + 'm,
{
    fn from(value: &'hash VerificationCardSetContext<'f, 'g, 'h, 'i, 'j, 'k, 'l, 'm>) -> Self {
        let h_p_table_j = HashableMessage::from(vec![
            HashableMessage::from(value.encryption_parameters),
            HashableMessage::from(value.p_table),
        ]);
        HashableMessage::from(vec![
            HashableMessage::from(value.vcs),
            HashableMessage::from(value.vcs_alias),
            HashableMessage::from(value.vcs_desc),
            HashableMessage::from(value.bb),
            HashableMessage::from(value.t_s_bb),
            HashableMessage::from(value.t_f_bb),
            HashableMessage::from(match value.test_ballot_box {
                true => "true".to_string(),
                false => "false".to_string(),
            }),
            HashableMessage::from(value.upper_n_upper_e),
            HashableMessage::from(value.grace_period),
            h_p_table_j,
        ])
    }
}

impl<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, 'i, 'j, 'k, 'l, 'm, 'hash>
    From<
        &'hash GetHashElectionEventContextContext<
            'a,
            'b,
            'c,
            'd,
            'e,
            'f,
            'g,
            'h,
            'i,
            'j,
            'k,
            'l,
            'm,
        >,
    > for HashableMessage<'hash>
where
    'hash: 'a + 'b + 'c + 'd + 'e + 'f + 'g + 'h + 'i + 'j + 'k + 'l + 'm,
{
    fn from(
        _value: &'hash GetHashElectionEventContextContext<
            'a,
            'b,
            'c,
            'd,
            'e,
            'f,
            'g,
            'h,
            'i,
            'j,
            'k,
            'l,
            'm,
        >,
    ) -> Self {
        todo!()
    }
}
