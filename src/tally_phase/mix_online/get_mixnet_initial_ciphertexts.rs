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

//! Module implementing the algorithms for the tally phase

use rust_ev_crypto_primitives::{
    elgamal::{Ciphertext, EncryptionParameters},
    ConstantsTrait, EncodeTrait, HashableMessage, Integer, RecursiveHashTrait, VerifyDomainTrait,
};

use super::MixOnlineError;

pub struct GetMixnetInitialCiphertextsOuput {
    pub hvc_j: String,
    pub c_init_j: Vec<Ciphertext>,
}

pub struct GetMixnetInitialCiphertextsContext<'a> {
    pub eg: &'a EncryptionParameters,
    pub _upper_n_upper_e: usize,
    pub delta: usize,
    pub el_pk: &'a [Integer],
}

pub struct GetMixnetInitialCiphertextsInput<'a> {
    pub vc_map_j: &'a [(&'a str, &'a Ciphertext)],
}

impl<'a> GetMixnetInitialCiphertextsInput<'a> {
    fn vc_map_j_to_hashable_message(&'a self) -> HashableMessage<'a> {
        HashableMessage::from(
            self.vc_map_j
                .iter()
                .map(|(vc_i, e_1_i)| {
                    HashableMessage::from(vec![
                        HashableMessage::from(*vc_i),
                        HashableMessage::from(*e_1_i),
                    ])
                })
                .collect::<Vec<_>>(),
        )
    }
}

impl<'a, 'b> VerifyDomainTrait<MixOnlineError>
    for (
        &GetMixnetInitialCiphertextsContext<'a>,
        &GetMixnetInitialCiphertextsInput<'b>,
    )
{
    fn verifiy_domain(&self) -> Vec<MixOnlineError> {
        if self.0._upper_n_upper_e < self.1.vc_map_j.len() {
            return vec![MixOnlineError::GetMixnetInitialCiphertextsInput(format!(
                "N_E (={}) must be greater or equal than N_C (={})",
                self.0._upper_n_upper_e,
                self.1.vc_map_j.len()
            ))];
        }
        vec![]
    }
}

impl GetMixnetInitialCiphertextsOuput {
    /// Algorithm 6.1
    pub fn get_mixnet_initial_ciphertexts(
        context: &GetMixnetInitialCiphertextsContext,
        input: &GetMixnetInitialCiphertextsInput,
    ) -> Result<Self, MixOnlineError> {
        let mut vc_map_j_ordered = input.vc_map_j.to_vec();
        vc_map_j_ordered.sort_by(|x, y| x.0.cmp(y.0));
        let mut c_init_j = vc_map_j_ordered
            .iter()
            .map(|(_, e_1_i)| e_1_i)
            .cloned()
            .cloned()
            .collect::<Vec<_>>();
        if input.vc_map_j.len() < 2 {
            let vec_1 = vec![Integer::one().clone(); context.delta];
            let e_trivial =
                Ciphertext::get_ciphertext(context.eg, &vec_1, Integer::one(), context.el_pk)
                    .map_err(|e| {
                        MixOnlineError::GetMixnetInitialCiphertextsProcess(format!(
                            "Error getting trivial ciphertext: {}",
                            e
                        ))
                    })?;
            c_init_j.push(e_trivial.clone());
            c_init_j.push(e_trivial);
        };
        let hvc_j = input
            .vc_map_j_to_hashable_message()
            .recursive_hash()
            .map_err(|e| {
                MixOnlineError::GetMixnetInitialCiphertextsProcess(format!(
                    "Error calculating hvc_j: {}",
                    e
                ))
            })?
            .base64_encode()
            .unwrap();
        Ok(Self { hvc_j, c_init_j })
    }
}
