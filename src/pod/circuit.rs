use std::collections::HashMap;

use crate::pod::HashableEntryValue;
use crate::pod::OperationCmd;
use crate::schnorr_prover::{
    MessageTarget, SchnorrBuilder, SchnorrPublicKeyTarget, SchnorrSignatureTarget,
    SignatureVerifierBuilder,
};
use anyhow::{anyhow, Result};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::{self, CircuitBuilder};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::log2_ceil;

use super::util::hash_string_to_field;
use super::PODProof;
use super::{Entry, HashablePayload, Origin, ScalarOrVec, Statement, POD};

const NUM_BITS: usize = 32;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct OriginTarget {
    pub origin_id: Target,
    pub gadget_id: Target,
}

impl OriginTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<GoldilocksField, 2>) -> Self {
        Self {
            origin_id: builder.add_virtual_target(),
            gadget_id: builder.add_virtual_target(),
        }
    }

    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        origin: &Origin,
    ) -> Result<()> {
        pw.set_target(self.origin_id, origin.origin_id)?;
        pw.set_target(
            self.gadget_id,
            GoldilocksField::from_canonical_u64(origin.gadget_id as usize as u64),
        )?;
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct StatementTarget {
    pub predicate: Target,
    pub origin1: OriginTarget,
    pub key1: Target,
    pub origin2: OriginTarget,
    pub key2: Target,
    pub origin3: OriginTarget,
    pub key3: Target,
    pub optional_value: Target,
}

impl StatementTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<GoldilocksField, 2>) -> Self {
        Self {
            predicate: builder.add_virtual_target(),
            origin1: OriginTarget::new_virtual(builder),
            key1: builder.add_virtual_target(),
            origin2: OriginTarget::new_virtual(builder),
            key2: builder.add_virtual_target(),
            origin3: OriginTarget::new_virtual(builder),
            key3: builder.add_virtual_target(),
            optional_value: builder.add_virtual_target(),
        }
    }

    pub fn set_witness<V: HashableEntryValue>(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        statement: &Statement<V>,
    ) -> Result<()> {
        pw.set_target(
            self.predicate,
            GoldilocksField::from_canonical_u64(statement.predicate as u64),
        )?;
        self.origin1.set_witness(pw, &statement.origin1)?;
        pw.set_target(self.key1, hash_string_to_field(&statement.key1))?;
        self.origin2
            .set_witness(pw, statement.origin2.as_ref().unwrap_or(&Origin::NONE))?;
        pw.set_target(
            self.key2,
            statement
                .key2
                .as_ref()
                .map_or(GoldilocksField::ZERO, |key_name| {
                    hash_string_to_field(&key_name)
                }),
        )?;
        self.origin3
            .set_witness(pw, statement.origin3.as_ref().unwrap_or(&Origin::NONE))?;
        pw.set_target(
            self.key3,
            statement
                .key3
                .as_ref()
                .map_or(GoldilocksField::ZERO, |key_name| {
                    hash_string_to_field(&key_name)
                }),
        )?;
        pw.set_target(
            self.optional_value,
            statement
                .optional_value
                .as_ref()
                .map_or(GoldilocksField::ZERO, |v| v.hash_or_value()),
        )?;
        Ok(())
    }
}

pub struct SchnorrPODTarget {
    payload: Vec<StatementTarget>,
    proof: SchnorrSignatureTarget,
}

impl SchnorrPODTarget {
    pub fn new_virtual(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        num_entries: usize,
    ) -> SchnorrPODTarget {
        let payload = (0..num_entries)
            .map(|_| StatementTarget::new_virtual(builder))
            .collect();
        let proof = SchnorrSignatureTarget::new_virtual(builder);
        SchnorrPODTarget { payload, proof }
    }
}

pub struct CircuitTarget {
    // Inputs
    pub input_payload_hash: Vec<Target>,
    pub pk_index: Vec<Target>,
    // GPG and Schnorr PODs have the same proof format
    pub input_proof: Vec<SchnorrSignatureTarget>,
    pub input_statements: Vec<Vec<StatementTarget>>,
    //    pub operations: Vec<OperationTarget>,

    // Outputs
    pub output_statements: Vec<StatementTarget>,
    pub output_payload_hash: Target,
}

impl CircuitTarget {
    pub fn new_virtual(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        num_pods: usize,
        num_statements: usize,
        num_output_statements: usize,
    ) -> Self {
        let input_payload_hash = builder.add_virtual_targets(num_pods);
        let pk_index = builder.add_virtual_targets(num_pods);
        let input_proof: Vec<SchnorrSignatureTarget> = (0..num_pods)
            .map(|_| SchnorrSignatureTarget::new_virtual(builder))
            .collect();
        let input_statements: Vec<Vec<StatementTarget>> = (0..num_pods)
            .map(|_| {
                (0..num_statements)
                    .map(|_| StatementTarget::new_virtual(builder))
                    .collect()
            })
            .collect();
        let output_statements: Vec<StatementTarget> = (0..num_output_statements)
            .map(|_| StatementTarget::new_virtual(builder))
            .collect();
        let output_payload_hash = builder.add_virtual_target();

        Self {
            input_payload_hash,
            pk_index,
            input_proof,
            input_statements,
            output_statements,
            output_payload_hash,
        }
    }
    pub fn set_witness(
        &self,
        opod_pubkey: GoldilocksField,
        pw: &mut PartialWitness<GoldilocksField>,
        input_schnorr_pods: &[POD],
        output_pod: &POD,
    ) -> Result<()> {
        // TODO: Padding and sorting

        // Determine payload hashes
        let input_payload_hash = input_schnorr_pods
            .iter()
            .map(|pod| pod.payload.hash_payload())
            .collect::<Vec<_>>();
        // Determine entry index of public key of ith POD. 0 if the POD is not a SchnorrPOD.
        let pk_index = input_schnorr_pods
            .iter()
            .enumerate()
            .map(|(pod_number, pod)| match pod.proof {
                PODProof::Oracle(_) => Err(anyhow!("POD {} is not a Schnorr POD.", pod_number)),
                PODProof::Schnorr(_) => {
                    let maybe_pk_index = pod
                        .payload
                        .statements_list
                        .iter()
                        .enumerate()
                        .filter(|(i, (key_name, _))| key_name == "entry-_signer") // TODO: Factor out.
                        .map(|(i, _)| i)
                        .next();
                    let pk_index = maybe_pk_index.ok_or::<anyhow::Error>(anyhow!(
                        "POD {} is missing signer's key!",
                        pod_number
                    ))?;
                    Ok(GoldilocksField::from_canonical_u64(pk_index as u64))
                }
            })
            .collect::<Result<Vec<GoldilocksField>>>()?;
        // Determine input proofs.
        let input_proof = input_schnorr_pods
            .iter()
            .enumerate()
            .map(|(pod_num, pod)| match pod.proof {
                PODProof::Schnorr(p) => Ok(p),
                _ => Err(anyhow!("POD {} is not a Schnorr POD.", pod_num)),
            })
            .collect::<Result<Vec<_>>>()?;
        // Determine input statements
        let input_statements = input_schnorr_pods
            .iter()
            .map(|pod| {
                pod.payload
                    .statements_list
                    .iter()
                    .map(|(_, s)| s)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        // Determine output data
        let output_statements = &output_pod.payload;
        let output_payload_hash = output_pod.payload.hash_payload();

        // Assign witnesses
        pw.set_target_arr(&self.input_payload_hash, &input_payload_hash)?;
        pw.set_target_arr(&self.pk_index, &pk_index)?;
        self.input_proof
            .iter()
            .enumerate()
            .map(|(i, ip)| ip.set_witness(pw, &input_proof[i]))
            .collect::<Result<Vec<()>>>()?;
        self.input_statements
            .iter()
            .enumerate()
            .map(|(i, statement_vec)| {
                statement_vec
                    .iter()
                    .enumerate()
                    .map(|(j, s)| s.set_witness(pw, input_statements[i][j]))
                    .collect::<Result<Vec<()>>>()
            })
            .collect::<Result<Vec<Vec<()>>>>()?;
        Ok(())
    }
}

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = <C as GenericConfig<D>>::F;

// TODO: Optimise.
pub fn pod2_circuit(
    num_pods: usize,
    num_statements: usize,
    num_output_statements: usize,
    //    num_operations: HashMap<Operation, usize>,
) -> Result<(CircuitBuilder<F, D>, CircuitTarget)> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Declare targets
    let circuit_target = CircuitTarget::new_virtual(
        &mut builder,
        num_pods,
        num_statements,
        num_output_statements,
    );
    let CircuitTarget {
        input_payload_hash,
        pk_index,
        input_proof,
        input_statements,
        output_statements,
        output_payload_hash,
    } = &circuit_target;

    // Look up Schnorr POD public key, which should be indexed by
    // entry statement number n (0-indexing), i.e. it should be less
    // than `num_pods`, and both of these should fit in `NUM_BITS`
    // bits.  We therefore check that input_entries[i][2*n] -
    // hash("_signer") = 0 and single out pk = input_statements[i][14*n +
    // 13].

    let pk_entry_name = pk_index
        .iter()
        .enumerate()
        .map(|(i, ind)| {
            builder.range_check(*ind, NUM_BITS);
            // Form num_entries - 1 - *ind
            let minus_ind_target = builder.neg(*ind);
            let expr_target = builder.add_const(
                minus_ind_target,
                GoldilocksField::from_canonical_u64(num_statements as u64 - 1),
            );
            builder.range_check(expr_target, NUM_BITS);
            Ok(builder.random_access(
                *ind,
                pad_to_power_of_two(input_statements[i].iter().map(|s| s.key1).collect())?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    // Each of these should be hash("_signer").
    let expected_pk_entry_name = builder.constant(hash_string_to_field("_signer"));
    pk_entry_name
        .into_iter()
        .for_each(|entry_name| builder.connect(entry_name, expected_pk_entry_name));

    let signer_pk = pk_index
        .iter()
        .enumerate()
        .map(|(i, ind)| {
            Ok(builder.random_access(
                *ind,
                pad_to_power_of_two(
                    input_statements[i]
                        .iter()
                        .map(|s| s.optional_value)
                        .collect(),
                )?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    // Check payload hashes.
    let flattened_statements: Vec<Vec<Target>> = input_statements
        .iter()
        .map(|s_vec| {
            s_vec
                .iter()
                .flat_map(|s| {
                    vec![
                        s.predicate,
                        s.origin1.origin_id,
                        s.origin1.gadget_id,
                        s.key1,
                        s.origin2.origin_id,
                        s.origin2.gadget_id,
                        s.key2,
                        s.origin3.origin_id,
                        s.origin3.gadget_id,
                        s.key3,
                        s.optional_value,
                    ]
                })
                .collect::<Vec<Target>>()
        })
        .collect();

    let expected_input_payload_hash = flattened_statements
        .iter()
        .map(|entries| {
            builder
                .hash_n_to_hash_no_pad::<PoseidonHash>(entries.to_vec())
                .elements[0]
        })
        .collect::<Vec<Target>>();
    std::iter::zip(expected_input_payload_hash, input_payload_hash)
        .for_each(|(eph, ph)| builder.connect(eph, *ph));

    // Check signature
    input_payload_hash.iter().enumerate().for_each(|(i, h)| {
        let sig_check = SchnorrBuilder::verify_sig::<C>(
            &SchnorrBuilder {},
            &mut builder,
            &input_proof[i],
            &MessageTarget {
                msg: vec![input_payload_hash[i]],
            },
            &SchnorrPublicKeyTarget { pk: signer_pk[i] },
        );
        builder.assert_one(sig_check.target);
    });

    // Build circuit
    Ok((builder, circuit_target))
}

/// Pads the end of the vector with its final element until its length
/// is a power of two. Needed for Plonky2 RAM.
fn pad_to_power_of_two<A: Clone>(v: Vec<A>) -> Result<Vec<A>> {
    let v_len = v.len();
    let bits = log2_ceil(v_len);
    let padding = (0..2usize.pow(bits as u32) - v_len)
        .map(|_| v.last().cloned())
        .collect::<Option<Vec<_>>>()
        .ok_or(anyhow!("Vector is empty"))?;
    Ok([v, padding].concat())
}
