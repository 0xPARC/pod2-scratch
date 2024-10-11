use std::cmp::Ordering;
use std::collections::HashMap;

//use circuit::pod2_circuit;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::field::types::PrimeField64;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::config::Hasher;
use util::hash_string_to_field;

use crate::schnorr::SchnorrPublicKey;
use crate::schnorr::SchnorrSecretKey;
use crate::schnorr::SchnorrSignature;
use crate::schnorr::SchnorrSigner;

use rand;

//mod circuit;
mod util;

pub(crate) type Error = Box<dyn std::error::Error>;

pub trait HashablePayload: Clone + PartialEq {
    fn to_field_vec(&self) -> Vec<GoldilocksField>;

    fn hash_payload(&self) -> GoldilocksField {
        let ins = self.to_field_vec();
        PoseidonHash::hash_no_pad(&ins).to_vec()[0]
    }
}

impl<V: EntryValue> HashablePayload for Vec<Entry<V>> {
    fn to_field_vec(&self) -> Vec<GoldilocksField> {
        // let mut sorted_by_key_name = self.clone();
        // sorted_by_key_name.sort_by(|a, b| a.key_name.cmp(&b.key_name));
        let mut ins = Vec::new();
        // sorted_by_key_name.iter().for_each(|entry| {
        //     ins.push(entry.key_hash);
        //     ins.push(entry.value_hash);
        // });
        self.iter().for_each(|entry| {
            ins.push(entry.key_hash);
            ins.push(entry.value_hash);
        });
        ins
    }
}

// TODO
impl HashablePayload for Vec<Statement> {
    fn to_field_vec(&self) -> Vec<GoldilocksField> {
        self.iter()
            .map(|statement| {
                [
                    vec![
                        GoldilocksField(statement.predicate as u64),
                        statement.origin1.origin_id,
                        GoldilocksField(statement.origin1.gadget_id as u64),
                        hash_string_to_field(&statement.key1),
                    ],
                    match statement.origin2 {
                        Some(ro) => vec![ro.origin_id, GoldilocksField(ro.gadget_id as u64)],
                        _ => vec![GoldilocksField(0), GoldilocksField(0)],
                    },
                    vec![
                        match &statement.key2 {
                            Some(rkn) => hash_string_to_field(&rkn),
                            _ => GoldilocksField::ZERO,
                        },
                        match statement.optional_value {
                            Some(x) => x,
                            _ => GoldilocksField::ZERO,
                        },
                    ],
                ]
                .concat()
            })
            .collect::<Vec<Vec<GoldilocksField>>>()
            .concat()
    }
}

pub trait ProofOf<Payload>: Clone {
    fn verify(&self, payload: &Payload) -> Result<bool, Error>;
}

// verify schnorr POD
impl ProofOf<Vec<Entry<ScalarOrVec>>> for SchnorrSignature {
    fn verify(&self, payload: &Vec<Entry<ScalarOrVec>>) -> Result<bool, Error> {
        let payload_hash = payload.hash_payload();
        let payload_hash_vec = vec![payload_hash];
        let protocol = SchnorrSigner::new();
        let wrapped_pk = payload
            .iter()
            .filter(|entry| entry.key_name == "_signer")
            .collect::<Vec<&Entry<ScalarOrVec>>>();
        if wrapped_pk.len() == 0 {
            return Err("No signer found in payload".into());
        }

        let pk = match wrapped_pk[0].value {
            ScalarOrVec::Vector(_) => Err(Error::from("Signer is a vector")),
            ScalarOrVec::Scalar(s) => Ok(s),
        }?;
        Ok(protocol.verify(&self, &payload_hash_vec, &SchnorrPublicKey { pk }))
    }
}

// verify GODPOD
impl ProofOf<Vec<Statement>> for SchnorrSignature {
    fn verify(&self, payload: &Vec<Statement>) -> Result<bool, Error> {
        let payload_hash = payload.hash_payload();
        let payload_hash_vec = vec![payload_hash];
        let protocol = SchnorrSigner::new();
        Ok(protocol.verify(
            &self,
            &payload_hash_vec,
            &protocol.keygen(&SchnorrSecretKey { sk: 0 }), // hardcoded secret key
        ))
    }
}

pub trait EntryValue: Clone + PartialEq {
    fn hash_or_value(&self) -> GoldilocksField;
}

impl EntryValue for GoldilocksField {
    fn hash_or_value(&self) -> GoldilocksField {
        *self
    }
}

impl EntryValue for Vec<GoldilocksField> {
    fn hash_or_value(&self) -> GoldilocksField {
        PoseidonHash::hash_no_pad(self).to_vec()[0]
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ScalarOrVec {
    Scalar(GoldilocksField),
    Vector(Vec<GoldilocksField>),
}

impl EntryValue for ScalarOrVec {
    fn hash_or_value(&self) -> GoldilocksField {
        match self {
            Self::Scalar(s) => s.hash_or_value(),
            Self::Vector(v) => v.hash_or_value(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(usize)]
pub enum GadgetID {
    NONE = 0,
    SCHNORR16 = 1,
    GOD = 2,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Origin {
    pub origin_id: GoldilocksField, // reserve 0 for NONE, 1 for SELF
    pub gadget_id: GadgetID, // if origin_id is SELF, this is none; otherwise, it's the gadget_id
}

impl Origin {
    pub const NONE: Self = Origin {
        origin_id: GoldilocksField::ZERO,
        gadget_id: GadgetID::NONE,
    };
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entry<V: EntryValue> {
    pub key_name: String,
    pub key_hash: GoldilocksField,
    pub value_hash: GoldilocksField,
    pub value: V,
}

impl<V: EntryValue> Entry<V> {
    fn new(key_name: &str, value: V) -> Self {
        Entry {
            key_name: key_name.to_string(),
            key_hash: hash_string_to_field(key_name),
            value_hash: value.hash_or_value(),
            value,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u64)]
pub enum StatementPredicate {
    None = 0,
    ValueOf = 1,
    Equal = 2,
    NotEqual = 3,
    Gt = 4,
    Contains = 5,
    SumOf = 6,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Statement {
    pub predicate: StatementPredicate,
    pub origin1: Origin,
    pub key1: String,
    pub origin2: Option<Origin>,
    pub key2: Option<String>,
    pub origin3: Option<Origin>,
    pub key3: Option<String>,
    pub optional_value: Option<GoldilocksField>, // todo: figure out how to allow this to be any EntryValue
}

pub fn entry_to_statement<V: EntryValue>(entry: &Entry<V>, gadget_id: GadgetID) -> Statement {
    Statement {
        predicate: StatementPredicate::ValueOf,
        origin1: Origin {
            origin_id: GoldilocksField(1),
            gadget_id,
        },
        key1: entry.key_name.clone(),
        origin2: None,
        key2: None,
        origin3: None,
        key3: None,
        optional_value: Some(entry.value.hash_or_value()),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct POD<Payload: HashablePayload, Proof: ProofOf<Payload>, const FromGadgetID: usize> {
    pub payload: Payload,
    proof: Proof,
}

type SchnorrPOD = POD<Vec<Entry<ScalarOrVec>>, SchnorrSignature, { GadgetID::SCHNORR16 as usize }>;

type GODPOD = POD<Vec<Statement>, SchnorrSignature, { GadgetID::GOD as usize }>;

#[derive(Clone, Debug, PartialEq)]
pub enum SchnorrOrGODPOD {
    SchnorrPOD(SchnorrPOD),
    GODPOD(GODPOD),
}

impl<Payload: HashablePayload, Proof: ProofOf<Payload>, const FromGadgetID: usize>
    POD<Payload, Proof, FromGadgetID>
{
    pub fn verify(&self) -> Result<bool, Error> {
        self.proof.verify(&self.payload)
    }
}

impl SchnorrPOD {
    pub fn gadget(entries: &Vec<Entry<ScalarOrVec>>, sk: &SchnorrSecretKey) -> Self {
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let protocol = SchnorrSigner::new();

        let mut payload = entries.clone();
        payload.push(Entry::new(
            "_signer",
            ScalarOrVec::Scalar(protocol.keygen(sk).pk),
        ));
        let payload_hash = payload.hash_payload();
        let payload_hash_vec = vec![payload_hash];
        let proof = protocol.sign(&payload_hash_vec, sk, &mut rng);
        Self { payload, proof }
    }
}

pub fn remap_origin_ids(inputs: &Vec<Vec<Statement>>) -> Vec<Vec<Statement>> {
    let mut all_in_origin_ids = Vec::new();
    for i in 0..inputs.len() {
        for statement in inputs[i].iter() {
            let left_origin_tuple = (i, statement.origin1.origin_id);
            if !all_in_origin_ids.contains(&left_origin_tuple) {
                all_in_origin_ids.push(left_origin_tuple);
            }

            if let Some(right_origin) = statement.origin2 {
                let right_origin_tuple = (i, right_origin.origin_id);
                if !all_in_origin_ids.contains(&right_origin_tuple) {
                    all_in_origin_ids.push(right_origin_tuple);
                }
            }
        }
    }

    // sort all_in_origin_ids in place
    all_in_origin_ids.sort_by(|a, b| {
        let first_cmp = a.0.cmp(&b.0);
        if first_cmp == Ordering::Equal {
            (a.1).to_canonical_u64().cmp(&(b.1).to_canonical_u64())
        } else {
            first_cmp
        }
    });

    let mut origin_id_map = HashMap::new();
    for idx_and_origin_id in all_in_origin_ids.iter().enumerate() {
        origin_id_map.insert(idx_and_origin_id.1, (idx_and_origin_id.0 + 2) as u64);
    }

    let mut remapped_inputs = Vec::new();

    println!("origin id map: {:?}", origin_id_map);

    for (idx, input) in inputs.iter().enumerate() {
        let mut remapped_input = Vec::new();
        for statement in input {
            let mut remapped_statement = statement.clone();
            println!("index: {:?}", idx);
            println!("OLD statement: {:?}", remapped_statement);
            remapped_statement.origin1.origin_id = GoldilocksField(
                *origin_id_map
                    .get(&(idx, remapped_statement.origin1.origin_id))
                    .unwrap(),
            );
            if let Some(right_origin) = remapped_statement.origin2 {
                remapped_statement.origin2 = Some(Origin {
                    origin_id: GoldilocksField(
                        *origin_id_map.get(&(idx, right_origin.origin_id)).unwrap(),
                    ),
                    gadget_id: right_origin.gadget_id,
                });
            }
            println!("NEW statement: {:?}", remapped_statement);
            remapped_input.push(remapped_statement);
        }
        remapped_inputs.push(remapped_input);
    }
    remapped_inputs
}

pub fn to_statements_with_remapping(inputs: &Vec<&SchnorrOrGODPOD>) -> Vec<Statement> {
    let statements = inputs
        .iter()
        .map(|pod| match pod {
            SchnorrOrGODPOD::GODPOD(p) => p.clone().payload,
            SchnorrOrGODPOD::SchnorrPOD(p) => p
                .payload
                .iter()
                .map(|entry| entry_to_statement(entry, GadgetID::SCHNORR16))
                .collect::<Vec<Statement>>(),
        })
        .collect::<Vec<Vec<Statement>>>();

    // Now remap
    remap_origin_ids(&statements).concat()
}

impl GODPOD {
    pub fn new(statements: &Vec<Statement>) -> Self {
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let protocol = SchnorrSigner::new();
        let payload = statements.clone();
        let payload_hash = statements.hash_payload();
        let payload_hash_vec = vec![payload_hash];

        // signature is a hardcoded skey (currently 0)
        // todo is to build a limited version of this with a ZKP
        // would start by making it so that the ZKP only allows
        // a max number of input PODs, max number of entries/statements per input POD,
        // max number of statements for output POD, and some max number of each type of operation
        let proof = protocol.sign(&payload_hash_vec, &SchnorrSecretKey { sk: 0 }, &mut rng);
        Self { payload, proof }
    }

    pub fn gadget(
        inputs: &Vec<&SchnorrOrGODPOD>, // will be converted to a vector of statements
        operations: &Vec<(
            Operation,
            Option<usize>,
            Option<usize>,
            Option<usize>,
            Option<&Entry<ScalarOrVec>>,
        )>,
    ) -> Self {
        // Check all input pods are valid.
        for pod in inputs {
            match pod {
                SchnorrOrGODPOD::GODPOD(p) => {
                    assert!(p.verify().expect("input GODPOD verification failed"));
                }
                SchnorrOrGODPOD::SchnorrPOD(p) => {
                    assert!(p.verify().expect("input SchnorrPOD verification failed"));
                }
            }
        }
        // Compile/arrange list of statements as Vec<Statement> (after converting each `Entry` into a `ValueOf` statement).
        // and then remap
        let remapped_statements = to_statements_with_remapping(inputs);

        // apply operations one by one on remapped_statements
        let mut final_statements = Vec::new();
        for (operation, idx1, idx2, idx3, entry) in operations {
            let statement1 = match idx1 {
                Some(idx) => Some(&remapped_statements[*idx]),
                None => None,
            };
            let statement2 = match idx2 {
                Some(idx) => Some(&remapped_statements[*idx]),
                None => None,
            };
            let statement3 = match idx3 {
                Some(idx) => Some(&remapped_statements[*idx]),
                None => None,
            };
            let optional_entry = match entry {
                Some(entry) => Some(*entry),
                None => None,
            };
            final_statements.push(operation.apply_operation(
                GadgetID::GOD,
                statement1,
                statement2,
                statement3,
                optional_entry,
            ))
        }

        GODPOD::new(
            &final_statements
                .iter()
                .map(|maybe_statement| maybe_statement.clone().unwrap())
                .collect::<Vec<Statement>>(),
        )
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Operation {
    None = 0,
    NewEntry = 1,
    CopyStatement = 2,
    EqualityFromEntries = 3,
    NonequalityFromEntries = 4,
    GtFromEntries = 5,
    TransitiveEqualityFromStatements = 6,
    GtToNonequality = 7,
    Contains = 8,
    SumOf = 9,
}

impl Operation {
    pub fn apply_operation<V: EntryValue>(
        &self,
        gadget_id: GadgetID,
        statement1: Option<&Statement>,
        statement2: Option<&Statement>,
        statement3: Option<&Statement>,
        optional_entry: Option<&Entry<V>>,
    ) -> Option<Statement> {
        match (self, statement1, statement2, statement3, optional_entry) {
            // A new statement is created from a single `Entry`.
            (Self::NewEntry, _, _, _, Some(entry)) => Some(entry_to_statement(&entry, gadget_id)),
            // SumOf <=> statement 1's value = statement 2's value + statement 3's value
            (Self::SumOf, Some(statement1), Some(statement2), Some(statement3), _) => {
                if [
                    statement1.predicate,
                    statement2.predicate,
                    statement3.predicate,
                ]
                .into_iter()
                .all(|p| p == StatementPredicate::ValueOf)
                    && (statement1.optional_value?
                        == statement2.optional_value? + statement3.optional_value?)
                {
                    Some(Statement {
                        predicate: StatementPredicate::SumOf,
                        origin1: statement1.origin1,
                        key1: statement1.key1.clone(),
                        origin2: Some(statement2.origin1),
                        key2: Some(statement2.key1.clone()),
                        origin3: Some(statement3.origin1),
                        key3: Some(statement3.key1.clone()),
                        optional_value: None,
                    })
                } else {
                    None
                }
            }
            // A statement is copied from a single (left) statement.
            (Self::CopyStatement, Some(statement), _, _, _) => Some(statement.clone()),
            // Eq <=> Left entry = right entry
            (Self::EqualityFromEntries, Some(left_entry), Some(right_entry), _, _) => {
                match (left_entry.predicate, right_entry.predicate) {
                    (StatementPredicate::ValueOf, StatementPredicate::ValueOf)
                        if left_entry.optional_value == right_entry.optional_value =>
                    {
                        Some(Statement {
                            predicate: StatementPredicate::Equal,
                            origin1: left_entry.origin1,
                            key1: left_entry.key1.clone(),
                            origin2: Some(right_entry.origin1),
                            key2: Some(right_entry.key1.clone()),
                            origin3: None,
                            key3: None,
                            optional_value: None,
                        })
                    }
                    _ => None,
                }
            }
            // Neq <=> Left entry != right entry
            (Self::NonequalityFromEntries, Some(left_entry), Some(right_entry), _, _) => {
                match (left_entry.predicate, right_entry.predicate) {
                    (StatementPredicate::ValueOf, StatementPredicate::ValueOf)
                        if left_entry.optional_value != right_entry.optional_value =>
                    {
                        Some(Statement {
                            predicate: StatementPredicate::NotEqual,
                            origin1: left_entry.origin1,
                            key1: left_entry.key1.clone(),
                            origin2: Some(right_entry.origin1),
                            key2: Some(right_entry.key1.clone()),
                            origin3: None,
                            key3: None,
                            optional_value: None,
                        })
                    }
                    _ => None,
                }
            }
            // Gt <=> Left entry > right entry
            (Self::GtFromEntries, Some(left_entry), Some(right_entry), _, _) => {
                match (
                    left_entry.predicate,
                    left_entry.optional_value,
                    right_entry.predicate,
                    right_entry.optional_value,
                ) {
                    (
                        StatementPredicate::ValueOf,
                        Some(left_value),
                        StatementPredicate::ValueOf,
                        Some(right_value),
                    ) if left_value.to_canonical_u64() > right_value.to_canonical_u64() => {
                        Some(Statement {
                            predicate: StatementPredicate::Gt,
                            origin1: left_entry.origin1,
                            key1: left_entry.key1.clone(),
                            origin2: Some(right_entry.origin1),
                            key2: Some(right_entry.key1.clone()),
                            origin3: None,
                            key3: None,
                            optional_value: None,
                        })
                    }
                    _ => None,
                }
            }
            // Equality deduction: a = b ∧ b = c => a = c.
            // TODO: Allow for permutations of left/right values.
            (
                Self::TransitiveEqualityFromStatements,
                Some(left_statement),
                Some(right_statement),
                _,
                _,
            ) => match (left_statement, right_statement) {
                (
                    Statement {
                        predicate: StatementPredicate::Equal,
                        origin1: ll_origin,
                        key1: ll_key_name,
                        origin2:
                            Some(Origin {
                                origin_id: lr_origin_id,
                                gadget_id: _,
                            }),
                        key2: Some(lr_key_name),
                        origin3: None,
                        key3: None,
                        optional_value: _,
                    },
                    Statement {
                        predicate: StatementPredicate::Equal,
                        origin1:
                            Origin {
                                origin_id: rl_origin_id,
                                gadget_id: _,
                            },
                        key1: rl_key_name,
                        origin2: rr_origin @ Some(_),
                        key2: rr_key_name @ Some(_),
                        origin3: None,
                        key3: None,
                        optional_value: _,
                    },
                ) if (lr_origin_id, &lr_key_name) == ((rl_origin_id, &rl_key_name)) => {
                    Some(Statement {
                        predicate: StatementPredicate::Equal,
                        origin1: *ll_origin,
                        key1: ll_key_name.clone(),
                        origin2: *rr_origin,
                        key2: rr_key_name.clone(),
                        origin3: None,
                        key3: None,
                        optional_value: None,
                    })
                }
                _ => None,
            },
            (Self::GtToNonequality, Some(left_statement), _, _, _) => match left_statement {
                Statement {
                    predicate: StatementPredicate::Gt,
                    origin1: left_origin,
                    key1: left_key_name,
                    origin2: right_origin,
                    key2: right_key_name,
                    origin3: None,
                    key3: None,
                    optional_value: _,
                } => Some(Statement {
                    predicate: StatementPredicate::NotEqual,
                    origin1: *left_origin,
                    key1: left_key_name.clone(),
                    origin2: *right_origin,
                    key2: right_key_name.clone(),
                    origin3: None,
                    key3: None,
                    optional_value: None,
                }),
                _ => None,
            },
            // TODO. also first need to make it so statement values can be vectors
            (Self::Contains, _, _, _, _) => None,
            _ => None,
        }
    }
}

#[test]
fn op_test() -> Result<(), Error> {
    // Start with some values.
    let scalar1 = GoldilocksField(36);
    let scalar2 = GoldilocksField(52);
    let scalar3 = GoldilocksField(16);
    let vector_value = vec![scalar1, scalar2];

    // Create entries
    let entry1 = Entry::new("some key", scalar1);
    let entry2 = Entry::new("some other key", scalar2);
    let entry3 = Entry::new("vector entry", vector_value.clone());
    let entry4 = Entry::new("another scalar1", scalar1);
    let entry5 = Entry::new("yet another scalar1", scalar1);
    let entry6 = Entry::new("scalar3", scalar3);

    // Create entry statements. Unwrapped for convenience.
    let entry_statement1 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, None, Some(&entry1))
        .unwrap();
    let entry_statement2 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, None, Some(&entry2))
        .unwrap();
    let entry_statement3 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, None, Some(&entry3))
        .unwrap();
    let entry_statement4 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, None, Some(&entry4))
        .unwrap();
    let entry_statement5 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, None, Some(&entry5))
        .unwrap();
    let entry_statement6 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, None, Some(&entry6))
        .unwrap();

    // Entry 2's value = entry 1's value + entry 6's value
    let sum_of_statement = Operation::SumOf
        .apply_operation(
            GadgetID::GOD,
            Some(&entry_statement2),
            Some(&entry_statement1),
            Some(&entry_statement6),
            <Option<&Entry<GoldilocksField>>>::None,
        )
        .unwrap();
    assert!(
        sum_of_statement
            == Statement {
                predicate: StatementPredicate::SumOf,
                origin1: entry_statement2.origin1,
                key1: entry_statement2.key1.clone(),
                origin2: Some(entry_statement1.origin1),
                key2: Some(entry_statement1.key1.clone()),
                origin3: Some(entry_statement6.origin1),
                key3: Some(entry_statement6.key1.clone()),
                optional_value: None
            }
    );

    let entries = [&entry_statement1, &entry_statement2, &entry_statement3];

    // Copy statements and check for equality of entries.
    entries.into_iter().for_each(|statement| {
        let copy = Operation::CopyStatement
            .apply_operation::<GoldilocksField>(GadgetID::GOD, Some(statement), None, None, None)
            .expect("This value should exist.");
        assert!(&copy == statement);
    });

    // Equality checks
    println!(
        "{:?}",
        Operation::EqualityFromEntries.apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&entry_statement1),
            Some(&entry_statement2),
            None,
            None
        )
    );
    entries.into_iter().for_each(|statement| {
        assert!(
            Operation::EqualityFromEntries.apply_operation::<GoldilocksField>(
                GadgetID::GOD,
                Some(statement),
                Some(statement),
                None,
                None
            ) == Some(Statement {
                predicate: StatementPredicate::Equal,
                origin1: statement.origin1,
                key1: statement.key1.clone(),
                origin2: Some(statement.origin1),
                key2: Some(statement.key1.clone()),
                origin3: None,
                key3: None,
                optional_value: None
            })
        );
    });
    // assert!(
    //     Operation::NonequalityFromEntries.apply_operation::<GoldilocksField>(
    //         GadgetID::GOD,
    //         Some(&entry_statement1),
    //         Some(&entry_statement2),
    //         None
    //     ) == Some(Statement {
    //         predicate: StatementPredicate::Equal,
    //         left_origin: entry_statement1.left_origin,
    //         left_key_name: entry_statement1.left_key_name.clone(),
    //         right_origin: Some(entry_statement2.left_origin),
    //         right_key_name: Some(entry_statement2.left_key_name.clone()),
    //         optional_value: None
    //     })
    // );
    assert!(
        Operation::EqualityFromEntries.apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&entry_statement1),
            Some(&entry_statement2),
            None,
            None
        ) == None
    );

    // Gt check
    let gt_statement = Operation::GtFromEntries.apply_operation::<GoldilocksField>(
        GadgetID::GOD,
        Some(&entry_statement2),
        Some(&entry_statement1),
        None,
        None,
    );
    assert!(
        gt_statement
            == Some(Statement {
                predicate: StatementPredicate::Gt,
                origin1: entry_statement2.origin1,
                key1: entry_statement2.key1.clone(),
                origin2: Some(entry_statement1.origin1),
                key2: Some(entry_statement1.key1.clone()),
                origin3: None,
                key3: None,
                optional_value: None
            })
    );

    // Eq transitivity check
    let eq_statement1 = Operation::EqualityFromEntries
        .apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&entry_statement4),
            Some(&entry_statement1),
            None,
            None,
        )
        .unwrap();
    let eq_statement2 = Operation::EqualityFromEntries
        .apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&entry_statement1),
            Some(&entry_statement5),
            None,
            None,
        )
        .unwrap();
    let eq_statement3 = Operation::EqualityFromEntries
        .apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&entry_statement4),
            Some(&entry_statement5),
            None,
            None,
        )
        .unwrap();

    assert!(
        Operation::TransitiveEqualityFromStatements.apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&eq_statement1),
            Some(&eq_statement2),
            None,
            None
        ) == Some(eq_statement3)
    );

    // Gt->Nonequality conversion check
    let unwrapped_gt_statement = gt_statement.unwrap();
    let mut expected_statement = unwrapped_gt_statement.clone();
    expected_statement.predicate = StatementPredicate::NotEqual;
    assert!(
        Operation::GtToNonequality.apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&unwrapped_gt_statement),
            None,
            None,
            None
        ) == Some(expected_statement)
    );
    Ok(())
}

#[test]
fn schnorr_pod_test() -> Result<(), Error> {
    // Start with some values.
    let scalar1 = GoldilocksField(36);
    let scalar2 = GoldilocksField(52);
    let vector_value = vec![scalar1, scalar2];

    let entry1 = Entry::new("some key", ScalarOrVec::Scalar(scalar1));
    let entry2 = Entry::new("some other key", ScalarOrVec::Scalar(scalar2));
    let entry3 = Entry::new("vector entry", ScalarOrVec::Vector(vector_value.clone()));

    let schnorrPOD1 = SchnorrPOD::gadget(
        &vec![entry1.clone(), entry2.clone()],
        &SchnorrSecretKey { sk: 25 },
    );

    let schnorrPOD2 = SchnorrPOD::gadget(
        &vec![entry2.clone(), entry3.clone()],
        &SchnorrSecretKey { sk: 42 },
    );

    let schnorrPOD3 = SchnorrPOD::gadget(&vec![entry1.clone()], &SchnorrSecretKey { sk: 25 });

    // println!(
    //     "verify schnorrpod1: {:?}",
    //     schnorrPOD1.clone().payload.to_field_vec()
    // );
    // println!("verify schnorrpod2: {:?}", schnorrPOD2.verify());

    assert!(schnorrPOD1.verify()? == true);
    assert!(schnorrPOD2.verify()? == true);

    // // ZK verification of SchnorrPOD 3.
    // let (builder, targets) = pod2_circuit(1, 2, 0, 0)?;

    // // Assign witnesses
    // const D: usize = 2;
    // type C = PoseidonGoldilocksConfig;
    // type F = <C as GenericConfig<D>>::F;
    // let mut pw: PartialWitness<F> = PartialWitness::new();
    // pw.set_target(targets.input_is_schnorr[0], GoldilocksField(1))?;
    // pw.set_target(targets.input_is_gpg[0], GoldilocksField::ZERO)?;
    // pw.set_target(
    //     targets.input_payload_hash[0],
    //     schnorrPOD3.payload.hash_payload(),
    // )?;
    // pw.set_target(targets.pk_index[0], GoldilocksField(1))?;
    // targets.input_proof[0].set_witness(&mut pw, &schnorrPOD3.proof)?;
    // targets.input_entries[0][0].set_witness(&mut pw, &schnorrPOD3.payload[0])?;
    // targets.input_entries[0][1].set_witness(&mut pw, &schnorrPOD3.payload[1])?;
    // let data = builder.build::<C>();
    // let proof = data.prove(pw)?;

    Ok(())
}

#[test]
fn god_pod_from_schnorr_test() -> Result<(), Error> {
    // Start with some values.
    let scalar1 = GoldilocksField(36);
    let scalar2 = GoldilocksField(52);
    let scalar3 = GoldilocksField(90);
    let vector_value = vec![scalar1, scalar2];

    // make entries
    let entry1 = Entry::new("some key", ScalarOrVec::Scalar(scalar1));
    let entry2 = Entry::new("some other key", ScalarOrVec::Scalar(scalar2));
    let entry3 = Entry::new("vector entry", ScalarOrVec::Vector(vector_value.clone()));
    let entry4 = Entry::new("new key", ScalarOrVec::Scalar(scalar2));
    let entry5 = Entry::new("foo", ScalarOrVec::Scalar(GoldilocksField(100)));
    let entry6 = Entry::new("baz", ScalarOrVec::Scalar(GoldilocksField(120)));
    let entry7 = Entry::new("yum", ScalarOrVec::Scalar(scalar2));
    let entry9 = Entry::new("godpod introduced entry key", ScalarOrVec::Scalar(scalar3));

    // three schnorr pods
    let schnorrPOD1 = SchnorrPOD::gadget(
        &vec![entry1.clone(), entry2.clone()],
        &SchnorrSecretKey { sk: 25 },
    );

    let schnorrPOD2 = SchnorrPOD::gadget(
        &vec![entry3.clone(), entry4.clone()],
        &SchnorrSecretKey { sk: 42 },
    );

    let schnorrPOD3 = SchnorrPOD::gadget(
        &vec![entry5.clone(), entry6.clone(), entry7.clone()],
        &SchnorrSecretKey { sk: 83 },
    );

    // make a GODPOD using from_pods called on the two schnorr PODs
    let god_pod_1 = GODPOD::gadget(
        &vec![
            &SchnorrOrGODPOD::SchnorrPOD(schnorrPOD1.clone()),
            &SchnorrOrGODPOD::SchnorrPOD(schnorrPOD2.clone()),
            &SchnorrOrGODPOD::SchnorrPOD(schnorrPOD3.clone()),
        ],
        &vec![
            (Operation::CopyStatement, Some(0), None, None, None),
            (Operation::CopyStatement, Some(1), None, None, None),
            (Operation::CopyStatement, Some(2), None, None, None),
            (Operation::CopyStatement, Some(3), None, None, None),
            (Operation::CopyStatement, Some(4), None, None, None),
            (Operation::CopyStatement, Some(5), None, None, None),
            (Operation::NewEntry, None, None, None, Some(&entry9)),
            (Operation::EqualityFromEntries, Some(1), Some(4), None, None),
            (Operation::EqualityFromEntries, Some(4), Some(8), None, None),
            (
                Operation::NonequalityFromEntries,
                Some(0),
                Some(1),
                None,
                None,
            ),
            (Operation::GtFromEntries, Some(1), Some(0), None, None),
        ],
    );
    println!("GODPOD1: {:?}", god_pod_1);
    assert!(god_pod_1.verify()? == true);

    // another GODPOD from the first GODPOD and another schnorr POD

    let god_pod_2 = GODPOD::gadget(
        &vec![
            &SchnorrOrGODPOD::GODPOD(god_pod_1.clone()),
            &SchnorrOrGODPOD::SchnorrPOD(schnorrPOD3.clone()),
        ],
        &vec![
            (Operation::CopyStatement, Some(8), None, None, None),
            (Operation::CopyStatement, Some(9), None, None, None),
            (Operation::CopyStatement, Some(3), None, None, None),
            (Operation::GtFromEntries, Some(6), Some(0), None, None),
            (
                Operation::TransitiveEqualityFromStatements,
                Some(7),
                Some(8),
                None,
                None,
            ),
            (Operation::GtToNonequality, Some(10), None, None, None),
        ],
    );
    println!("GODPOD2: {:?}", god_pod_2);

    // println!(
    //     "verify schnorrpod1: {:?}",
    //     schnorrPOD1.clone().payload.to_field_vec()
    // );
    // println!("verify schnorrpod2: {:?}", schnorrPOD2.verify());

    assert!(god_pod_2.verify()? == true);

    Ok(())
}

#[test]
#[should_panic]
fn god_pod_should_panic() {
    // Start with some values.
    let scalar1 = GoldilocksField(36);
    let scalar2 = GoldilocksField(52);
    let scalar3 = GoldilocksField(90);
    let vector_value = vec![scalar1, scalar2];

    // make entries
    let entry1 = Entry::new("some key", ScalarOrVec::Scalar(scalar1));
    let entry2 = Entry::new("some other key", ScalarOrVec::Scalar(scalar2));
    let entry3 = Entry::new("vector entry", ScalarOrVec::Vector(vector_value.clone()));
    let entry4 = Entry::new("new key", ScalarOrVec::Scalar(scalar2));
    let entry5 = Entry::new("foo", ScalarOrVec::Scalar(GoldilocksField(100)));
    let entry6 = Entry::new("foo", ScalarOrVec::Scalar(GoldilocksField(120)));
    let entry9 = Entry::new("godpod introduced entry key", ScalarOrVec::Scalar(scalar3));

    // three schnorr pods
    let schnorrPOD1 = SchnorrPOD::gadget(
        &vec![entry1.clone(), entry2.clone()],
        &SchnorrSecretKey { sk: 25 },
    );

    let schnorrPOD2 = SchnorrPOD::gadget(
        &vec![entry3.clone(), entry4.clone()],
        &SchnorrSecretKey { sk: 42 },
    );

    let schnorrPOD3 = SchnorrPOD::gadget(
        &vec![entry5.clone(), entry6.clone()],
        &SchnorrSecretKey { sk: 83 },
    );

    // make a GODPOD using from_pods called on the two schnorr PODs
    let god_pod_1 = GODPOD::gadget(
        &vec![
            &SchnorrOrGODPOD::SchnorrPOD(schnorrPOD1.clone()),
            &SchnorrOrGODPOD::SchnorrPOD(schnorrPOD2.clone()),
        ],
        // this Gt operation should fail because 36 is not gt 52
        &vec![(Operation::GtFromEntries, Some(0), Some(1), None, None)],
    );
}
