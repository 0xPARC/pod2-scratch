use std::cmp::Ordering;
use std::collections::HashMap;

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
use rand::Rng;

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
        let mut sorted_by_key_name = self.clone();
        sorted_by_key_name.sort_by(|a, b| a.key_name.cmp(&b.key_name));
        let mut ins = Vec::new();
        sorted_by_key_name.iter().for_each(|entry| {
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
                        statement.left_origin.origin_id,
                        GoldilocksField(statement.left_origin.gadget_id as u64),
                        hash_string_to_field(&statement.left_key_name),
                    ],
                    match statement.right_origin {
                        Some(ro) => vec![ro.origin_id, GoldilocksField(ro.gadget_id as u64)],
                        _ => vec![GoldilocksField(0), GoldilocksField(0)],
                    },
                    vec![
                        match &statement.right_key_name {
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

impl ProofOf<Vec<Entry<ScalarOrVec>>> for SchnorrSignature {
    fn verify(&self, payload: &Vec<Entry<ScalarOrVec>>) -> Result<bool, Error> {
        let payload_vec = payload.to_field_vec();
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
        Ok(protocol.verify(&self, &payload_vec, &SchnorrPublicKey { pk }))
    }
}

// TODO
impl ProofOf<Vec<Statement>> for SchnorrSignature {
    fn verify(&self, payload: &Vec<Statement>) -> Result<bool, Error> {
        let payload_vec = payload.to_field_vec();
        let protocol = SchnorrSigner::new();
        let wrapped_pk = payload
            .iter()
            .filter(|statement| {
                statement.left_key_name == "_signer"
                    && statement.left_origin.origin_id == GoldilocksField(1)
                    && statement.optional_value.is_some()
            })
            .collect::<Vec<&Statement>>();
        if wrapped_pk.len() == 0 {
            return Err("No signer found in payload".into());
        }

        let pk = wrapped_pk[0]
            .optional_value
            .expect("Signer's public key is missing.");
        Ok(protocol.verify(&self, &payload_vec, &SchnorrPublicKey { pk }))
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
}

#[derive(Clone, Debug, PartialEq)]
pub struct Statement {
    pub predicate: StatementPredicate,
    pub left_origin: Origin,
    pub left_key_name: String,
    pub right_origin: Option<Origin>,
    pub right_key_name: Option<String>,
    pub optional_value: Option<GoldilocksField>,
}

pub fn entry_to_statement<V: EntryValue>(entry: &Entry<V>, gadget_id: GadgetID) -> Statement {
    Statement {
        predicate: StatementPredicate::ValueOf,
        left_origin: Origin {
            origin_id: GoldilocksField(1),
            gadget_id,
        },
        left_key_name: entry.key_name.clone(),
        right_origin: None,
        right_key_name: None,
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
    pub fn new(entries: &Vec<Entry<ScalarOrVec>>, sk: &SchnorrSecretKey) -> Self {
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let protocol = SchnorrSigner::new();

        let mut payload = entries.clone();
        payload.push(Entry::new(
            "_signer",
            ScalarOrVec::Scalar(protocol.keygen(sk).pk),
        ));
        let payload_vec = payload.to_field_vec();
        let proof = protocol.sign(&payload_vec, sk, &mut rng);
        Self { payload, proof }
    }
}

pub fn remap_origin_ids(inputs: &Vec<Vec<Statement>>) -> Vec<Vec<Statement>> {
    let mut all_in_origin_ids = Vec::new();
    for i in 0..inputs.len() {
        for statement in inputs[i].iter() {
            let left_origin_tuple = (i, statement.left_origin.origin_id);
            if !all_in_origin_ids.contains(&left_origin_tuple) {
                all_in_origin_ids.push(left_origin_tuple);
            }

            if let Some(right_origin) = statement.right_origin {
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

    for input in inputs {
        let mut remapped_input = Vec::new();
        for (idx, statement) in input.iter().enumerate() {
            let mut remapped_statement = statement.clone();
            remapped_statement.left_origin.origin_id = GoldilocksField(
                *origin_id_map
                    .get(&(idx, remapped_statement.left_origin.origin_id))
                    .unwrap(),
            );
            if let Some(mut right_origin) = remapped_statement.right_origin {
                right_origin.origin_id =
                    GoldilocksField(*origin_id_map.get(&(idx, right_origin.origin_id)).unwrap());
            }
            remapped_input.push(remapped_statement);
        }
        remapped_inputs.push(remapped_input);
    }
    remapped_inputs
}

// TODO
impl GODPOD {
    pub fn new(statements: &Vec<Statement>) -> Self {
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let protocol = SchnorrSigner::new();
        let payload = statements.clone();
        let payload_vec = statements.to_field_vec();
        let proof = protocol.sign(&payload_vec, &SchnorrSecretKey { sk: 0 }, &mut rng);
        Self { payload, proof }
    }

    pub fn from_pods(
        inputs: &Vec<SchnorrOrGODPOD>, // will be converted to a vector of statements
        operations: &Vec<(
            Operation,
            Option<usize>,
            Option<usize>,
            Option<&Entry<ScalarOrVec>>,
        )>,
    ) -> Self {
        // Check signatures.
        // Compile/arrange list of statements as Vec<Statement> (after converting each `Entry` into a `ValueOf` statement).
        let statements = inputs
            .iter()
            .map(|pod| match pod {
                SchnorrOrGODPOD::GODPOD(p) => p.clone().payload,
                SchnorrOrGODPOD::SchnorrPOD(p) => p
                    .payload
                    .iter()
                    .map(|entry| entry_to_statement(entry, GadgetID::GOD))
                    .collect::<Vec<Statement>>(),
            })
            .collect::<Vec<Vec<Statement>>>();

        // Now remap
        let remapped_statements = remap_origin_ids(&statements).concat();

        // apply operations one by one on remapped_statements
        let mut final_statements = Vec::new();
        for (operation, left_idx, right_idx, entry) in operations {
            let left_statement = match left_idx {
                Some(idx) => Some(&remapped_statements[*idx]),
                None => None,
            };
            let right_statement = match right_idx {
                Some(idx) => Some(&remapped_statements[*idx]),
                None => None,
            };
            let optional_entry = match entry {
                Some(entry) => Some(entry.clone()),
                None => None,
            };
            final_statements.push(operation.apply_operation(
                GadgetID::GOD,
                left_statement,
                right_statement,
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
}

impl Operation {
    pub fn apply_operation<V: EntryValue>(
        &self,
        gadget_id: GadgetID,
        left_statement: Option<&Statement>,
        right_statement: Option<&Statement>,
        optional_entry: Option<&Entry<V>>,
    ) -> Option<Statement> {
        match (self, left_statement, right_statement, optional_entry) {
            // A new statement is created from a single `Entry`.
            (Self::NewEntry, _, _, Some(entry)) => Some(entry_to_statement(&entry, gadget_id)),
            // A statement is copied from a single (left) statement.
            (Self::CopyStatement, Some(statement), _, _) => Some(statement.clone()),
            // Eq <=> Left entry = right entry
            (Self::EqualityFromEntries, Some(left_entry), Some(right_entry), _) => {
                match (left_entry.predicate, right_entry.predicate) {
                    (StatementPredicate::ValueOf, StatementPredicate::ValueOf)
                        if left_entry.optional_value == right_entry.optional_value =>
                    {
                        Some(Statement {
                            predicate: StatementPredicate::Equal,
                            left_origin: left_entry.left_origin,
                            left_key_name: left_entry.left_key_name.clone(),
                            right_origin: Some(right_entry.left_origin),
                            right_key_name: Some(right_entry.left_key_name.clone()),
                            optional_value: None,
                        })
                    }
                    _ => None,
                }
            }
            // Neq <=> Left entry != right entry
            (Self::NonequalityFromEntries, Some(left_entry), Some(right_entry), _) => {
                match (left_entry.predicate, right_entry.predicate) {
                    (StatementPredicate::ValueOf, StatementPredicate::ValueOf)
                        if left_entry.optional_value != right_entry.optional_value =>
                    {
                        Some(Statement {
                            predicate: StatementPredicate::Equal,
                            left_origin: left_entry.left_origin,
                            left_key_name: left_entry.left_key_name.clone(),
                            right_origin: Some(right_entry.left_origin),
                            right_key_name: Some(right_entry.left_key_name.clone()),
                            optional_value: None,
                        })
                    }
                    _ => None,
                }
            }
            // Gt <=> Left entry > right entry
            (Self::GtFromEntries, Some(left_entry), Some(right_entry), _) => {
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
                            left_origin: left_entry.left_origin,
                            left_key_name: left_entry.left_key_name.clone(),
                            right_origin: Some(right_entry.left_origin),
                            right_key_name: Some(right_entry.left_key_name.clone()),
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
            ) => match (left_statement, right_statement) {
                (
                    Statement {
                        predicate: StatementPredicate::Equal,
                        left_origin: ll_origin,
                        left_key_name: ll_key_name,
                        right_origin:
                            Some(Origin {
                                origin_id: lr_origin_id,
                                gadget_id: _,
                            }),
                        right_key_name: Some(lr_key_name),
                        optional_value: _,
                    },
                    Statement {
                        predicate: StatementPredicate::Equal,
                        left_origin:
                            Origin {
                                origin_id: rl_origin_id,
                                gadget_id: _,
                            },
                        left_key_name: rl_key_name,
                        right_origin: rr_origin @ Some(_),
                        right_key_name: rr_key_name @ Some(_),
                        optional_value: _,
                    },
                ) if (lr_origin_id, &lr_key_name) == ((rl_origin_id, &rl_key_name)) => {
                    Some(Statement {
                        predicate: StatementPredicate::Equal,
                        left_origin: *ll_origin,
                        left_key_name: ll_key_name.clone(),
                        right_origin: *rr_origin,
                        right_key_name: rr_key_name.clone(),
                        optional_value: None,
                    })
                }
                _ => None,
            },
            (Self::GtToNonequality, Some(left_statement), _, _) => match left_statement {
                (Statement {
                    predicate: StatementPredicate::Gt,
                    left_origin,
                    left_key_name,
                    right_origin,
                    right_key_name,
                    optional_value: _,
                }) => Some(Statement {
                    predicate: StatementPredicate::NotEqual,
                    left_origin: *left_origin,
                    left_key_name: left_key_name.clone(),
                    right_origin: *right_origin,
                    right_key_name: right_key_name.clone(),
                    optional_value: None,
                }),
                _ => None,
            },
            _ => None,
        }
    }
}

#[test]
fn op_test() -> Result<(), Error> {
    // Start with some values.
    let scalar1 = GoldilocksField(36);
    let scalar2 = GoldilocksField(52);
    let vector_value = vec![scalar1, scalar2];

    // Create entries
    let entry1 = Entry::new("some key", scalar1);
    let entry2 = Entry::new("some other key", scalar2);
    let entry3 = Entry::new("vector entry", vector_value.clone());
    let entry4 = Entry::new("another scalar1", scalar1);
    let entry5 = Entry::new("yet another scalar1", scalar1);

    // Create entry statements. Unwrapped for convenience.
    let entry_statement1 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, Some(&entry1))
        .unwrap();
    let entry_statement2 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, Some(&entry2))
        .unwrap();
    let entry_statement3 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, Some(&entry3))
        .unwrap();
    let entry_statement4 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, Some(&entry4))
        .unwrap();
    let entry_statement5 = Operation::NewEntry
        .apply_operation(GadgetID::GOD, None, None, Some(&entry5))
        .unwrap();

    let entries = [&entry_statement1, &entry_statement2, &entry_statement3];

    // Copy statements and check for equality of entries.
    entries.into_iter().for_each(|statement| {
        let copy = Operation::CopyStatement
            .apply_operation::<GoldilocksField>(GadgetID::GOD, Some(statement), None, None)
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
            None
        )
    );
    entries.into_iter().for_each(|statement| {
        assert!(
            Operation::EqualityFromEntries.apply_operation::<GoldilocksField>(
                GadgetID::GOD,
                Some(statement),
                Some(statement),
                None
            ) == Some(Statement {
                predicate: StatementPredicate::Equal,
                left_origin: statement.left_origin,
                left_key_name: statement.left_key_name.clone(),
                right_origin: Some(statement.left_origin),
                right_key_name: Some(statement.left_key_name.clone()),
                optional_value: None
            })
        );
    });
    assert!(
        Operation::NonequalityFromEntries.apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&entry_statement1),
            Some(&entry_statement2),
            None
        ) == Some(Statement {
            predicate: StatementPredicate::Equal,
            left_origin: entry_statement1.left_origin,
            left_key_name: entry_statement1.left_key_name.clone(),
            right_origin: Some(entry_statement2.left_origin),
            right_key_name: Some(entry_statement2.left_key_name.clone()),
            optional_value: None
        })
    );
    assert!(
        Operation::EqualityFromEntries.apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&entry_statement1),
            Some(&entry_statement2),
            None
        ) == None
    );

    // Gt check
    let gt_statement = Operation::GtFromEntries.apply_operation::<GoldilocksField>(
        GadgetID::GOD,
        Some(&entry_statement2),
        Some(&entry_statement1),
        None,
    );
    assert!(
        gt_statement
            == Some(Statement {
                predicate: StatementPredicate::Gt,
                left_origin: entry_statement2.left_origin,
                left_key_name: entry_statement2.left_key_name.clone(),
                right_origin: Some(entry_statement1.left_origin),
                right_key_name: Some(entry_statement1.left_key_name.clone()),
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
        )
        .unwrap();
    let eq_statement2 = Operation::EqualityFromEntries
        .apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&entry_statement1),
            Some(&entry_statement5),
            None,
        )
        .unwrap();
    let eq_statement3 = Operation::EqualityFromEntries
        .apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&entry_statement4),
            Some(&entry_statement5),
            None,
        )
        .unwrap();

    assert!(
        Operation::TransitiveEqualityFromStatements.apply_operation::<GoldilocksField>(
            GadgetID::GOD,
            Some(&eq_statement1),
            Some(&eq_statement2),
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
            None
        ) == Some(expected_statement)
    );

    let entry1 = Entry::new("some key", ScalarOrVec::Scalar(scalar1));
    let entry2 = Entry::new("some other key", ScalarOrVec::Scalar(scalar2));
    let entry3 = Entry::new("vector entry", ScalarOrVec::Vector(vector_value.clone()));

    println!("=================TEST POD SCHNORR=================");

    let schnorrPOD1 = SchnorrPOD::new(
        &vec![entry1.clone(), entry2.clone()],
        &SchnorrSecretKey { sk: 25 },
    );

    let schnorrPOD2 = SchnorrPOD::new(
        &vec![entry2.clone(), entry3.clone()],
        &SchnorrSecretKey { sk: 42 },
    );

    // println!(
    //     "verify schnorrpod1: {:?}",
    //     schnorrPOD1.clone().payload.to_field_vec()
    // );
    // println!("verify schnorrpod2: {:?}", schnorrPOD2.verify());

    assert!(schnorrPOD1.verify()? == true);
    assert!(schnorrPOD2.verify()? == true);

    Ok(())
}
