use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::config::Hasher;
use util::hash_string_to_field;

mod util;

pub trait EntryValue: Clone {
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum GadgetID {
    NONE = 0,
    SCHNORR16 = 1,
    GOD = 2,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Origin {
    pub origin_id: GoldilocksField,  // reserve 0 for NONE, 1 for SELF
    pub gadget_id: Option<GadgetID>, // if origin_id is SELF, this is none; otherwise, it's the gadget_id
}

#[derive(Clone, Debug)]
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
        self,
        left_statement: Option<&Statement>,
        right_statement: Option<&Statement>,
        optional_entry: Option<&Entry<V>>,
    ) -> Option<Statement> {
        match (self, left_statement, right_statement, optional_entry) {
            // A new entry is created from a single `Entry`.
            (Self::NewEntry, _, _, Some(entry)) => Some(Statement {
                predicate: StatementPredicate::ValueOf,
                left_origin: Origin {
                    origin_id: GoldilocksField(1),
                    gadget_id: None,
                },
                left_key_name: entry.key_name.clone(),
                right_origin: None,
                right_key_name: None,
                optional_value: Some(entry.value.hash_or_value()),
            }),
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
fn op_test() {
    // Start with some values.
    let scalar1 = GoldilocksField(36);
    let scalar2 = GoldilocksField(52);
    let vector_value = vec![scalar1, scalar2];

    // Create entries
    let entry1 = Entry::new("some key", scalar1);
    let entry2 = Entry::new("some other key", scalar2);
    let entry3 = Entry::new("vector entry", vector_value);
    let entry4 = Entry::new("another scalar1", scalar1);
    let entry5 = Entry::new("yet another scalar1", scalar1);

    // Create entry statements. Unwrapped for convenience.
    let entry_statement1 = Operation::NewEntry
        .apply_operation(None, None, Some(&entry1))
        .unwrap();
    let entry_statement2 = Operation::NewEntry
        .apply_operation(None, None, Some(&entry2))
        .unwrap();
    let entry_statement3 = Operation::NewEntry
        .apply_operation(None, None, Some(&entry3))
        .unwrap();
    let entry_statement4 = Operation::NewEntry
        .apply_operation(None, None, Some(&entry4))
        .unwrap();
    let entry_statement5 = Operation::NewEntry
        .apply_operation(None, None, Some(&entry5))
        .unwrap();

    let entries = [&entry_statement1, &entry_statement2, &entry_statement3];

    // Copy statements and check for equality of entries.
    entries.into_iter().for_each(|statement| {
        let copy = Operation::CopyStatement
            .apply_operation::<GoldilocksField>(Some(statement), None, None)
            .expect("This value should exist.");
        assert!(&copy == statement);
    });

    // Equality checks
    println!(
        "{:?}",
        Operation::EqualityFromEntries.apply_operation::<GoldilocksField>(
            Some(&entry_statement1),
            Some(&entry_statement2),
            None
        )
    );
    entries.into_iter().for_each(|statement| {
        assert!(
            Operation::EqualityFromEntries.apply_operation::<GoldilocksField>(
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
            Some(&entry_statement1),
            Some(&entry_statement2),
            None
        ) == None
    );

    // Gt check
    let gt_statement = Operation::GtFromEntries.apply_operation::<GoldilocksField>(
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
        .apply_operation::<GoldilocksField>(Some(&entry_statement4), Some(&entry_statement1), None)
        .unwrap();
    let eq_statement2 = Operation::EqualityFromEntries
        .apply_operation::<GoldilocksField>(Some(&entry_statement1), Some(&entry_statement5), None)
        .unwrap();
    let eq_statement3 = Operation::EqualityFromEntries
        .apply_operation::<GoldilocksField>(Some(&entry_statement4), Some(&entry_statement5), None)
        .unwrap();

    assert!(
        Operation::TransitiveEqualityFromStatements.apply_operation::<GoldilocksField>(
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
        Operation::GtToNonequality.apply_operation::<GoldilocksField>(Some(&unwrapped_gt_statement), None, None)
            == Some(expected_statement)
        );
}
