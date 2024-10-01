use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::config::Hasher;

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

#[derive(Copy, Clone, Debug)]
pub enum GadgetID {
    NONE = 0,
    SCHNORR16 = 1,
    GOD = 2,
}

#[derive(Copy, Clone, Debug)]
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

#[derive(Copy, Clone, Debug)]
pub enum StatementPredicate {
    NONE = 0,
    VALUEOF = 1,
    EQUAL = 2,
    NOTEQUAL = 3,
    GT = 4,
    CONTAINS = 5,
}

#[derive(Clone, Debug)]
pub struct Statement {
    pub predicate: StatementPredicate,
    pub left_origin: Origin,
    pub left_key_name: String,
    pub right_origin: Option<Origin>,
    pub right_key_name: Option<String>,
    pub optional_value: Option<GoldilocksField>,
}

#[derive(Clone, Debug)]
pub enum Operation {
    NONE = 0,
    NEW_ENTRY = 1,
    COPY_STATEMENT = 2,
    EQUALITY_FROM_ENTRIES = 3,
    NONEQUALITY_FROM_ENTRIES = 4,
    GT_FROM_ENTRIES = 5,
    TRANSITIVE_EQUALITY_FROM_STATEMENTS = 6,
    GT_TO_NONEQUALITY = 7,
}

impl Operation {
    pub fn apply_operation<V: EntryValue>(
        &self,
        left_statement: Option<Statement>,
        right_statement: Option<Statement>,
        optional_entry: Option<Entry<V>>,
    ) -> Option<Statement> {
        match self {
            Self::NEW_ENTRY => {
                if let Some(entry) = optional_entry {
                    Some(Statement {
                        predicate: StatementPredicate::VALUEOF,
                        left_origin: Origin {
                            origin_id: GoldilocksField(1),
                            gadget_id: None,
                        },
                        left_key_name: entry.key_name,
                        right_origin: None,
                        right_key_name: None,
                        optional_value: Some(entry.value.hash_or_value()),
                    })
                } else {
                    None
                }
            }
            Self::COPY_STATEMENT => {
                if let Some(statement) = left_statement {
                    Some(statement.clone())
                } else {
                    None
                }
            }
            Self::EQUALITY_FROM_ENTRIES => {
                if let Some(left_entry) = left_statement {
                    if let Some(right_entry) = right_statement {
                        if left_entry.predicate == StatementPredicate::VALUEOF
                            && right_entry.predicate == StatementPredicate::VALUEOF
                            && left_entry.optional_value == right_entry.optional_value
                        {
                            Some(Statement {
                                predicate: StatementPredicate::EQUAL,
                                left_origin: left_entry.left_origin,
                                left_key_name: left_entry.left_key_name,
                                right_origin: right_entry.left_origin,
                                right_key_name: right_entry.left_key_name,
                                optional_value: None,
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
