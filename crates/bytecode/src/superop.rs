use crate::opcode::Opcode;

pub const CATALOGUE: &[(Opcode, &[Opcode])] = &[
    (
        Opcode::Super0,
        &[Opcode::Move, Opcode::LoadK, Opcode::GetTable],
    ),
    (
        Opcode::Super1,
        &[Opcode::LoadK, Opcode::GetTable, Opcode::Move],
    ),
    (
        Opcode::Super2,
        &[Opcode::GetGlobal, Opcode::LoadK, Opcode::Move],
    ),
    (Opcode::Super8, &[Opcode::Mul, Opcode::LoadK, Opcode::LtK]),
    (Opcode::Super3, &[Opcode::Move, Opcode::LoadK]),
    (Opcode::Super4, &[Opcode::LoadK, Opcode::GetTable]),
    (Opcode::Super5, &[Opcode::GetGlobal, Opcode::LoadK]),
    (Opcode::Super6, &[Opcode::GetTable, Opcode::Move]),
    (Opcode::Super7, &[Opcode::Move, Opcode::Move]),
    (Opcode::Super9, &[Opcode::LoadK, Opcode::LoadK]),
    (Opcode::FlatStateEq, &[Opcode::LoadK, Opcode::Eq]),
];

pub fn provenance_only(op: Opcode) -> bool {
    matches!(op, Opcode::FlatStateEq)
}

pub fn sub_ops(op: Opcode) -> Option<&'static [Opcode]> {
    CATALOGUE.iter().find(|(o, _)| *o == op).map(|(_, s)| *s)
}

pub fn is_super(op: Opcode) -> bool {
    sub_ops(op).is_some()
}

pub fn operand_count(op: Opcode) -> usize {
    sub_ops(op).map_or(3, |s| 3 * s.len())
}
