pub mod actvm;
pub mod aead;
pub mod blockstate;
pub mod cfg;
pub mod compile;
pub mod crypt;
pub mod disasm;
pub mod encoder;
pub mod encoding;
pub mod format;
pub mod gensuper;
pub mod inst;
pub mod intrinsic;
pub mod kepoch;
pub mod literal;
pub mod lzw;
pub mod microir;
pub mod opcode;
pub mod proto;
pub mod sha256;
pub mod streamdigest;
pub mod superop;

pub use compile::compile;
pub use inst::Inst;
pub use opcode::Opcode;
pub use proto::{Const, Proto, UpvalDesc};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_table_is_contiguous() {
        for (i, (op, _)) in opcode::ALL.iter().enumerate() {
            assert_eq!(opcode::concrete(*op) as usize, i);
            assert_eq!(opcode::from_concrete(i as u8), Some(*op));
        }
    }

    #[test]
    fn serialization_round_trips() {
        let child = Proto {
            num_params: 1,
            is_vararg: false,
            max_stack: 3,
            code: vec![
                Inst::new(Opcode::GetUpval, 0, 0, 0),
                Inst::new(Opcode::Return, 0, 2, 0),
            ],
            consts: vec![Const::Number(2.5), Const::Str(b"hi\x00\xff".to_vec())],
            upvals: vec![UpvalDesc {
                in_stack: true,
                index: 4,
            }],
            protos: vec![],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        };
        let main = Proto {
            num_params: 0,
            is_vararg: true,
            max_stack: 8,
            code: vec![
                Inst::new(Opcode::LoadK, 0, 0, 0),
                Inst::new(Opcode::Closure, 1, 0, 0),
                Inst::new(Opcode::Call, 1, 1, 1),
                Inst::new(Opcode::Return, 0, 1, 0),
            ],
            consts: vec![Const::Number(-42.0), Const::Str(b"print".to_vec())],
            upvals: vec![],
            protos: vec![child],
            line_info: vec![],
            hot_callback: None,
            stable_id: None,
            d1: None,
        };

        let bytes = encoder::serialize(&main);
        let back = encoder::deserialize(&bytes).expect("deserialize");
        assert_eq!(main, back);
    }
}
