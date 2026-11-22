use std::collections::HashMap;

use bytecode::inst::Inst;
use bytecode::opcode::{synonyms_of, Opcode, ALL};
use bytecode::proto::Proto;

use crate::rng::Rng;

pub fn synonymize(proto: &Proto, seed: u64) -> Proto {
    let mut choices: HashMap<Opcode, Vec<Opcode>> = HashMap::new();
    for (op, _) in ALL {
        let set = synonyms_of(*op);
        if set.len() > 1 {
            choices.insert(*op, set);
        }
    }
    let mut rng = Rng::new(seed ^ 0x_5359_4E5F_5043);
    rewrite(proto, &choices, &mut rng)
}

fn rewrite(proto: &Proto, choices: &HashMap<Opcode, Vec<Opcode>>, rng: &mut Rng) -> Proto {
    let code = proto
        .code
        .iter()
        .map(|inst| match choices.get(&inst.op) {
            Some(set) => Inst {
                op: set[rng.below(set.len() as u64) as usize],
                ..inst.clone()
            },
            None => inst.clone(),
        })
        .collect();
    let protos = proto
        .protos
        .iter()
        .map(|c| rewrite(c, choices, rng))
        .collect();
    Proto {
        code,
        protos,
        ..proto.clone()
    }
}
