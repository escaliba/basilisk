pub mod cff;
pub mod dataflow;
pub mod flat_fuse;
pub mod fragment;
pub mod fuse;
pub mod junk;
mod lower;
pub mod microir;
pub mod opaque;
pub mod optimize;
pub mod pad;
mod predicate;
mod rng;
pub mod semgroup;
pub mod semopt;
pub mod shuffle;
pub mod stable_id;
pub mod synonym;

pub use cff::{flatten, flatten_d1};
pub use flat_fuse::flat_fuse;
pub use fragment::{
    fragment_strings, fragment_strings_scoped, fragment_strings_selective, FragStats,
};
pub use fuse::fuse;
pub use junk::junk;
pub use microir::lower_microir;
pub use opaque::opaque;
pub use optimize::{optimize, optimize_with_level};
pub use pad::pad_decoys;
pub use shuffle::{root_proto_order, shuffle_structure};
pub use synonym::synonymize;

pub trait Pass {
    fn name(&self) -> &str;

    fn run(&self, module: &mut ir::Module);
}

pub use stable_id::assign_stable_ids;
