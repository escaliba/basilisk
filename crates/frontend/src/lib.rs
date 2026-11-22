pub mod attributes;
pub mod audit;
pub mod capture_native;
pub mod encfunc_escape;
pub mod encval;
pub mod env_audit;
pub mod inline;
pub mod lookup_native;
pub mod macros;
pub mod native_escape;
pub mod native_strings;
pub mod optin;
pub mod precheck;
pub mod state_cell;
pub use macros::free_vars;
mod lower;
pub mod sanitize;
pub mod stackalloc;
pub mod tblscramble;

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Parse(String),
    Unsupported(String),
    Macro(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parse(msg) => write!(f, "parse error: {msg}"),
            Error::Unsupported(what) => write!(f, "unsupported Luau construct: {what}"),
            Error::Macro(msg) => write!(f, "macro error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

pub fn lower_str(source: &str) -> Result<ir::Module, Error> {
    lower_str_opt(source, true)
}

pub fn lower_str_opt(source: &str, line_info: bool) -> Result<ir::Module, Error> {
    let ast = full_moon::parse(source).map_err(|errors| {
        let joined = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Error::Parse(joined)
    })?;
    lower::module_opt(&ast, line_info)
}
