pub mod keys;
pub mod meme;
pub mod rng;
pub mod theme;
pub mod types;

pub use types::TypeNoiseMode;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum UnicodeTheme {
    #[default]
    None = 0,
    Ascii = 1,
}

impl UnicodeTheme {
    pub fn token(self) -> &'static str {
        match self {
            UnicodeTheme::None => "none",
            UnicodeTheme::Ascii => "ascii",
        }
    }

    pub fn from_token(s: &str) -> Option<Self> {
        Some(match s {
            "none" => UnicodeTheme::None,
            "ascii" => UnicodeTheme::Ascii,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct SurfaceConfig {
    pub theme: UnicodeTheme,
    pub memes: bool,
    pub meme_strings: Option<Vec<String>>,
    pub types: TypeNoiseMode,
}

#[derive(Clone, Debug)]
pub struct SurfacePlan {
    pub seed: u64,
    pub theme: UnicodeTheme,
    pub memes: Vec<String>,
    pub types: TypeNoiseMode,
}

pub const DEFAULT_MEME_COUNT: usize = 6;
pub const MAX_SURFACE_EXPANSION: u64 = 64;

impl SurfaceConfig {
    pub fn is_off(&self) -> bool {
        self.theme == UnicodeTheme::None && !self.memes && !self.types.is_on()
    }

    pub fn validate(&self) -> Result<(), String> {
        match (self.memes, &self.meme_strings) {
            (false, Some(_)) => Err("surface: meme_strings supplied but memes are disabled".into()),
            (true, Some(list)) if list.is_empty() => Err("surface: meme_strings is empty".into()),
            (true, Some(list)) => meme::from_strings(list).map(|_| ()),
            _ => Ok(()),
        }
    }

    pub fn resolve(
        &self,
        seed: u64,
        catalog: Option<&meme::Catalog>,
    ) -> Result<SurfacePlan, String> {
        let theme = self.theme;

        let memes = if self.memes {
            let cat = catalog.ok_or_else(|| {
                "surface: --surface-memes requires a meme catalog (set BASIL_MEME_CATALOG or create assets/meme_strings.toml)".to_string()
            })?;
            if cat.strings.is_empty() {
                return Err(
                    "surface: --surface-memes enabled but the meme catalog is empty".into(),
                );
            }
            meme::select(cat, seed, DEFAULT_MEME_COUNT)
        } else {
            Vec::new()
        };

        Ok(SurfacePlan {
            seed,
            theme,
            memes,
            types: self.types,
        })
    }
}

impl SurfacePlan {
    pub fn is_off(&self) -> bool {
        self.theme == UnicodeTheme::None && self.memes.is_empty()
    }
}

pub use meme::{Emission, ANCHOR_COUNT};

pub fn surface_emission(plan: &SurfacePlan) -> Emission {
    meme::emission(plan)
}

pub fn decorate_payload(
    packer_out: &str,
    plan: &SurfacePlan,
    offset: Option<&str>,
) -> (String, String) {
    meme::decorate_payload_assignment(packer_out, plan, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off() {
        assert!(SurfaceConfig::default().is_off());
        assert_eq!(SurfaceConfig::default().theme, UnicodeTheme::None);
    }

    #[test]
    fn memes_without_catalog_errors() {
        let c = SurfaceConfig {
            memes: true,
            ..Default::default()
        };
        assert!(c.resolve(1, None).is_err());
        let empty = meme::Catalog {
            version: 1,
            strings: vec![],
        };
        assert!(c.resolve(1, Some(&empty)).is_err());
    }

    #[test]
    fn validate_default_and_memes_off_ok() {
        assert!(SurfaceConfig::default().validate().is_ok());
        let a = SurfaceConfig {
            memes: false,
            meme_strings: None,
            ..Default::default()
        };
        assert!(a.validate().is_ok());
    }

    #[test]
    fn validate_rejects_pool_without_memes() {
        let d = SurfaceConfig {
            memes: false,
            meme_strings: Some(vec!["x".into()]),
            ..Default::default()
        };
        assert!(d.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_pool() {
        let e = SurfaceConfig {
            memes: true,
            meme_strings: Some(vec![]),
            ..Default::default()
        };
        assert!(e.validate().is_err());
    }

    #[test]
    fn validate_accepts_valid_pool_and_rejects_bad_entries() {
        let ok = SurfaceConfig {
            memes: true,
            meme_strings: Some(vec!["alpha".into(), "beta".into()]),
            ..Default::default()
        };
        assert!(ok.validate().is_ok());
        let ctrl = SurfaceConfig {
            memes: true,
            meme_strings: Some(vec!["ok".into(), "bad\u{0}nul".into()]),
            ..Default::default()
        };
        assert!(ctrl.validate().is_err());
    }
}
