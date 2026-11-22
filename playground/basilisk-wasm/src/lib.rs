use pipeline::surface::{SurfaceConfig, UnicodeTheme};
use pipeline::{Optimizer, ShellFamily};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
#[serde(default)]
struct Options {
    seed: u64,
    flatten: bool,
    opaque: bool,
    junk: bool,
    fuse: bool,
    minify: bool,
    compress: bool,
    // surface alphabet, e.g. "none" | "ascii"
    theme: String,
    // "default" | "iife" | "setmeta" | "table-entry" | "helper-launcher"
    shell: String,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            seed: 1,
            flatten: true,
            opaque: true,
            junk: true,
            fuse: true,
            minify: true,
            compress: false,
            theme: "none".into(),
            shell: "default".into(),
        }
    }
}

#[derive(Serialize)]
struct Outcome {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[wasm_bindgen]
pub fn obfuscate(source: &str, options_json: &str) -> String {
    let outcome = match run(source, options_json) {
        Ok(output) => Outcome {
            ok: true,
            output: Some(output),
            error: None,
        },
        Err(e) => Outcome {
            ok: false,
            output: None,
            error: Some(e),
        },
    };
    serde_json::to_string(&outcome)
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"failed to encode result\"}".to_string())
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn run(source: &str, options_json: &str) -> Result<String, String> {
    if source.len() > 512 * 1024 {
        return Err("input too large (max 512 KiB)".into());
    }
    let opts: Options =
        serde_json::from_str(options_json).map_err(|e| format!("bad options: {e}"))?;

    let mut config = pipeline::default_config(opts.seed);
    config.flatten = opts.flatten;
    config.opaque = opts.opaque;
    config.junk = opts.junk;
    config.fuse = opts.fuse;
    config.minify = opts.minify;
    config.compress = opts.compress;

    // shell families live in the surface layer, so selecting one enables it
    match opts.shell.as_str() {
        "default" => {}
        "iife" => {
            config.surface = true;
            config.shell_family = Some(ShellFamily::Iife);
        }
        "setmeta" => {
            config.surface = true;
            config.shell_family = Some(ShellFamily::SetMeta);
        }
        "table-entry" => {
            config.surface = true;
            config.shell_family = Some(ShellFamily::TableEntry);
        }
        "helper-launcher" => {
            config.surface = true;
            config.shell_family = Some(ShellFamily::HelperLauncher);
        }
        other => return Err(format!("unknown shell `{other}`")),
    }

    let theme = UnicodeTheme::from_token(&opts.theme)
        .ok_or_else(|| format!("unknown theme `{}`", opts.theme))?;

    let surface = if theme == UnicodeTheme::None {
        SurfaceConfig::default()
    } else {
        SurfaceConfig {
            theme,
            ..Default::default()
        }
    };
    surface.validate().map_err(|e| e.to_string())?;

    pipeline::obfuscate_str(source, &config, Optimizer::Off, false, &surface)
        .map_err(|e| e.to_string())
}
