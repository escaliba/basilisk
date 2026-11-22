use crate::rng::{Rng, DOMAIN_MEME};
use crate::{keys, theme, SurfacePlan};

pub const MAX_STRING_BYTES: usize = 512;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_TOTAL_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug)]
pub struct Catalog {
    pub version: u32,
    pub strings: Vec<String>,
}

pub fn load(path: &std::path::Path) -> Result<Catalog, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("surface: cannot read meme catalog {}: {e}", path.display()))?;
    parse(&text)
}

pub fn parse(text: &str) -> Result<Catalog, String> {
    let val: toml::Value = text
        .parse()
        .map_err(|e| format!("surface: meme catalog is not valid TOML: {e}"))?;
    let version = val
        .get("version")
        .and_then(|v| v.as_integer())
        .ok_or("surface: meme catalog missing integer `version`")?;
    if version != 1 {
        return Err(format!(
            "surface: unsupported meme catalog version {version} (expected 1)"
        ));
    }
    let arr = val
        .get("strings")
        .and_then(|v| v.as_array())
        .ok_or("surface: meme catalog missing `strings` array")?;
    let mut raw: Vec<String> = Vec::with_capacity(arr.len());
    for (i, entry) in arr.iter().enumerate() {
        let s = entry
            .as_str()
            .ok_or_else(|| format!("surface: meme catalog entry {i} is not a string"))?;
        raw.push(s.to_string());
    }
    from_strings(&raw)
}

pub fn from_strings(raw: &[String]) -> Result<Catalog, String> {
    if raw.len() > MAX_ENTRIES {
        return Err(format!(
            "surface: meme catalog has {} entries (max {MAX_ENTRIES})",
            raw.len()
        ));
    }
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut strings: Vec<String> = Vec::new();
    let mut total = 0usize;
    for (i, s) in raw.iter().enumerate() {
        if s.is_empty() {
            return Err(format!("surface: meme catalog entry {i} is empty"));
        }
        if s.len() > MAX_STRING_BYTES {
            return Err(format!(
                "surface: meme catalog entry {i} is {} bytes (max {MAX_STRING_BYTES})",
                s.len()
            ));
        }
        for &b in s.as_bytes() {
            if b == 0 {
                return Err(format!(
                    "surface: meme catalog entry {i} contains a NUL byte"
                ));
            }
            if b < 0x20 && b != b'\t' {
                return Err(format!(
                    "surface: meme catalog entry {i} contains control byte {b:#x}"
                ));
            }
        }
        total += s.len();
        if total > MAX_TOTAL_BYTES {
            return Err(format!(
                "surface: meme catalog exceeds {MAX_TOTAL_BYTES} total bytes"
            ));
        }
        if seen.insert(s.as_str()) {
            strings.push(s.clone());
        }
    }
    Ok(Catalog {
        version: 1,
        strings,
    })
}

pub fn to_toml(strings: &[String]) -> String {
    let mut out = String::from("version = 1\nstrings = [\n");
    for s in strings {
        out.push_str("    \"");
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\t' => out.push_str("\\t"),
                _ => out.push(ch),
            }
        }
        out.push_str("\",\n");
    }
    out.push_str("]\n");
    out
}

pub fn select(cat: &Catalog, seed: u64, count: usize) -> Vec<String> {
    if cat.strings.is_empty() {
        return Vec::new();
    }
    let mut rng = Rng::new(seed ^ DOMAIN_MEME);
    let n = cat.strings.len();
    let take = count.min(n);
    let mut idx: Vec<usize> = (0..n).collect();
    for i in 0..take {
        let j = i + rng.below((n - i) as u64) as usize;
        idx.swap(i, j);
    }
    idx[..take]
        .iter()
        .map(|&i| cat.strings[i].clone())
        .collect()
}

pub fn luau_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for &b in s.as_bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7E => out.push(b as char),
            _ => out.push_str(&format!("\\{b}")),
        }
    }
    out.push('"');
    out
}

pub struct Namer {
    tag: String,
    n: u32,
}

impl Namer {
    pub fn new(seed: u64) -> Self {
        let mut rng = Rng::new(seed ^ 0x_5346_4e41_4d45);
        let letters = b"abcdefghijklmnopqrstuvwxyz";
        let tag: String = (0..4)
            .map(|_| letters[rng.below(26) as usize] as char)
            .collect();
        Namer {
            tag: format!("_sf{tag}"),
            n: 0,
        }
    }
    pub fn fresh(&mut self) -> String {
        self.n += 1;
        format!("{}{}", self.tag, self.n)
    }
}

pub fn carrier_int(value: u64, rng: &mut Rng) -> String {
    if value <= 8 && rng.below(3) == 0 {
        if value == 0 {
            return "#{}".to_string();
        }
        let elems = vec!["0"; value as usize].join(";");
        return format!("#{{{elems}}}");
    }
    value.to_string()
}

const DOMAIN_DIST: u64 = 0x_4449_5354_5249_4255;

pub const ANCHOR_COUNT: usize = 11;
pub const OCC_MIN: usize = 24;
pub const OCC_MAX: usize = 30;
const EARLY_SLOTS: usize = 6;

pub struct Emission {
    pub preamble: String,
    pub anchors: Vec<String>,
    pub offset: String,
}

fn offset_lit() -> String {
    "1".to_string()
}

fn distinct_memes(plan: &SurfacePlan) -> Vec<&String> {
    let mut seen = std::collections::HashSet::new();
    plan.memes
        .iter()
        .filter(|m| seen.insert((*m).as_str()))
        .collect()
}

pub(crate) fn offset_only(
    plan: &SurfacePlan,
    rng: &mut Rng,
    namer: &mut Namer,
) -> (String, String) {
    if theme::get(plan.theme).is_some() {
        let key = keys::generate(plan.theme, plan.seed ^ rng.next(), 1);
        if let Some(k) = key.first() {
            let kt = namer.fresh();
            let v = offset_lit();
            let decls = format!("local {kt} = {{ [{}] = {v} }}\n", keys::luau_string_key(k));
            return (decls, format!("{kt}[{}]", keys::luau_string_key(k)));
        }
    }
    (String::new(), offset_lit())
}

fn carrier_stmt(acc: &str, meme: &str, themed: bool, plan: &SurfacePlan, rng: &mut Rng) -> String {
    let t = rng.range(1, 60);
    let comp = t + meme.len() as u64;
    let core = format!("({} - #{})", comp, luau_str(meme));
    if themed {
        if let Some(k) = keys::generate(plan.theme, plan.seed ^ rng.next(), 1).first() {
            let kk = keys::luau_string_key(k);
            return format!("{acc} = {acc} + (({{[{kk}] = {core}}})[{kk}] - {t})");
        }
    }
    match rng.below(4) {
        0 => format!("{acc} = {acc} - ({t} - {core})"),
        1 => format!("{acc} = {acc} + ({{[{t}] = 0}})[{core}]"),
        2 => format!("{acc} = {acc} + ({core} == {t} and 0 or 1)"),
        _ => format!("{acc} = {acc} + ({core} - {t})"),
    }
}

const DOMAIN_INK: u64 = 0x_4D45_4D45_494E_4B;

pub fn plan_pool(plan: &SurfacePlan, max_sites: usize) -> Vec<(String, usize)> {
    let memes = distinct_memes(plan);
    if memes.is_empty() || max_sites == 0 {
        return Vec::new();
    }
    let mut rng = Rng::new(plan.seed ^ DOMAIN_MEME ^ DOMAIN_DIST);
    let target = (OCC_MIN + rng.below((OCC_MAX - OCC_MIN + 1) as u64) as usize).min(max_sites);
    let d = memes.len();
    let mut order: Vec<usize> = (0..d).collect();
    rng.shuffle(&mut order);
    (0..target)
        .map(|i| (luau_str(memes[order[i % d]]), memes[order[i % d]].len()))
        .collect()
}

fn ink_num(v: i64) -> String {
    let mag = v.unsigned_abs();
    if v < 0 {
        format!("-{mag}")
    } else {
        mag.to_string()
    }
}

pub fn wrap_expr(inner: &str, lit: &str, len: usize, rng: &mut Rng) -> String {
    let l = len as i64;
    match rng.below(8) {
        0 => format!("(-#{lit} + ({inner} + {}))", ink_num(l)),
        1 => format!("(({inner} + {}) - #{lit})", ink_num(l)),
        2 => format!("({inner} + (-#{lit} + {}))", ink_num(l)),
        3 => format!("({inner} - (#{lit} - {}))", ink_num(l)),
        4 => format!("({inner} + (#{lit} - {}))", ink_num(l)),
        5 => format!("(({} - #{lit}) + {inner})", ink_num(l)),
        6 => format!("({inner} - ({} - #{lit}))", ink_num(l)),
        _ => {
            let a = rng.range(1, 60) as i64;
            format!(
                "(({inner} + {}) + (-#{lit} + {}))",
                ink_num(a),
                ink_num(l - a)
            )
        }
    }
}

pub struct MemeInk {
    pool: Vec<(String, usize)>,
    cursor: usize,
    cap: usize,
    rng: Rng,
    counts: std::collections::HashMap<&'static str, usize>,
    seen: std::collections::HashMap<&'static str, usize>,
    sites: std::collections::HashMap<&'static str, usize>,
    pub log: Vec<(&'static str, String)>,
}

impl MemeInk {
    pub fn new(plan: &SurfacePlan, cap: usize) -> Option<MemeInk> {
        let pool = plan_pool(plan, OCC_MAX);
        if pool.is_empty() {
            return None;
        }
        Some(MemeInk {
            pool,
            cursor: 0,
            cap,
            rng: Rng::new(plan.seed ^ DOMAIN_INK),
            counts: std::collections::HashMap::new(),
            seen: std::collections::HashMap::new(),
            sites: std::collections::HashMap::new(),
            log: Vec::new(),
        })
    }

    pub fn expect_sites(&mut self, region: &'static str, n: usize) {
        self.sites.insert(region, n);
    }

    pub fn wrap(&mut self, region: &'static str, inner: &str) -> Option<String> {
        let seen = *self.seen.entry(region).or_insert(0);
        self.seen.insert(region, seen + 1);
        if self.cursor >= self.pool.len() {
            return None;
        }
        let placed = *self.counts.get(region).unwrap_or(&0);
        if placed >= self.cap {
            return None;
        }
        if let Some(&sites) = self.sites.get(region) {
            let want = self.cap.min(sites);
            if sites > 0 && (seen + 1) * want / sites <= placed {
                return None;
            }
        }
        let (lit, len) = self.pool[self.cursor].clone();
        self.cursor += 1;
        *self.counts.entry(region).or_insert(0) += 1;
        self.log.push((region, lit.trim_matches('"').to_string()));
        Some(wrap_expr(inner, &lit, len, &mut self.rng))
    }

    pub fn placed(&self) -> usize {
        self.cursor
    }

    pub fn regions_used(&self) -> usize {
        self.counts.len()
    }
}

pub fn emission(plan: &SurfacePlan) -> Emission {
    let empty = vec![String::new(); ANCHOR_COUNT];
    let memes = distinct_memes(plan);
    if memes.is_empty() {
        let mut rng = Rng::new(plan.seed ^ DOMAIN_MEME ^ DOMAIN_DIST);
        let mut namer = Namer::new(plan.seed ^ DOMAIN_DIST);
        let (preamble, offset) = offset_only(plan, &mut rng, &mut namer);
        return Emission {
            preamble,
            anchors: empty,
            offset,
        };
    }

    let mut rng = Rng::new(plan.seed ^ DOMAIN_MEME ^ DOMAIN_DIST);
    let mut namer = Namer::new(plan.seed ^ DOMAIN_DIST);
    let acc = namer.fresh();

    let slots = ANCHOR_COUNT + 1;
    let mut counts = vec![0usize; slots];
    for (s, c) in counts.iter_mut().enumerate() {
        *c = if s < EARLY_SLOTS { 1 } else { 3 };
    }
    let extra = rng.below((EARLY_SLOTS + 1) as u64) as usize;
    let mut early: Vec<usize> = (0..EARLY_SLOTS).collect();
    rng.shuffle(&mut early);
    for &s in early.iter().take(extra) {
        counts[s] = 2;
    }
    let total: usize = counts.iter().sum();

    let mut pool: Vec<&String> = memes.clone();
    rng.shuffle(&mut pool);
    let mut occ: Vec<&String> = (0..total).map(|i| pool[i % pool.len()]).collect();
    rng.shuffle(&mut occ);

    let flag_subset = |frac_num: usize, frac_den: usize, rng: &mut Rng| -> Vec<bool> {
        let mut f = vec![false; total];
        let target = total * frac_num / frac_den;
        let mut idx: Vec<usize> = (0..total).collect();
        rng.shuffle(&mut idx);
        for &i in idx.iter().take(target) {
            f[i] = true;
        }
        f
    };
    let themed = theme::get(plan.theme).is_some();
    let th_flags = if themed {
        flag_subset(1, 3, &mut rng)
    } else {
        vec![false; total]
    };

    let mut chunks: Vec<String> = Vec::with_capacity(slots);
    let mut k = 0usize;
    for &c in &counts {
        let mut buf = String::new();
        for _ in 0..c {
            buf.push_str(&carrier_stmt(&acc, occ[k], th_flags[k], plan, &mut rng));
            buf.push('\n');
            k += 1;
        }
        chunks.push(buf);
    }

    let one = offset_lit();
    let offset = format!("({one} + {acc})");
    let preamble = format!("local {acc} = 0\n{}", chunks[0]);
    Emission {
        preamble,
        anchors: chunks[1..].to_vec(),
        offset,
    }
}

pub fn decorate_payload_assignment(
    packer_out: &str,
    plan: &SurfacePlan,
    offset: Option<&str>,
) -> (String, String) {
    let anchor = "local PAYLOAD = ";
    let Some(pos) = packer_out.rfind(anchor) else {
        return (String::new(), packer_out.to_string());
    };
    let head = &packer_out[..pos];
    let rhs = &packer_out[pos + anchor.len()..];
    let (preamble, off) = match offset {
        Some(o) => (String::new(), o.to_string()),
        None => {
            let mut rng = Rng::new(plan.seed ^ DOMAIN_MEME ^ 0x_4445_434f_52);
            let mut namer = Namer::new(plan.seed ^ 0x_4445_434f_52);
            offset_only(plan, &mut rng, &mut namer)
        }
    };
    (
        preamble,
        format!("{head}local PAYLOAD = string.sub({rhs}, {off})"),
    )
}

fn is_carrier_line(line: &str) -> bool {
    line.contains(" - #\"")
}

#[derive(Clone, Debug)]
pub struct Preview {
    pub distinct: Vec<String>,
    pub counts: Vec<(String, usize)>,
    pub total: usize,
    pub slots: Vec<usize>,
}

pub fn preview(plan: &SurfacePlan) -> Preview {
    let distinct: Vec<String> = distinct_memes(plan).into_iter().cloned().collect();
    let em = emission(plan);
    let mut slots: Vec<usize> = Vec::with_capacity(ANCHOR_COUNT + 1);
    slots.push(em.preamble.lines().filter(|l| is_carrier_line(l)).count());
    for a in &em.anchors {
        slots.push(a.lines().filter(|l| is_carrier_line(l)).count());
    }
    let joined = format!("{}\n{}", em.preamble, em.anchors.join("\n"));
    let mut counts: Vec<(String, usize)> = distinct
        .iter()
        .map(|m| {
            (
                m.clone(),
                joined.matches(&format!("#{}", luau_str(m))).count(),
            )
        })
        .collect();
    let total = counts.iter().map(|(_, c)| *c).sum();
    counts.sort_by(|a, b| b.1.cmp(&a.1));
    Preview {
        distinct,
        counts,
        total,
        slots,
    }
}

pub fn band_distribution(artifact: &str, memes: &[&str]) -> (usize, [usize; 5]) {
    let b = artifact.as_bytes();
    let n = b.len();
    let mut masked = vec![false; n];
    let mut i = 0;
    while i < n {
        if b[i] == b'[' {
            let mut j = i + 1;
            let mut eq = 0;
            while j < n && b[j] == b'=' {
                eq += 1;
                j += 1;
            }
            if j < n && b[j] == b'[' {
                let close: Vec<u8> = std::iter::once(b']')
                    .chain(std::iter::repeat(b'=').take(eq))
                    .chain(std::iter::once(b']'))
                    .collect();
                let mut k = j + 1;
                let mut end = n;
                while k + close.len() <= n {
                    if &b[k..k + close.len()] == close.as_slice() {
                        end = k + close.len();
                        break;
                    }
                    k += 1;
                }
                for m in masked.iter_mut().take(end).skip(i) {
                    *m = true;
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    let mut prefix = vec![0usize; n + 1];
    for idx in 0..n {
        prefix[idx + 1] = prefix[idx] + if masked[idx] { 0 } else { 1 };
    }
    let shell = prefix[n].max(1);
    let mut bands = [0usize; 5];
    let mut total = 0;
    for m in memes {
        let needle = format!("#{}", luau_str(m));
        for (off, _) in artifact.match_indices(&needle) {
            let band = ((prefix[off] as f64 / shell as f64) * 5.0) as usize;
            bands[band.min(4)] += 1;
            total += 1;
        }
    }
    (total, bands)
}

#[derive(Clone, Debug)]
pub struct Audit {
    pub entries: usize,
    pub unique: usize,
    pub duplicates: usize,
    pub shortest: usize,
    pub longest: usize,
    pub median: usize,
    pub invalid: usize,
    pub non_ascii: usize,
    pub total_bytes: usize,
}

pub fn audit(text: &str) -> Result<Audit, String> {
    let val: toml::Value = text
        .parse()
        .map_err(|e| format!("surface: meme catalog is not valid TOML: {e}"))?;
    let arr = val
        .get("strings")
        .and_then(|v| v.as_array())
        .ok_or("surface: meme catalog missing `strings` array")?;
    let mut lens: Vec<usize> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut unique = 0usize;
    let mut invalid = 0usize;
    let mut non_ascii = 0usize;
    let mut total_bytes = 0usize;
    for entry in arr {
        let Some(s) = entry.as_str() else {
            invalid += 1;
            continue;
        };
        total_bytes += s.len();
        let bad = s.is_empty()
            || s.len() > MAX_STRING_BYTES
            || s.as_bytes()
                .iter()
                .any(|&b| b == 0 || (b < 0x20 && b != b'\t'));
        if bad {
            invalid += 1;
            continue;
        }
        if s.bytes().any(|b| b >= 0x80) {
            non_ascii += 1;
        }
        lens.push(s.len());
        if seen.insert(s) {
            unique += 1;
        }
    }
    lens.sort_unstable();
    let median = if lens.is_empty() {
        0
    } else {
        lens[lens.len() / 2]
    };
    Ok(Audit {
        entries: arr.len(),
        unique,
        duplicates: lens.len().saturating_sub(unique),
        shortest: lens.first().copied().unwrap_or(0),
        longest: lens.last().copied().unwrap_or(0),
        median,
        invalid,
        non_ascii,
        total_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnicodeTheme;

    fn plan(memes: Vec<String>, theme: UnicodeTheme) -> SurfacePlan {
        SurfacePlan {
            seed: 7,
            theme,
            memes,
            types: crate::types::TypeNoiseMode::Off,
        }
    }

    #[test]
    fn luau_str_preserves_byte_length() {
        for s in [
            "abc",
            "a\"b",
            "a\\b",
            "it's",
            "mult\u{00e9}byte \u{1f600}",
            "tab\there",
            "x",
        ] {
            let lit = luau_str(s);
            assert!(lit.starts_with('"') && lit.ends_with('"'));
            let inner = &lit[1..lit.len() - 1];
            let mut runtime_bytes = 0usize;
            let bytes: Vec<u8> = inner.bytes().collect();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    let next = bytes[i + 1];
                    if next == b'"' || next == b'\\' {
                        runtime_bytes += 1;
                        i += 2;
                    } else {
                        let mut j = i + 1;
                        while j < bytes.len() && bytes[j].is_ascii_digit() && j - i <= 3 {
                            j += 1;
                        }
                        runtime_bytes += 1;
                        i = j;
                    }
                } else {
                    runtime_bytes += 1;
                    i += 1;
                }
            }
            assert_eq!(
                runtime_bytes,
                s.len(),
                "runtime #{s:?} must equal utf8 byte length"
            );
        }
    }

    #[test]
    fn carrier_int_equals_value_when_decoded() {
        for v in [0u64, 1, 2, 5, 8, 15, 16, 24, 100] {
            for seed in 0..60u64 {
                let p = plan(
                    vec!["hello".into(), "it's \u{1f600}".into()],
                    UnicodeTheme::None,
                );
                let mut rng = Rng::new(seed);
                let expr = carrier_int(v, &mut rng);
                assert_eq!(
                    eval_const(&expr, &p),
                    v as i64,
                    "expr {expr:?} must equal {v}"
                );
            }
        }
    }

    fn eval_const(expr: &str, _p: &SurfacePlan) -> i64 {
        let e = expr.trim();
        if let Some(inner) = e.strip_prefix('(').and_then(|x| x.strip_suffix(')')) {
            let parts: Vec<&str> = inner.splitn(2, " - #").collect();
            let comp: i64 = parts[0].trim().parse().unwrap();
            let s = parts[1].trim();
            let inner_s = &s[1..s.len() - 1];
            let mut n = 0i64;
            let bytes: Vec<u8> = inner_s.bytes().collect();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    let nx = bytes[i + 1];
                    if nx == b'"' || nx == b'\\' {
                        n += 1;
                        i += 2;
                    } else {
                        let mut j = i + 1;
                        while j < bytes.len() && bytes[j].is_ascii_digit() && j - i <= 3 {
                            j += 1;
                        }
                        n += 1;
                        i = j;
                    }
                } else {
                    n += 1;
                    i += 1;
                }
            }
            return comp - n;
        }
        if let Some(inner) = e.strip_prefix("#{").and_then(|x| x.strip_suffix('}')) {
            if inner.is_empty() {
                return 0;
            }
            return inner.split(';').count() as i64;
        }
        e.parse::<i64>().unwrap()
    }

    #[test]
    fn parse_validates() {
        assert!(parse("version = 2\nstrings = []").is_err());
        assert!(parse("strings = []").is_err());
        assert!(parse("version = 1").is_err());
        let c = parse("version = 1\nstrings = [\"a\",\"b\",\"a\"]").unwrap();
        assert_eq!(
            c.strings,
            vec!["a".to_string(), "b".to_string()],
            "dedupe keeps first order"
        );
        assert!(
            parse("version = 1\nstrings = [\"\"]").is_err(),
            "empty entry rejected"
        );
        assert!(
            parse("version = 1\nstrings = [\"a\\u0000\"]").is_err(),
            "NUL rejected"
        );
    }

    fn stmts(em: &Emission) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for line in em.preamble.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with("local ") && l.ends_with("= 0") {
                continue;
            }
            out.push(l.to_string());
        }
        for a in &em.anchors {
            for line in a.lines() {
                let l = line.trim();
                if !l.is_empty() {
                    out.push(l.to_string());
                }
            }
        }
        out
    }

    fn core_target(stmt: &str) -> i64 {
        let marker = " - #\"";
        let mpos = stmt.find(marker).expect("core has - #\"");
        let b = stmt.as_bytes();
        let mut s = mpos;
        while s > 0 && (b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'_') {
            s -= 1;
        }
        let comp = stmt[s..mpos].parse::<i64>().unwrap();
        let mut i = mpos + marker.len();
        let mut runtime = 0i64;
        while i < b.len() {
            if b[i] == b'\\' {
                let nx = b[i + 1];
                if nx == b'"' || nx == b'\\' {
                    runtime += 1;
                    i += 2;
                } else {
                    let mut j = i + 1;
                    while j < b.len() && b[j].is_ascii_digit() && j - i <= 3 {
                        j += 1;
                    }
                    runtime += 1;
                    i = j;
                }
            } else if b[i] == b'"' {
                break;
            } else {
                runtime += 1;
                i += 1;
            }
        }
        comp - runtime
    }

    fn dist_plan(memes: Vec<String>, theme: UnicodeTheme) -> SurfacePlan {
        SurfacePlan {
            seed: 20261012,
            theme,
            memes,
            types: crate::types::TypeNoiseMode::Off,
        }
    }

    #[test]
    fn emission_offset_only_without_memes() {
        let em = emission(&dist_plan(vec![], UnicodeTheme::None));
        assert!(
            em.preamble.is_empty(),
            "no preamble without memes/theme: {}",
            em.preamble
        );
        assert_eq!(em.offset, "1");
        assert!(
            em.anchors.iter().all(|a| a.is_empty()),
            "no anchors without memes"
        );
        assert_eq!(em.anchors.len(), ANCHOR_COUNT);
    }

    #[test]
    fn emission_distributes_total_in_range_and_every_carrier_compensated() {
        let memes = vec![
            "alpha".into(),
            "beta".into(),
            "gamma".into(),
            "delta".into(),
            "eps".into(),
        ];
        let em = emission(&dist_plan(memes.clone(), UnicodeTheme::None));
        let acc = em.preamble.lines().next().unwrap();
        assert!(
            acc.starts_with("local ") && acc.ends_with("= 0"),
            "preamble declares accumulator: {acc}"
        );

        let all = stmts(&em);
        assert!(
            (OCC_MIN..=OCC_MAX).contains(&all.len()),
            "total occurrences {} out of [{OCC_MIN},{OCC_MAX}]",
            all.len()
        );

        for s in &all {
            let t = core_target(s);
            assert!(
                (1..=60).contains(&t),
                "carrier not compensated to a valid target ({t}): {s}"
            );
        }

        for m in &memes {
            let n = all
                .iter()
                .filter(|s| s.contains(&format!("#{}", luau_str(m))))
                .count();
            assert!(n >= 2, "meme {m:?} must recur (>=2), saw {n}");
        }

        assert!(
            em.offset.starts_with('('),
            "offset is the accumulator sum: {}",
            em.offset
        );
    }

    #[test]
    fn emission_is_deterministic() {
        let p = dist_plan(
            vec!["a".into(), "bb".into(), "ccc".into()],
            UnicodeTheme::Ascii,
        );
        let a = emission(&p);
        let b = emission(&p);
        assert_eq!(a.preamble, b.preamble);
        assert_eq!(a.anchors, b.anchors);
        assert_eq!(a.offset, b.offset);
    }

    #[test]
    fn select_is_distinct_first_deterministic_and_bounded() {
        let big = Catalog {
            version: 1,
            strings: (0..20).map(|i| format!("m{i}")).collect(),
        };
        let s1 = select(&big, 9, 6);
        let s2 = select(&big, 9, 6);
        assert_eq!(s1, s2, "same seed is deterministic");
        assert_eq!(
            s1.len(),
            6,
            "catalog larger than count yields exactly count"
        );
        let uniq: std::collections::HashSet<&String> = s1.iter().collect();
        assert_eq!(
            uniq.len(),
            6,
            "selection is distinct, never drawn with replacement"
        );
        assert!(s1.iter().all(|x| big.strings.contains(x)));

        let tiny = Catalog {
            version: 1,
            strings: vec!["a".into(), "b".into(), "c".into()],
        };
        let t = select(&tiny, 9, 6);
        assert_eq!(t.len(), 3, "tiny catalog uses all available strings");
        let tu: std::collections::HashSet<&String> = t.iter().collect();
        assert_eq!(tu.len(), 3, "tiny selection is still distinct");
    }

    #[test]
    fn select_varies_across_seeds_and_is_not_constant() {
        let cat = Catalog {
            version: 1,
            strings: (0..30).map(|i| format!("meme{i}")).collect(),
        };
        let runs: Vec<Vec<String>> = (0..40u64).map(|s| select(&cat, s, 6)).collect();
        let distinct_runs: std::collections::HashSet<&Vec<String>> = runs.iter().collect();
        assert!(
            distinct_runs.len() > 20,
            "selection must vary across seeds, saw {} distinct of 40",
            distinct_runs.len()
        );
    }

    #[test]
    fn occurrence_counts_are_balanced_and_every_meme_recurs() {
        for seed in [1u64, 7, 42, 1337, 20261012] {
            let memes: Vec<String> = (0..6).map(|i| format!("sel{i}")).collect();
            let p = SurfacePlan {
                seed,
                theme: UnicodeTheme::None,
                memes,
                types: crate::types::TypeNoiseMode::Off,
            };
            let pv = preview(&p);
            assert!(
                (OCC_MIN..=OCC_MAX).contains(&pv.total),
                "seed {seed}: total {} out of range",
                pv.total
            );
            let counts: Vec<usize> = pv.counts.iter().map(|(_, c)| *c).collect();
            let min = *counts.iter().min().unwrap();
            let max = *counts.iter().max().unwrap();
            assert!(
                min >= 2,
                "seed {seed}: every selected meme must recur >=2, min {min}"
            );
            assert!(
                max - min <= 1,
                "seed {seed}: repetition must be balanced, spread {min}..{max}"
            );
        }
    }

    #[test]
    fn meme_text_does_not_perturb_structure() {
        let seed = 20261012;
        let mk = |memes: Vec<String>| SurfacePlan {
            seed,
            theme: UnicodeTheme::None,
            memes,
            types: crate::types::TypeNoiseMode::Off,
        };
        let a = preview(&mk(vec!["a".into(), "bb".into(), "ccc".into()]));
        let b = preview(&mk(vec!["ZZZZZZZZ".into(), "y".into(), "wwww".into()]));
        assert_eq!(
            a.total, b.total,
            "occurrence total must not depend on meme text or length"
        );
        assert_eq!(
            a.slots, b.slots,
            "carrier placement must not depend on meme text or length"
        );

        let ea = emission(&mk(vec!["aaaa".into(), "bbbb".into(), "cccc".into()]));
        let eb = emission(&mk(vec!["wxyz".into(), "1234".into(), "QRST".into()]));
        assert_eq!(ea.anchors.len(), eb.anchors.len());
        let shapes = |em: &Emission| -> Vec<String> {
            let j = format!("{}\n{}", em.preamble, em.anchors.join("\n"));
            j.lines()
                .filter(|l| is_carrier_line(l))
                .map(|l| {
                    let start = l.find("- #\"").unwrap();
                    let open = l[start..].find('"').map(|x| start + x).unwrap();
                    let close = l[open + 1..].find('"').map(|x| open + 1 + x).unwrap();
                    format!("{}@{}", &l[..start], &l[close + 1..])
                })
                .collect()
        };
        assert_eq!(
            shapes(&ea),
            shapes(&eb),
            "expression shapes/constants must be text-independent"
        );
    }

    #[test]
    fn preview_counts_match_emission_sites() {
        let memes: Vec<String> = vec![
            "alpha".into(),
            "beta".into(),
            "gamma".into(),
            "delta".into(),
        ];
        let p = dist_plan(memes.clone(), UnicodeTheme::None);
        let pv = preview(&p);
        let em = emission(&p);
        let joined = format!("{}\n{}", em.preamble, em.anchors.join("\n"));
        let measured: usize = memes
            .iter()
            .map(|m| joined.matches(&format!("#{}", luau_str(m))).count())
            .sum();
        assert_eq!(
            pv.total, measured,
            "preview total must equal real emission sites"
        );
        assert_eq!(
            pv.slots.len(),
            ANCHOR_COUNT + 1,
            "preview reports every carrier slot"
        );
        assert_eq!(
            pv.slots.iter().sum::<usize>(),
            pv.total,
            "slot counts must sum to the total"
        );
    }

    #[test]
    fn audit_reports_catalog_stats() {
        let a = audit("version = 1\nstrings = [\"ab\", \"ab\", \"\u{4e2d}\u{6587}\", \"ccccc\"]")
            .unwrap();
        assert_eq!(a.entries, 4);
        assert_eq!(a.unique, 3);
        assert_eq!(a.duplicates, 1);
        assert_eq!(a.shortest, 2);
        assert_eq!(a.longest, 6);
        assert_eq!(a.non_ascii, 1);
        assert_eq!(a.invalid, 0);
    }

    #[test]
    fn from_strings_dedupes_first_seen_and_preserves_order() {
        let cat =
            from_strings(&["beta".into(), "alpha".into(), "beta".into(), "gamma".into()]).unwrap();
        assert_eq!(cat.strings, vec!["beta", "alpha", "gamma"]);
    }

    #[test]
    fn from_strings_enforces_limits_and_control_bytes() {
        assert!(from_strings(&["".into()]).is_err());
        assert!(from_strings(&["x".repeat(MAX_STRING_BYTES + 1)]).is_err());
        assert!(from_strings(&["bad\u{0}".into()]).is_err());
        assert!(from_strings(&["line\nbreak".into()]).is_err());
        let too_many: Vec<String> = (0..=MAX_ENTRIES).map(|i| i.to_string()).collect();
        assert!(from_strings(&too_many).is_err());
        let over_total =
            vec!["x".repeat(MAX_STRING_BYTES); (MAX_TOTAL_BYTES / MAX_STRING_BYTES) + 2];
        assert!(from_strings(&over_total).is_err());
    }

    #[test]
    fn from_strings_allows_crude_profanity_and_tabs() {
        let cat = from_strings(&[
            "perth".into(),
            "u cant skid this bitch".into(),
            "a\tb".into(),
        ])
        .unwrap();
        assert_eq!(cat.strings.len(), 3);
    }

    #[test]
    fn to_toml_round_trips_through_parse() {
        let pool = vec![
            "perth".to_string(),
            "has \"quotes\" and \\slash".to_string(),
            "Jason Jackson Tanson".to_string(),
            "a\tb".to_string(),
        ];
        let cat = parse(&to_toml(&pool)).unwrap();
        assert_eq!(cat.strings, pool);
    }

    #[test]
    fn plan_pool_is_balanced_deterministic_and_bounded_by_sites() {
        for seed in [1u64, 7, 42, 1337, 20261018] {
            let memes: Vec<String> = (0..6).map(|i| format!("sel{i}")).collect();
            let p = SurfacePlan {
                seed,
                theme: UnicodeTheme::None,
                memes,
                types: crate::types::TypeNoiseMode::Off,
            };
            let pool = plan_pool(&p, 1000);
            assert!(
                (OCC_MIN..=OCC_MAX).contains(&pool.len()),
                "seed {seed}: pool {} out of range",
                pool.len()
            );
            assert_eq!(pool, plan_pool(&p, 1000), "same seed deterministic");
            let mut counts = std::collections::HashMap::new();
            for (lit, _len) in &pool {
                *counts.entry(lit.clone()).or_insert(0usize) += 1;
            }
            let min = *counts.values().min().unwrap();
            let max = *counts.values().max().unwrap();
            assert!(
                min >= 2 && max - min <= 1,
                "seed {seed}: balance {min}..{max}"
            );
            assert!(
                plan_pool(&p, 5).len() <= 5,
                "seed {seed}: pool bounded by max_sites"
            );
        }
    }

    #[test]
    fn wrap_expr_is_a_pure_expression_carrying_the_meme() {
        let lit = luau_str("some meme");
        for s in 0..24u64 {
            let mut rng = Rng::new(s);
            let e = wrap_expr("K", &lit, 9, &mut rng);
            assert!(
                e.contains("#\"some meme\""),
                "carrier must embed the meme length op: {e}"
            );
            assert!(
                e.contains('K'),
                "carrier must keep the original inner expression: {e}"
            );
            assert!(
                !e.contains('='),
                "carrier is an expression, never an assignment: {e}"
            );
        }
    }

    #[test]
    fn meme_ink_budgets_per_region_and_caps_each() {
        let memes: Vec<String> = (0..6).map(|i| format!("m{i}")).collect();
        let p = SurfacePlan {
            seed: 20261018,
            theme: UnicodeTheme::None,
            memes,
            types: crate::types::TypeNoiseMode::Off,
        };
        let mut ink = MemeInk::new(&p, 4).unwrap();
        ink.expect_sites("OpcodeMeta", 40);
        let mut per: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for _ in 0..40 {
            if let Some(e) = ink.wrap("OpcodeMeta", "K") {
                assert!(!e.contains('='), "woven carrier must be an expression: {e}");
                *per.entry("OpcodeMeta").or_default() += 1;
            }
        }
        for r in ["MaskSetup", "HashSetup", "EnvProbe", "Activation", "Paging"] {
            for _ in 0..4 {
                if ink.wrap(r, "K").is_some() {
                    *per.entry(r).or_default() += 1;
                }
            }
        }
        assert_eq!(
            per["OpcodeMeta"], 4,
            "a region is capped regardless of how many sites it offers"
        );
        assert!(
            ink.regions_used() >= 6,
            "the plan must span >= 6 regions, got {}",
            ink.regions_used()
        );
        let total: usize = per.values().sum();
        let max = *per.values().max().unwrap();
        assert!(max * 4 <= total, "no region may exceed 25% ({per:?})");
    }
}
