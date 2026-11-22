#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub token: String,
    pub count: usize,
    pub category: String,
}

pub const HARD_FAIL_MIN_LEN: usize = 6;

pub fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack.matches(needle).count()
}

pub fn scan(artifact: &str, forbidden: &[(&str, &str)]) -> Vec<Finding> {
    forbidden
        .iter()
        .filter_map(|(token, category)| {
            let count = count_occurrences(artifact, token);
            (count > 0).then(|| Finding {
                token: (*token).to_string(),
                count,
                category: (*category).to_string(),
            })
        })
        .collect()
}

pub fn hard<'a>(findings: &'a [Finding]) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.token.len() >= HARD_FAIL_MIN_LEN)
        .collect()
}

pub fn advisory<'a>(findings: &'a [Finding]) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.token.len() < HARD_FAIL_MIN_LEN)
        .collect()
}

pub fn report(artifact_path: &str, findings: &[Finding]) -> String {
    let mut out = format!("leak scan — {artifact_path}\n");
    if findings.is_empty() {
        out.push_str("  (none)\n");
        return out;
    }
    for f in findings {
        out.push_str(&format!(
            "  {:>4}x  [{}]  {}\n",
            f.count, f.category, f.token
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_forbidden_plaintext_with_category() {
        let hits = scan(
            "...validateWhitelistToken...",
            &[("validateWhitelistToken", "identifier")],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].count, 1);
        assert_eq!(hits[0].category, "identifier");
    }

    #[test]
    fn ignores_absent_tokens() {
        assert!(scan(
            "a clean release artifact",
            &[("secretUserId", "id"), ("/unlock", "url")]
        )
        .is_empty());
    }

    #[test]
    fn counts_multiple_non_overlapping_occurrences() {
        assert_eq!(count_occurrences("aaaa", "aa"), 2);
        assert_eq!(
            count_occurrences("bananamonkey bananamonkey", "bananamonkey"),
            2
        );
    }

    #[test]
    fn empty_needle_is_never_a_finding() {
        assert_eq!(count_occurrences("anything", ""), 0);
    }

    #[test]
    fn handles_large_high_entropy_artifact_safely() {
        let mut big = String::with_capacity(300_000);
        for i in 0..30_000u32 {
            big.push_str(&format!("NA[{}]=", i % 128));
        }
        big.push_str("bananamonkey");
        let hits = scan(
            &big,
            &[("bananamonkey", "password"), ("access granted", "string")],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].token, "bananamonkey");
    }

    #[test]
    fn hard_excludes_short_tokens_and_advisory_keeps_them() {
        let findings = scan(
            ".op present and validateWhitelistToken present",
            &[
                (".op", "internal"),
                ("validateWhitelistToken", "identifier"),
            ],
        );
        let hard = hard(&findings);
        let adv = advisory(&findings);
        assert_eq!(hard.len(), 1);
        assert_eq!(hard[0].token, "validateWhitelistToken");
        assert_eq!(adv.len(), 1);
        assert_eq!(adv[0].token, ".op");
    }

    #[test]
    fn report_lists_token_count_category_and_no_artifact_body() {
        let findings = scan(
            "secretUserId secretUserId",
            &[("secretUserId", "identifier")],
        );
        let text = report("/tmp/art.luau", &findings);
        assert!(text.contains("secretUserId"));
        assert!(text.contains("2x"));
        assert!(text.contains("identifier"));
        assert!(text.contains("/tmp/art.luau"));
        assert!(report("/tmp/art.luau", &[]).contains("(none)"));
    }
}
