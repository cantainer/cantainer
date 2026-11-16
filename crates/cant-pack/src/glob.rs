//! `[pack] exclude` patterns: `*` and `?` within one path component, `**` for any number of
//! components. Patterns and paths are relative to the can's root (a leading `/` is ignored).

fn component(pat: &[u8], s: &[u8]) -> bool {
    match (pat.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => component(&pat[1..], s) || (!s.is_empty() && component(pat, &s[1..])),
        (Some(b'?'), Some(_)) => component(&pat[1..], &s[1..]),
        (Some(p), Some(c)) if p == c => component(&pat[1..], &s[1..]),
        _ => false,
    }
}

fn parts(pat: &[&str], path: &[&str]) -> bool {
    match pat.first() {
        None => path.is_empty(),
        Some(&"**") => (0..=path.len()).any(|skip| parts(&pat[1..], &path[skip..])),
        Some(p) => {
            !path.is_empty()
                && component(p.as_bytes(), path[0].as_bytes())
                && parts(&pat[1..], &path[1..])
        }
    }
}

/// Whether `path` matches `pattern`.
pub fn matches(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.trim_start_matches('/').split('/').collect();
    let path: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    parts(&pat, &path)
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn globs() {
        assert!(matches("**/*.pyc", "usr/lib/python3/x.pyc"));
        assert!(matches("**/*.pyc", "x.pyc"));
        assert!(!matches("**/*.pyc", "usr/lib/x.py"));
        assert!(matches("**/__pycache__/**", "a/__pycache__/b/c"));
        assert!(matches("/usr/share/doc/**", "usr/share/doc/git/README"));
        assert!(!matches("usr/share/doc/*", "usr/share/doc/git/README"));
        assert!(matches(
            "usr/lib/git-core/git-?ui*",
            "usr/lib/git-core/git-gui--askpass"
        ));
    }
}
