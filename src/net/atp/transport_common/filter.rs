//! Include/exclude/filter rules for selective sync (rsync / gitignore-style).
//!
//! A [`FilterSet`] is an ordered list of include/exclude [`FilterRule`]s. For a
//! given path the **first** matching rule decides; if no rule matches the path
//! is included (rsync's default). This makes precedence explicit and
//! deterministic — earlier rules win, so an `include` placed before a broad
//! `exclude` rescues a needed path.
//!
//! Pattern semantics (a documented gitignore-style subset):
//!
//! - A **trailing `/`** makes the rule match directories only (`target/`).
//! - A **leading `/`** or an **internal `/`** anchors the pattern to the
//!   transfer root, matching the whole relative path (`/build`, `src/gen/*.rs`).
//! - A pattern with **no `/`** matches the final path component at any depth
//!   (`*.tmp` matches `a/b/c.tmp`; `target` matches `x/target`).
//! - `*` matches any run of non-`/` characters; `?` matches one non-`/`
//!   character; `**` matches any run including `/`, and `**/` matches zero or
//!   more leading directory segments (`src/**/*.rs`).
//!
//! Subtree exclusion is the walker's job: when a *directory* is excluded the
//! walk does not descend into it, so its contents never reach
//! [`FilterSet::decision`]. This module is the transport-agnostic matching core;
//! wiring it into the source walk / receiver apply is the consumer's part.

/// Whether a [`FilterRule`] includes or excludes the paths it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    /// Matching paths are kept.
    Include,
    /// Matching paths are skipped.
    Exclude,
}

/// The decision a [`FilterSet`] reaches for a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    /// The path is transferred.
    Include,
    /// The path is skipped (and, if a directory, not descended into).
    Exclude,
}

/// A parse error for a filter rule line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    /// A rule line had no pattern after its `+`/`-` action.
    #[error("filter rule has an empty pattern: {0:?}")]
    EmptyPattern(String),
    /// A rule line did not start with a recognized action (`+`, `-`).
    #[error("filter rule must start with '+' or '-': {0:?}")]
    UnknownAction(String),
}

/// One include/exclude rule with a compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRule {
    action: FilterAction,
    /// Pattern body without the leading/trailing `/` markers.
    pattern: String,
    /// Anchored to the transfer root (matches the whole rel-path).
    anchored: bool,
    /// Matches directories only (had a trailing `/`).
    dir_only: bool,
}

impl FilterRule {
    /// Build an include rule from a pattern.
    #[must_use]
    pub fn include(pattern: &str) -> Self {
        Self::compile(FilterAction::Include, pattern)
    }

    /// Build an exclude rule from a pattern.
    #[must_use]
    pub fn exclude(pattern: &str) -> Self {
        Self::compile(FilterAction::Exclude, pattern)
    }

    fn compile(action: FilterAction, raw: &str) -> Self {
        let dir_only = raw.ends_with('/');
        let trimmed = raw.trim_end_matches('/');
        // A leading or internal '/' anchors the pattern to the root.
        let anchored = trimmed.starts_with('/') || trimmed.contains('/');
        let pattern = trimmed.trim_start_matches('/').to_string();
        Self {
            action,
            pattern,
            anchored,
            dir_only,
        }
    }

    /// The rule's action.
    #[must_use]
    pub fn action(&self) -> FilterAction {
        self.action
    }

    /// Whether this rule matches `rel_path` (a forward-slash relative path).
    #[must_use]
    pub fn matches(&self, rel_path: &str, is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }
        let target = if self.anchored {
            rel_path.trim_start_matches('/')
        } else {
            basename(rel_path)
        };
        glob_match(self.pattern.as_bytes(), target.as_bytes())
    }
}

/// An ordered set of filter rules; the first matching rule decides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterSet {
    rules: Vec<FilterRule>,
}

impl FilterSet {
    /// An empty filter set (includes everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a set from an ordered list of rules.
    #[must_use]
    pub fn with_rules(rules: Vec<FilterRule>) -> Self {
        Self { rules }
    }

    /// Append a rule (lower precedence than existing rules).
    pub fn push(&mut self, rule: FilterRule) {
        self.rules.push(rule);
    }

    /// Parse rsync-style rule lines: `+ pattern` (include) / `- pattern`
    /// (exclude). Blank lines and `#` comments are ignored. Rule order is
    /// preserved (first match wins).
    pub fn parse<'a, I>(lines: I) -> Result<Self, FilterError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut rules = Vec::new();
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Char-based (not byte split_at) so a non-ASCII first char can't panic.
            let mut chars = trimmed.chars();
            let action = match chars.next() {
                Some('+') => FilterAction::Include,
                Some('-') => FilterAction::Exclude,
                _ => return Err(FilterError::UnknownAction(trimmed.to_string())),
            };
            let pattern = chars.as_str().trim();
            if pattern.is_empty() {
                return Err(FilterError::EmptyPattern(trimmed.to_string()));
            }
            rules.push(FilterRule::compile(action, pattern));
        }
        Ok(Self { rules })
    }

    /// Number of rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the set has no rules (includes everything).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Decide whether `rel_path` is included. First matching rule wins; with no
    /// match the path is included.
    #[must_use]
    pub fn decision(&self, rel_path: &str, is_dir: bool) -> FilterDecision {
        for rule in &self.rules {
            if rule.matches(rel_path, is_dir) {
                return match rule.action {
                    FilterAction::Include => FilterDecision::Include,
                    FilterAction::Exclude => FilterDecision::Exclude,
                };
            }
        }
        FilterDecision::Include
    }

    /// Convenience: `true` if `rel_path` is included.
    #[must_use]
    pub fn is_included(&self, rel_path: &str, is_dir: bool) -> bool {
        matches!(self.decision(rel_path, is_dir), FilterDecision::Include)
    }

    /// Whether a *file* at `rel_path` survives filtering, accounting for
    /// directory pruning: the file is excluded if it, or any of its ancestor
    /// directories, is excluded.
    ///
    /// Use this to filter a file-only source walk (where directories are not
    /// separate entries) — it yields the same result as walking with [`Self::select`]
    /// without needing directory entries. Rescuing a file under an excluded tree
    /// still requires including its ancestor directories first (rsync semantics).
    #[must_use]
    pub fn is_path_included(&self, rel_path: &str) -> bool {
        let segments: Vec<&str> = rel_path.split('/').filter(|s| !s.is_empty()).collect();
        let mut prefix = String::new();
        for (i, seg) in segments.iter().enumerate() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(seg);
            // Ancestor components are directories; the final component is the file.
            let is_dir = i + 1 < segments.len();
            if matches!(self.decision(&prefix, is_dir), FilterDecision::Exclude) {
                return false;
            }
        }
        true
    }

    /// Apply the filter to a set of entries with directory pruning, returning the
    /// transferred rel-paths in input order.
    ///
    /// `entries` must be ordered so a directory precedes its descendants (a
    /// normal top-down walk order). An excluded directory prunes its whole
    /// subtree: descendants of an excluded dir are dropped even if they would
    /// individually be included. This mirrors what a streaming walk does.
    #[must_use]
    pub fn select(&self, entries: &[(String, bool)]) -> Vec<String> {
        let mut out = Vec::new();
        let mut pruned: Vec<String> = Vec::new();
        for (rel, is_dir) in entries {
            // Drop anything under an already-pruned directory.
            if pruned.iter().any(|p| is_under(rel, p)) {
                continue;
            }
            match self.decision(rel, *is_dir) {
                FilterDecision::Include => out.push(rel.clone()),
                FilterDecision::Exclude => {
                    if *is_dir {
                        pruned.push(rel.clone());
                    }
                }
            }
        }
        out
    }
}

/// The final path component (after the last `/`).
fn basename(rel_path: &str) -> &str {
    match rel_path.rsplit_once('/') {
        Some((_, name)) => name,
        None => rel_path,
    }
}

/// Whether `path` is the directory `dir` itself or lies beneath it.
fn is_under(path: &str, dir: &str) -> bool {
    path == dir
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Glob match: `*` = any run of non-`/`, `?` = one non-`/`, `**` = any run
/// including `/`, `**/` = zero or more leading directory segments.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.first() {
        None => text.is_empty(),
        Some(b'*') if pattern.get(1) == Some(&b'*') => {
            // "**/" matches zero or more leading directory segments.
            if pattern.get(2) == Some(&b'/') {
                let rest = &pattern[3..];
                if glob_match(rest, text) {
                    return true;
                }
                for (i, &c) in text.iter().enumerate() {
                    if c == b'/' && glob_match(pattern, &text[i + 1..]) {
                        return true;
                    }
                }
                false
            } else {
                // bare "**": consume any run including '/'.
                let rest = &pattern[2..];
                (0..=text.len()).any(|i| glob_match(rest, &text[i..]))
            }
        }
        Some(b'*') => {
            // "*": consume zero or more non-'/' characters.
            let rest = &pattern[1..];
            let mut i = 0;
            loop {
                if glob_match(rest, &text[i..]) {
                    return true;
                }
                if i < text.len() && text[i] != b'/' {
                    i += 1;
                } else {
                    return false;
                }
            }
        }
        Some(b'?') => !text.is_empty() && text[0] != b'/' && glob_match(&pattern[1..], &text[1..]),
        Some(&c) => !text.is_empty() && text[0] == c && glob_match(&pattern[1..], &text[1..]),
    }
}

#[cfg(test)]
#[path = "filter_inline_tests.rs"]
mod tests;
