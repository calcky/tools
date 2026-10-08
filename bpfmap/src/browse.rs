use anyhow::{bail, Result};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Query {
    #[default]
    All,
    Text(String),
    Key(Vec<u8>),
}

impl Query {
    pub fn label(&self) -> String {
        match self {
            Self::All => "all entries".into(),
            Self::Text(text) => format!("search: {text}"),
            Self::Key(key) => format!("key: {}", crate::kernel::hex(key)),
        }
    }

    pub fn matches(&self, key: &str, value: &str) -> bool {
        match self {
            Self::Text(text) => {
                key.to_lowercase().contains(text) || value.to_lowercase().contains(text)
            }
            _ => true,
        }
    }
}

#[derive(Clone, Copy)]
pub enum InputKind {
    Search,
    Key,
}

pub struct Input {
    pub kind: InputKind,
    pub text: String,
    pub error: Option<String>,
}

impl Input {
    pub fn label(&self) -> &'static str {
        match self.kind {
            InputKind::Search => "Search key/value",
            InputKind::Key => "Key hex bytes",
        }
    }

    pub fn query(&self, key_size: usize) -> Result<Query> {
        match self.kind {
            InputKind::Search => {
                let text = self.text.trim().to_lowercase();
                Ok(if text.is_empty() {
                    Query::All
                } else {
                    Query::Text(text)
                })
            }
            InputKind::Key => Ok(Query::Key(parse_key(&self.text, key_size)?)),
        }
    }
}

pub fn parse_key(text: &str, size: usize) -> Result<Vec<u8>> {
    let text = text.trim().strip_prefix("0x").unwrap_or(text.trim());
    let bytes = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if bytes.len() != size * 2 || size == 0 || size > 4096 {
        bail!("Expected exactly {size} bytes, written as hex pairs in kernel memory order");
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| (byte as char).to_digit(16).map(|number| number as u8);
            match (digit(pair[0]), digit(pair[1])) {
                (Some(high), Some(low)) => Ok((high << 4) | low),
                _ => anyhow::bail!("Key contains a non-hex byte"),
            }
        })
        .collect()
}

#[derive(Default)]
pub struct State {
    pub query: Query,
    pub anchor: Option<Vec<u8>>,
    pub pages: Vec<Option<Vec<u8>>>,
    pub generation: u64,
    pub pending: bool,
    pub loading: bool,
    pub counter_mode: bool,
    pub input: Option<Input>,
    pub scanned: usize,
    pub search_started: Option<Instant>,
    pub continuing: bool,
}

impl State {
    pub fn set_query(&mut self, query: Query) {
        self.query = query;
        self.anchor = None;
        self.pages.clear();
        self.scanned = 0;
        self.continuing = false;
        self.search_started = Some(Instant::now());
        self.invalidate();
    }

    pub fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.pending = true;
        self.loading = false;
    }

    pub fn next(&mut self, key: Option<&[u8]>) -> bool {
        if matches!(self.query, Query::Key(_)) || self.pages.len() >= 4096 {
            return false;
        }
        let Some(key) = key else {
            return false;
        };
        self.pages.push(self.anchor.take());
        self.anchor = Some(key.to_vec());
        self.scanned = 0;
        self.continuing = false;
        self.search_started = Some(Instant::now());
        self.invalidate();
        true
    }

    pub fn previous(&mut self) -> bool {
        let Some(anchor) = self.pages.pop() else {
            return false;
        };
        self.anchor = anchor;
        self.scanned = 0;
        self.continuing = false;
        self.search_started = Some(Instant::now());
        self.invalidate();
        true
    }

    pub fn page(&self) -> usize {
        self.pages.len() + 1
    }

    pub fn continue_search(&mut self, preview: &crate::kernel::Preview) -> bool {
        self.scanned = if self.continuing {
            self.scanned.saturating_add(preview.scanned)
        } else {
            preview.scanned
        };
        if matches!(self.query, Query::Text(_))
            && preview.entries.is_empty()
            && preview.partial
            && preview.next_key.is_some()
            && self.scanned < 65536
            && self
                .search_started
                .is_some_and(|time| time.elapsed() < Duration::from_secs(2))
        {
            self.anchor = preview.next_key.clone();
            self.pending = true;
            self.continuing = true;
            true
        } else {
            self.continuing = false;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_keys_have_explicit_length_and_memory_order() {
        assert_eq!(parse_key("0x01 00 00 00", 4).unwrap(), [1, 0, 0, 0]);
        assert_eq!(parse_key("abCd", 2).unwrap(), [0xab, 0xcd]);
        for text in ["1", "gg000000", "01 00", "01 00 00 00 00"] {
            assert!(parse_key(text, 4).is_err());
        }
    }

    #[test]
    fn filtering_matches_fields_and_query_changes_reset_paging() {
        let input = Input {
            kind: InputKind::Search,
            text: "  MTU ".into(),
            error: None,
        };
        let query = input.query(4).unwrap();
        assert!(query.matches("key", "{max_inner_mtu = 1480}"));
        assert!(!query.matches("key", "generation = 2"));
        let mut state = State::default();
        assert!(state.next(Some(&[7])));
        assert!(state.next(Some(&[8])));
        assert_eq!(state.page(), 3);
        assert!(state.previous());
        assert_eq!(state.anchor, Some(vec![7]));
        let generation = state.generation;
        state.set_query(query);
        assert_eq!(state.page(), 1);
        assert_eq!(state.anchor, None);
        assert!(state.generation != generation && state.pending);
        state.set_query(Query::Key(vec![1, 0, 0, 0]));
        assert!(!state.next(Some(&[8])));
    }

    #[test]
    fn automatic_search_is_bounded_and_normal_refresh_does_not_accumulate() {
        let mut state = State::default();
        state.set_query(Query::Text("missing".into()));
        let partial = crate::kernel::Preview {
            scanned: 4096,
            partial: true,
            next_key: Some(vec![7]),
            ..Default::default()
        };
        for _ in 0..15 {
            assert!(state.continue_search(&partial));
        }
        assert!(!state.continue_search(&partial));
        assert_eq!(state.scanned, 65536);
        assert_eq!(state.anchor, Some(vec![7]));
        state.set_query(Query::Text("missing".into()));
        state.search_started = Some(Instant::now() - Duration::from_secs(3));
        assert!(!state.continue_search(&partial));
        assert_eq!(state.scanned, 4096);
        let complete = crate::kernel::Preview {
            scanned: 2,
            ..Default::default()
        };
        assert!(!state.continue_search(&complete));
        assert!(!state.continue_search(&complete));
        assert_eq!(state.scanned, 2);
        state.set_query(Query::All);
        assert!(!state.continue_search(&partial));
    }
}
