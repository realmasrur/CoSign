//! Hash-chained audit log. Each entry commits to the previous one, so editing,
//! deleting or reordering any entry breaks `verify`. Truncating the TAIL is only
//! detectable against a `head()` anchored outside CoSign (WORM store, other chain).

use crate::keccak::keccak256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub ts: u64,
    pub prev: [u8; 32],
    pub detail: String,
    pub hash: [u8; 32],
}

#[derive(Debug)]
pub struct SinkError;

/// Durable, append-only storage (WORM bucket, append-only DB role, etc).
pub trait Sink {
    fn append(&mut self, e: &Entry) -> Result<(), SinkError>;
}

/// In-memory sink for tests and local runs only.
impl Sink for Vec<Entry> {
    fn append(&mut self, e: &Entry) -> Result<(), SinkError> {
        self.push(e.clone());
        Ok(())
    }
}

pub struct Log<S: Sink> {
    sink: S,
    seq: u64,
    head: [u8; 32],
}

fn link(seq: u64, ts: u64, prev: &[u8; 32], detail: &str) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend(seq.to_be_bytes());
    b.extend(ts.to_be_bytes());
    b.extend(prev);
    b.extend(detail.as_bytes());
    keccak256(&b)
}

pub fn hex32(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{:02x}", b)).collect()
}

impl<S: Sink> Log<S> {
    pub fn new(sink: S) -> Self {
        Self { sink, seq: 0, head: [0; 32] }
    }

    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Fails without advancing the chain if the sink cannot persist the entry.
    pub fn append(&mut self, ts: u64, detail: String) -> Result<[u8; 32], SinkError> {
        let hash = link(self.seq, ts, &self.head, &detail);
        let e = Entry { seq: self.seq, ts, prev: self.head, detail, hash };
        self.sink.append(&e)?;
        self.seq += 1;
        self.head = hash;
        Ok(hash)
    }
}

pub fn verify(entries: &[Entry]) -> bool {
    let mut prev = [0u8; 32];
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 || e.prev != prev || e.hash != link(e.seq, e.ts, &e.prev, &e.detail) {
            return false;
        }
        prev = e.hash;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_edit_delete_and_reorder() {
        let mut l = Log::new(Vec::new());
        for i in 0..3 {
            l.append(i, format!("e{i}")).unwrap();
        }
        let e = l.sink().clone();
        assert!(verify(&e));
        assert_eq!(l.head(), e[2].hash);

        let mut edited = e.clone();
        edited[1].detail = "x".into();
        assert!(!verify(&edited));

        let mut deleted = e.clone();
        deleted.remove(1);
        assert!(!verify(&deleted));

        let mut reordered = e.clone();
        reordered.swap(0, 1);
        assert!(!verify(&reordered));
    }

    #[test]
    fn sink_failure_does_not_advance_the_chain() {
        struct Fail;
        impl Sink for Fail {
            fn append(&mut self, _: &Entry) -> Result<(), SinkError> {
                Err(SinkError)
            }
        }
        let mut l = Log::new(Fail);
        assert!(l.append(0, "a".into()).is_err());
        assert_eq!(l.head(), [0; 32]);
    }
}
