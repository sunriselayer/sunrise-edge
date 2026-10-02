//! Counted immutable publication port. Every preparation-side `put_blob`
//! call is visible, including overwrite attempts, by wrapping the one real
//! [`MemoryBlobStore`] an operation's prepare path actually uses. Shared by
//! fee, bond lifecycle, slash and registration preparation tests.

use protocol_types::Digest32;
use runtime::{BlobStore, MemoryBlobStore, RuntimeError};
use std::cell::Cell;

pub(crate) struct CountedBlobs<'a> {
    inner: &'a MemoryBlobStore,
    puts: Cell<usize>,
}

impl<'a> CountedBlobs<'a> {
    pub(crate) fn new(inner: &'a MemoryBlobStore) -> Self {
        Self {
            inner,
            puts: Cell::new(0),
        }
    }

    pub(crate) fn put_count(&self) -> usize {
        self.puts.get()
    }
}

impl BlobStore for CountedBlobs<'_> {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.puts.set(self.puts.get() + 1);
        self.inner.put_blob(digest, bytes)
    }

    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.inner.get_blob(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::HashAlgorithmId;

    #[test]
    fn counted_blob_port_observes_identical_and_conflicting_overwrite_attempts() {
        let inner: MemoryBlobStore = MemoryBlobStore::default();
        let blobs: CountedBlobs<'_> = CountedBlobs::new(&inner);
        let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x91; 32]);
        blobs.put_blob(digest, vec![0x92]).unwrap();
        blobs.put_blob(digest, vec![0x92]).unwrap();
        assert_eq!(
            blobs.put_blob(digest, vec![0x93]),
            Err(RuntimeError::BlobDigestConflict { digest })
        );
        assert_eq!(blobs.put_count(), 3);
        assert_eq!(blobs.get_blob(&digest).unwrap(), Some(vec![0x92]));
        assert_eq!(blobs.put_count(), 3);
    }
}
