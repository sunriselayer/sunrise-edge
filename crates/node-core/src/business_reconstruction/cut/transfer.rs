use super::*;
use execution::publication::encode_publication_context;
use std::ops::Bound::{Excluded, Included, Unbounded};

/// Non-circular context/genesis/domain/stream seed. No final cut digest enters
/// a business or artifact root. The package-wide seed uses kind 8 plus its cut.
pub(super) fn seed(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    genesis: Digest32,
    domain: AtomicityDomainId,
    kind: u16,
    cut: Option<Digest32>,
) -> Result<Digest32, BusinessCutError> {
    let mut value: CanonicalStruct = CanonicalStruct::new(0x64B6, 1);
    value.field_bytes(
        1,
        encode_publication_context(context).map_err(|_| invalid("cut seed context"))?,
    )?;
    value.field_bytes(2, encode_digest32(&genesis)?)?;
    value.field_bytes(3, domain.as_bytes().to_vec())?;
    value.field_u16(4, kind)?;
    value.field_bytes(
        5,
        cut.map(|digest| encode_digest32(&digest))
            .transpose()?
            .unwrap_or_default(),
    )?;
    hash(resolver, context, &value.finish()?)
}
pub(super) fn fold(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    previous: Digest32,
    descriptor: &BusinessCutComponentDescriptor,
) -> Result<Digest32, BusinessCutError> {
    let mut value: CanonicalStruct = CanonicalStruct::new(0x64B7, 1);
    value.field_bytes(1, encode_digest32(&previous)?)?;
    value.field_bytes(2, encode_business_cut_descriptor(descriptor)?)?;
    hash(resolver, context, &value.finish()?)
}
pub(super) fn roots(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    genesis: Digest32,
    domain: AtomicityDomainId,
    components: &BTreeMap<(BusinessCutCollection, Vec<u8>), SavedBusinessCutComponent>,
) -> Result<[BusinessCutCollectionRoot; 7], BusinessCutError> {
    let mut result: Vec<BusinessCutCollectionRoot> = Vec::with_capacity(7);
    for collection in BUSINESS_CUT_STREAMS {
        let mut accumulator: Digest32 =
            seed(resolver, context, genesis, domain, collection as u16, None)?;
        let mut count: u64 = 0;
        for ((stream, _), item) in components {
            if *stream != collection {
                continue;
            }
            accumulator = fold(resolver, context, accumulator, &item.descriptor)?;
            count = count
                .checked_add(1)
                .ok_or(invalid("cut stream count overflow"))?;
        }
        result.push(BusinessCutCollectionRoot {
            collection,
            count,
            root: accumulator,
        });
    }
    result
        .try_into()
        .map_err(|_| invalid("cut stream root count"))
}
pub(super) fn read_page(
    cut: &VerifiedBusinessCut,
    resolver: &HashSuiteResolver,
    collection: BusinessCutCollection,
    after_key: Option<&[u8]>,
    limit: NonZeroUsize,
) -> Result<BusinessCutPage, BusinessCutError> {
    if limit.get() > MAX_BUSINESS_CUT_PAGE_ENTRIES {
        return Err(invalid("cut page entry capacity"));
    }
    let mut accumulator: Digest32 = seed(
        resolver,
        &cut.identity.context,
        cut.identity.genesis_digest,
        cut.identity.domain,
        collection as u16,
        None,
    )?;
    let lower = if let Some(cursor) = after_key {
        let key: (BusinessCutCollection, Vec<u8>) = (collection, cursor.to_vec());
        accumulator = *cut
            .prefix_accumulators
            .get(&key)
            .ok_or(invalid("cut page cursor is not an exact component key"))?;
        Excluded(key)
    } else {
        Included((collection, Vec::new()))
    };
    let previous: Digest32 = accumulator;
    let mut descriptors: Vec<BusinessCutComponentDescriptor> = Vec::new();
    let mut terminal: bool = true;
    for ((stream, _), item) in cut.components.range((lower, Unbounded)) {
        if *stream != collection {
            break;
        }
        if descriptors.len() == limit.get() {
            terminal = false;
            break;
        }
        accumulator = fold(
            resolver,
            &cut.identity.context,
            accumulator,
            &item.descriptor,
        )?;
        descriptors.push(item.descriptor.clone());
    }
    let page: BusinessCutPage = BusinessCutPage {
        cut_digest: cut.cut_digest,
        package_digest: cut.package_digest,
        collection,
        after_key: after_key.map(<[u8]>::to_vec),
        previous_accumulator: previous,
        descriptors,
        accumulator,
        terminal,
    };
    encode_business_cut_page(&page)?;
    Ok(page)
}
pub(super) fn read_chunk(
    cut: &VerifiedBusinessCut,
    descriptor: &BusinessCutComponentDescriptor,
    offset: u64,
    limit: NonZeroUsize,
) -> Result<BusinessCutChunk, BusinessCutError> {
    if limit.get() > MAX_BUSINESS_CUT_CHUNK_BYTES {
        return Err(invalid("cut chunk byte capacity"));
    }
    encode_business_cut_descriptor(descriptor)?;
    let item: &SavedBusinessCutComponent = cut
        .components
        .get(&(descriptor.collection, descriptor.key.clone()))
        .ok_or(invalid("cut chunk component is absent"))?;
    if &item.descriptor != descriptor
        || offset > descriptor.length
        || (offset == descriptor.length && descriptor.length != 0)
    {
        return Err(invalid("cut chunk descriptor/range differs"));
    }
    let start: usize = usize::try_from(offset).map_err(|_| invalid("cut chunk offset capacity"))?;
    let count: usize = limit.get().min(item.bytes.len() - start);
    let end: usize = start
        .checked_add(count)
        .ok_or(invalid("cut chunk range overflow"))?;
    let result: BusinessCutChunk = BusinessCutChunk {
        cut_digest: cut.cut_digest,
        package_digest: cut.package_digest,
        descriptor: descriptor.clone(),
        offset,
        total_length: descriptor.length,
        bytes: item.bytes[start..end].to_vec(),
    };
    encode_business_cut_chunk(&result)?;
    Ok(result)
}

/// Transfer completeness against supplied root claims only. A successful
/// finish is NOT a verified cut: `verify_saved_business_cut` must replay again.
pub struct BusinessCutPageVerifier {
    identity: BusinessCutIdentity,
    cut_digest: Digest32,
    package_digest: Digest32,
    expected: BusinessCutCollectionRoot,
    accumulator: Digest32,
    last_key: Option<Vec<u8>>,
    count: u64,
    terminal: bool,
}
impl BusinessCutPageVerifier {
    pub fn new(
        resolver: &HashSuiteResolver,
        identity: &BusinessCutIdentity,
        package: &BusinessCutPackageIdentity,
        collection: BusinessCutCollection,
    ) -> Result<Self, BusinessCutError> {
        let cut_digest: Digest32 = business_cut_identity_digest(resolver, identity)?;
        let package_digest: Digest32 = business_cut_package_digest(resolver, identity, package)?;
        let expected: BusinessCutCollectionRoot =
            package.streams[usize::from(collection as u16) - 1].clone();
        if expected.collection != collection {
            return Err(invalid("cut page expected stream"));
        }
        Ok(Self {
            identity: identity.clone(),
            cut_digest,
            package_digest,
            expected,
            accumulator: seed(
                resolver,
                &identity.context,
                identity.genesis_digest,
                identity.domain,
                collection as u16,
                None,
            )?,
            last_key: None,
            count: 0,
            terminal: false,
        })
    }
    /// Rejected pages leave all continuation state unchanged.
    pub fn push_page(
        &mut self,
        resolver: &HashSuiteResolver,
        page: &BusinessCutPage,
    ) -> Result<(), BusinessCutError> {
        encode_business_cut_page(page)?;
        if self.terminal
            || page.cut_digest != self.cut_digest
            || page.package_digest != self.package_digest
            || page.collection != self.expected.collection
            || page.after_key != self.last_key
            || page.previous_accumulator != self.accumulator
        {
            return Err(invalid("cut page identity/cursor/accumulator differs"));
        }
        let mut accumulator: Digest32 = self.accumulator;
        let mut count: u64 = self.count;
        let mut last_key: Option<Vec<u8>> = self.last_key.clone();
        for descriptor in &page.descriptors {
            accumulator = fold(resolver, &self.identity.context, accumulator, descriptor)?;
            count = count
                .checked_add(1)
                .ok_or(invalid("cut page count overflow"))?;
            last_key = Some(descriptor.key.clone());
        }
        if accumulator != page.accumulator
            || count > self.expected.count
            || (page.terminal
                && (count != self.expected.count || accumulator != self.expected.root))
        {
            return Err(invalid("cut page does not reproduce exact terminal stream"));
        }
        self.accumulator = accumulator;
        self.count = count;
        self.last_key = last_key;
        self.terminal = page.terminal;
        Ok(())
    }
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }
    pub fn finish(self) -> Result<(), BusinessCutError> {
        if !self.terminal {
            return Err(invalid("cut stream has no verified terminal page"));
        }
        Ok(())
    }
}
