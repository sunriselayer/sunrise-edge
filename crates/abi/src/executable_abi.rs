//! Signed executable metadata, distinct from historical CallAbi version one.
use crate::call_values::{CallAbi, ValueError, decode_call_abi, encode_call_abi};
use crate::public_abi::{self, ObjectResultDeclaration};
use canonical_encoding::{CanonicalFrame, CanonicalStruct, decode_canonical_frame};

/// Outer wrapper bound; the inner CallAbi budget subtracts actual wrapper metadata.
pub const MAX_EXECUTABLE_ABI_BYTES: usize = 64 * 1024;

/// Closed typed-host metadata over an unchanged canonical CallAbi.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutableAbi {
    /// Exact argument/object/body declarations.
    pub call: CallAbi,
    /// Exact initializer, or None for a dependency library.
    pub initializer: Option<String>,
    /// Strictly sorted package-local constructors permitting owner transfer.
    pub transferable_constructors: Vec<u16>,
    /// Positional ordered typed object result slots for each entrypoint
    /// (DR-0124), aligned with `call.objects.entrypoints`. An empty vector
    /// for every entrypoint preserves historical version-one bytes exactly.
    pub results: Vec<Vec<ObjectResultDeclaration>>,
}
impl ExecutableAbi {
    /// Validates role and permission references without granting host authority.
    pub fn validate(&self) -> Result<(), ValueError> {
        if let Some(name) = &self.initializer {
            // Preserve UTF-8 export names while respecting the call name bound.
            if name.is_empty() || name.len() > 64 {
                return Err(ValueError::Invalid("initializer name profile"));
            }
            let entry = self
                .call
                .objects
                .entrypoints
                .iter()
                .find(|entry| &entry.name == name)
                .ok_or(ValueError::Invalid("initializer must name an entrypoint"))?;
            if !entry.objects.is_empty() || !entry.type_parameters.is_empty() {
                return Err(ValueError::Invalid(
                    "initializer cannot require objects or type parameters",
                ));
            }
        }
        if self.transferable_constructors.len() > 64
            || self
                .transferable_constructors
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ValueError::Invalid(
                "transfer constructors must be sorted unique",
            ));
        }
        for id in &self.transferable_constructors {
            if !self
                .call
                .objects
                .constructors
                .iter()
                .any(|constructor| constructor.local_id == *id)
            {
                return Err(ValueError::Invalid("unknown transfer constructor"));
            }
        }
        if self.results.len() != self.call.objects.entrypoints.len() {
            return Err(ValueError::Invalid(
                "object result declarations must align with every entrypoint",
            ));
        }
        let mut node_count: usize = 0;
        for (entry, results) in self.call.objects.entrypoints.iter().zip(&self.results) {
            public_abi::validate_object_result_shape(
                results,
                self.call.objects.origin.chain_id(),
                entry.type_parameters.len(),
                &mut node_count,
            )
            .map_err(ValueError::Abi)?;
        }
        Ok(())
    }
}
/// Encodes executable wrapper 0x5406/v1; never aliases historical CallAbi bytes.
/// Adds field 4 under version 2 exactly when any entrypoint declares a
/// nonempty typed object result list; an all-empty `results` preserves the
/// exact historical version-one bytes (DR-0124).
pub fn encode_executable_abi(abi: &ExecutableAbi) -> Result<Vec<u8>, ValueError> {
    abi.validate()?;
    let call_bytes: Vec<u8> = encode_call_abi(&abi.call)?;
    let has_results: bool = abi.results.iter().any(|slots| !slots.is_empty());
    let mut results_bytes: Vec<Vec<u8>> = Vec::new();
    if has_results {
        for slots in &abi.results {
            results_bytes
                .push(public_abi::encode_object_result_list(slots).map_err(ValueError::Abi)?);
        }
    }
    let field_count: usize = if has_results { 4 } else { 3 };
    let results_overhead: usize = results_bytes
        .iter()
        .try_fold(0usize, |total, item| total.checked_add(item.len()))
        .ok_or(ValueError::Limit("object result bytes exceed maximum"))?;
    let overhead: usize = 10
        + field_count * 6
        + abi.initializer.as_deref().map_or(0, str::len)
        + 2
        + 2 * abi.transferable_constructors.len()
        + results_overhead;
    if call_bytes
        .len()
        .checked_add(overhead)
        .is_none_or(|total| total > MAX_EXECUTABLE_ABI_BYTES)
    {
        return Err(ValueError::Limit("inner CallAbi exceeds wrapper budget"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x5406, if has_results { 2 } else { 1 });
    frame.field_bytes(1, call_bytes)?;
    frame.field_str(2, abi.initializer.as_deref().unwrap_or(""))?;
    let mut ids: Vec<u8> = Vec::with_capacity(2 + 2 * abi.transferable_constructors.len());
    ids.extend_from_slice(&(abi.transferable_constructors.len() as u16).to_le_bytes());
    for id in &abi.transferable_constructors {
        ids.extend_from_slice(&id.to_le_bytes());
    }
    frame.field_bytes(3, ids)?;
    if has_results {
        if results_bytes.len() > public_abi::MAX_ABI_ENTRYPOINTS {
            return Err(ValueError::Limit("object result entrypoint count"));
        }
        let outer: Vec<u8> = encode_ordered_byte_list(&results_bytes)?;
        frame.field_bytes(4, outer)?;
    }
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_EXECUTABLE_ABI_BYTES {
        return Err(ValueError::Limit("executable ABI bytes"));
    }
    Ok(bytes)
}

const RESULT_LISTS_FRAME_TYPE: u16 = 0x540A;
const RESULT_LISTS_FRAME_VERSION: u16 = 1;

fn encode_ordered_byte_list(items: &[Vec<u8>]) -> Result<Vec<u8>, ValueError> {
    let count_u16: u16 = u16::try_from(items.len())
        .map_err(|_| ValueError::Limit("object result entrypoint count exceeds u16::MAX"))?;
    let mut s: CanonicalStruct =
        CanonicalStruct::new(RESULT_LISTS_FRAME_TYPE, RESULT_LISTS_FRAME_VERSION);
    s.field_u16(1, count_u16)?;
    for (index, item) in items.iter().enumerate() {
        let field_id: u16 = u16::try_from(
            index
                .checked_add(2)
                .ok_or(ValueError::Limit("field id overflow"))?,
        )
        .map_err(|_| ValueError::Limit("field id exceeds u16::MAX"))?;
        s.field_bytes(field_id, item.as_slice())?;
    }
    Ok(s.finish()?)
}

fn decode_ordered_byte_list(bytes: &[u8], max_items: usize) -> Result<Vec<Vec<u8>>, ValueError> {
    if bytes.len() > MAX_EXECUTABLE_ABI_BYTES {
        return Err(ValueError::Limit("object result list byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(RESULT_LISTS_FRAME_TYPE)?;
    frame.require_version(RESULT_LISTS_FRAME_VERSION)?;
    let count: usize = usize::from(frame.required_u16(1)?);
    if count > max_items {
        return Err(ValueError::Limit("object result entrypoint count"));
    }
    let mut fields: Vec<u16> = Vec::with_capacity(count + 1);
    fields.push(1);
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(count);
    for index in 0..count {
        let field_id: u16 = u16::try_from(
            index
                .checked_add(2)
                .ok_or(ValueError::Limit("field id overflow"))?,
        )
        .map_err(|_| ValueError::Limit("field id exceeds u16::MAX"))?;
        fields.push(field_id);
        items.push(frame.required_field(field_id)?.to_vec());
    }
    frame.require_only_fields(&fields)?;
    Ok(items)
}
/// Strictly decodes the bounded executable wrapper and all referenced metadata.
pub fn decode_executable_abi(bytes: &[u8]) -> Result<ExecutableAbi, ValueError> {
    if bytes.len() > MAX_EXECUTABLE_ABI_BYTES {
        return Err(ValueError::Limit("executable ABI bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(0x5406)?;
    match frame.version() {
        1 => frame.require_only_fields(&[1, 2, 3])?,
        2 => frame.require_only_fields(&[1, 2, 3, 4])?,
        _ => return Err(ValueError::Invalid("executable abi version")),
    }
    let name: &str = frame.required_str(2)?;
    let encoded: &[u8] = frame.required_field(3)?;
    if encoded.len() < 2 || encoded.len() > 130 {
        return Err(ValueError::Limit("transfer constructors"));
    }
    let count: usize = usize::from(u16::from_le_bytes([encoded[0], encoded[1]]));
    if encoded.len() != 2 + count * 2 {
        return Err(ValueError::Invalid("transfer constructor count"));
    }
    let ids: Vec<u16> = encoded[2..]
        .chunks_exact(2)
        .map(|bytes: &[u8]| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect();
    let call: CallAbi = decode_call_abi(frame.required_field(1)?)?;
    let ep_count: usize = call.objects.entrypoints.len();
    let results: Vec<Vec<ObjectResultDeclaration>> = if frame.version() == 1 {
        vec![Vec::new(); ep_count]
    } else {
        let root_chain = call.objects.origin.chain_id().clone();
        let outer: Vec<Vec<u8>> =
            decode_ordered_byte_list(frame.required_field(4)?, public_abi::MAX_ABI_ENTRYPOINTS)?;
        if outer.len() != ep_count {
            return Err(ValueError::Invalid(
                "object result entrypoint count mismatch",
            ));
        }
        let mut node_count: usize = 0;
        let mut decoded: Vec<Vec<ObjectResultDeclaration>> = Vec::with_capacity(outer.len());
        for item in &outer {
            decoded.push(
                public_abi::decode_object_result_list(item, &root_chain, &mut node_count)
                    .map_err(ValueError::Abi)?,
            );
        }
        if decoded.iter().all(Vec::is_empty) {
            return Err(ValueError::Invalid(
                "noncanonical empty object result declarations under version 2",
            ));
        }
        decoded
    };
    let abi: ExecutableAbi = ExecutableAbi {
        call,
        initializer: if name.is_empty() {
            None
        } else {
            Some(name.to_owned())
        },
        transferable_constructors: ids,
        results,
    };
    abi.validate()?;
    Ok(abi)
}
