//! Signed executable metadata, distinct from historical CallAbi version one.
use crate::call_values::{CallAbi, ValueError, decode_call_abi, encode_call_abi};
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
        Ok(())
    }
}
/// Encodes executable wrapper 0x5406/v1; never aliases historical CallAbi bytes.
pub fn encode_executable_abi(abi: &ExecutableAbi) -> Result<Vec<u8>, ValueError> {
    abi.validate()?;
    let call_bytes: Vec<u8> = encode_call_abi(&abi.call)?;
    let overhead: usize = 10
        + 3 * 6
        + abi.initializer.as_deref().map_or(0, str::len)
        + 2
        + 2 * abi.transferable_constructors.len();
    if call_bytes.len() > MAX_EXECUTABLE_ABI_BYTES - overhead {
        return Err(ValueError::Limit("inner CallAbi exceeds wrapper budget"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x5406, 1);
    frame.field_bytes(1, call_bytes)?;
    frame.field_str(2, abi.initializer.as_deref().unwrap_or(""))?;
    let mut ids: Vec<u8> = Vec::with_capacity(2 + 2 * abi.transferable_constructors.len());
    ids.extend_from_slice(&(abi.transferable_constructors.len() as u16).to_le_bytes());
    for id in &abi.transferable_constructors {
        ids.extend_from_slice(&id.to_le_bytes());
    }
    frame.field_bytes(3, ids)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_EXECUTABLE_ABI_BYTES {
        return Err(ValueError::Limit("executable ABI bytes"));
    }
    Ok(bytes)
}
/// Strictly decodes the bounded executable wrapper and all referenced metadata.
pub fn decode_executable_abi(bytes: &[u8]) -> Result<ExecutableAbi, ValueError> {
    if bytes.len() > MAX_EXECUTABLE_ABI_BYTES {
        return Err(ValueError::Limit("executable ABI bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(0x5406)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3])?;
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
    let abi: ExecutableAbi = ExecutableAbi {
        call: decode_call_abi(frame.required_field(1)?)?,
        initializer: if name.is_empty() {
            None
        } else {
            Some(name.to_owned())
        },
        transferable_constructors: ids,
    };
    abi.validate()?;
    Ok(abi)
}
