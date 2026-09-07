//! Checked typed `sunrise` host bindings.
//!
//! Canonical type, type-argument, body and instance bytes remain opaque here;
//! the host validates them against committed interfaces and frame authority.
//! Handles are frame-local selectors, not transferable authority or object IDs.
//! Contract calls use the runtime's signed authorization table for both same-
//! and different-instance dispatch. The dependency selector is an adapter into
//! that common frame/authority model, not an independent privilege mechanism.
//! A nested host failure traps the entire invocation, even if WASM ignores its
//! return value. Native builds have no host and return [`Error::Unavailable`].

use alloc::vec::Vec;
use core::{convert::Infallible, fmt};

/// Opaque selector issued for this frame's inputs or newly created objects.
/// Copying a selector does not duplicate rights; the host tracks all aliases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle(u32);

/// Maximum object selectors delegated to one typed contract or dependency call.
pub const MAX_DEPENDENCY_HANDLES: usize = 32;

/// Checked wrapper failure. Host authorization errors remain opaque.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No `sunrise` host exists on this target.
    Unavailable,
    /// An index, offset or byte length cannot fit the signed host ABI.
    IntegerOutOfRange,
    /// An input index is not present in this frame.
    InvalidHandle,
    /// A call handle list contains duplicate selectors.
    DuplicateHandle,
    /// The bounded call object parameter count was exceeded.
    TooManyHandles,
    /// The host returned a negative result.
    HostRejected,
    /// A host result violates the operation's return convention.
    InvalidHostResult,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "typed contract host is unavailable",
            Self::IntegerOutOfRange => "typed host integer or length is out of range",
            Self::InvalidHandle => "input handle is outside this frame",
            Self::DuplicateHandle => "call handle selectors must be unique",
            Self::TooManyHandles => "typed calls permit at most 32 object handles",
            Self::HostRejected => "typed host rejected the operation",
            Self::InvalidHostResult => "typed host returned an invalid result",
        })
    }
}
impl core::error::Error for Error {}

fn abi_len(value: usize) -> Result<i32, Error> {
    i32::try_from(value).map_err(|_| Error::IntegerOutOfRange)
}
fn abi_index(value: u32) -> Result<i32, Error> {
    i32::try_from(value).map_err(|_| Error::IntegerOutOfRange)
}
fn nonnegative(value: i32) -> Result<u32, Error> {
    u32::try_from(value).map_err(|_| Error::HostRejected)
}
fn success(value: i32) -> Result<(), Error> {
    match value {
        0 => Ok(()),
        value if value < 0 => Err(Error::HostRejected),
        _ => Err(Error::InvalidHostResult),
    }
}
fn written(value: i32, capacity: usize) -> Result<usize, Error> {
    let count: usize =
        usize::try_from(nonnegative(value)?).map_err(|_| Error::InvalidHostResult)?;
    if count > capacity {
        return Err(Error::InvalidHostResult);
    }
    Ok(count)
}
fn available() -> Result<(), Error> {
    if cfg!(target_arch = "wasm32") {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

/// Returns the number of object selectors available in the current frame.
pub fn object_count() -> Result<u32, Error> {
    available()?;
    // SAFETY: no pointers are passed; result is checked before conversion.
    nonnegative(unsafe { raw::get_object_count() })
}

/// Obtains an existing input selector after checking the current host count.
pub fn input_handle(index: u32) -> Result<Handle, Error> {
    abi_index(index)?;
    if index >= object_count()? {
        return Err(Error::InvalidHandle);
    }
    Ok(Handle(index))
}

/// Returns the current data length, rejecting consumed/inaccessible handles.
pub fn object_data_len(handle: Handle) -> Result<u32, Error> {
    let index = abi_index(handle.0)?;
    available()?;
    // SAFETY: only a checked integer selector is passed.
    nonnegative(unsafe { raw::get_object_data_len(index) })
}

/// Reads at most `output.len()` bytes, returning the checked bytes written.
pub fn read_object(handle: Handle, offset: u32, output: &mut [u8]) -> Result<usize, Error> {
    let index = abi_index(handle.0)?;
    let offset = abi_index(offset)?;
    let length = abi_len(output.len())?;
    available()?;
    // SAFETY: output is writable for exactly length bytes for this synchronous call.
    written(
        unsafe { raw::read_object_data(index, offset, output.as_mut_ptr(), length) },
        output.len(),
    )
}

/// Replaces an object's canonical body under the host's type/instance rights.
pub fn write_object(handle: Handle, body: &[u8]) -> Result<(), Error> {
    let index = abi_index(handle.0)?;
    let length = abi_len(body.len())?;
    available()?;
    // SAFETY: body remains readable for length bytes throughout the call.
    success(unsafe { raw::write_object_data(index, body.as_ptr(), length) })
}

/// Consumes the object; the host invalidates every alias in every frame.
pub fn consume_object(handle: Handle) -> Result<(), Error> {
    let index = abi_index(handle.0)?;
    available()?;
    // SAFETY: only a checked integer selector is passed.
    success(unsafe { raw::consume_object(index) })
}

/// Creates an own-defined canonical typed object and returns its frame-local selector.
/// The host validates the fixed address and grants rights appropriate to its owner.
pub fn create_object(type_tag: &[u8], owner: &[u8; 32], body: &[u8]) -> Result<Handle, Error> {
    let type_len = abi_len(type_tag.len())?;
    let body_len = abi_len(body.len())?;
    available()?;
    // SAFETY: all pointers reference live slices of the checked lengths; owner is 32 bytes.
    let result = unsafe {
        raw::create_object(
            type_tag.as_ptr(),
            type_len,
            owner.as_ptr(),
            body.as_ptr(),
            body_len,
        )
    };
    Ok(Handle(nonnegative(result)?))
}

/// Transfers an object; the host permanently downgrades all aliases to Read.
pub fn transfer_object(handle: Handle, owner: &[u8; 32]) -> Result<(), Error> {
    let index = abi_index(handle.0)?;
    available()?;
    // SAFETY: owner references exactly 32 readable bytes.
    success(unsafe { raw::transfer_object(index, owner.as_ptr()) })
}

/// Returns the canonical argument buffer length.
pub fn args_len() -> Result<u32, Error> {
    available()?;
    // SAFETY: no pointers are passed.
    nonnegative(unsafe { raw::get_args_len() })
}

/// Reads a bounded part of the canonical argument buffer.
pub fn read_args(offset: u32, output: &mut [u8]) -> Result<usize, Error> {
    let offset = abi_index(offset)?;
    let length = abi_len(output.len())?;
    available()?;
    // SAFETY: output is writable for exactly length bytes.
    written(
        unsafe { raw::read_args(offset, output.as_mut_ptr(), length) },
        output.len(),
    )
}

/// Returns the authenticated root sender's fixed 32-byte address.
pub fn caller() -> Result<[u8; 32], Error> {
    available()?;
    let mut address: [u8; 32] = [0; 32];
    // SAFETY: address is writable for exactly 32 bytes.
    let count = unsafe { raw::get_caller(address.as_mut_ptr()) };
    if written(count, address.len())? != address.len() {
        return Err(Error::InvalidHostResult);
    }
    Ok(address)
}

/// Writes the current frame's canonical `0x6404` instance record into a supplied buffer.
/// Insufficient space is rejected by the host; there is no implicit size probe.
pub fn instance(output: &mut [u8]) -> Result<usize, Error> {
    let length = abi_len(output.len())?;
    available()?;
    // SAFETY: output is writable for length bytes.
    written(
        unsafe { raw::get_instance(output.as_mut_ptr(), length) },
        output.len(),
    )
}

/// Emits a canonical own-defined scoped event tag and canonical body.
pub fn emit_event(type_tag: &[u8], body: &[u8]) -> Result<(), Error> {
    let type_len = abi_len(type_tag.len())?;
    let body_len = abi_len(body.len())?;
    available()?;
    // SAFETY: both slices remain readable for their checked lengths.
    success(unsafe { raw::emit_event(type_tag.as_ptr(), type_len, body.as_ptr(), body_len) })
}

fn encode_handles(handles: &[Handle]) -> Result<Vec<u8>, Error> {
    if handles.len() > MAX_DEPENDENCY_HANDLES {
        return Err(Error::TooManyHandles);
    }
    abi_len(handles.len())?;
    let length = handles
        .len()
        .checked_mul(4)
        .ok_or(Error::IntegerOutOfRange)?;
    abi_len(length)?;
    for (index, handle) in handles.iter().enumerate() {
        abi_index(handle.0)?;
        if handles[..index].contains(handle) {
            return Err(Error::DuplicateHandle);
        }
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(length);
    for handle in handles {
        bytes.extend_from_slice(&handle.0.to_le_bytes());
    }
    Ok(bytes)
}

/// Calls a directly declared dependency library in the same instance.
/// Type arguments and arguments use their existing canonical encodings.
/// The host checks the callee's rights against this unique subset of handles.
/// This selector adapts to the common contract-call frame validator and grants
/// no privilege absent from that validator.
pub fn call_dependency(
    dependency: u32,
    entrypoint: &str,
    types: &[u8],
    handles: &[Handle],
    args: &[u8],
) -> Result<(), Error> {
    let dependency = abi_index(dependency)?;
    let entry_len = abi_len(entrypoint.len())?;
    let types_len = abi_len(types.len())?;
    let handle_count = abi_len(handles.len())?;
    let args_len = abi_len(args.len())?;
    let encoded_handles = encode_handles(handles)?;
    available()?;
    // SAFETY: all slices remain readable throughout this synchronous call; handles
    // have exactly handle_count little-endian u32 elements, without alignment assumptions.
    success(unsafe {
        raw::call_dependency(
            dependency,
            entrypoint.as_ptr(),
            entry_len,
            types.as_ptr(),
            types_len,
            encoded_handles.as_ptr(),
            handle_count,
            args.as_ptr(),
            args_len,
        )
    })
}

/// Calls the exact target selected by the runtime's signed authorization table.
///
/// The same operation applies to targets in the current or another instance.
/// `authorization_index` selects an existing signed entry; this wrapper cannot
/// invent targets, entrypoints, type arguments, object selectors or rights.
/// The host validates `arguments` against the selected committed ABI layout.
/// Handles are a unique ordered subset of this frame's opaque selectors; the
/// host also enforces their signed selectors and current rights. Calls are void
/// and effectful; a nested trap rejects the complete invocation.
pub fn call_contract(
    authorization_index: u32,
    handles: &[Handle],
    arguments: &[u8],
) -> Result<(), Error> {
    let authorization_index: i32 = abi_index(authorization_index)?;
    let handle_count: i32 = abi_len(handles.len())?;
    let arguments_len: i32 = abi_len(arguments.len())?;
    let encoded_handles: Vec<u8> = encode_handles(handles)?;
    available()?;
    // SAFETY: both slices are live for their checked lengths throughout this
    // synchronous call. Handles encode exactly handle_count little-endian u32
    // selectors without relying on alignment or exposing Handle's representation.
    success(unsafe {
        raw::call_contract(
            authorization_index,
            encoded_handles.as_ptr(),
            handle_count,
            arguments.as_ptr(),
            arguments_len,
        )
    })
}

/// Traps the WASM invocation. Native calls return Unavailable without panicking.
pub fn abort(message: &str) -> Result<Infallible, Error> {
    let length = abi_len(message.len())?;
    available()?;
    // SAFETY: message is readable for length bytes. The host must not return.
    unsafe { raw::abort(message.as_ptr(), length) };
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();
    #[cfg(not(target_arch = "wasm32"))]
    Err(Error::Unavailable)
}

#[cfg(target_arch = "wasm32")]
mod raw {
    #[link(wasm_import_module = "sunrise")]
    unsafe extern "C" {
        pub(super) fn get_object_count() -> i32;
        pub(super) fn get_object_data_len(handle: i32) -> i32;
        pub(super) fn read_object_data(handle: i32, offset: i32, out: *mut u8, length: i32) -> i32;
        pub(super) fn write_object_data(handle: i32, data: *const u8, length: i32) -> i32;
        pub(super) fn consume_object(handle: i32) -> i32;
        pub(super) fn create_object(
            ty: *const u8,
            ty_len: i32,
            owner: *const u8,
            data: *const u8,
            data_len: i32,
        ) -> i32;
        pub(super) fn transfer_object(handle: i32, owner: *const u8) -> i32;
        pub(super) fn get_args_len() -> i32;
        pub(super) fn read_args(offset: i32, out: *mut u8, length: i32) -> i32;
        pub(super) fn get_caller(out: *mut u8) -> i32;
        pub(super) fn get_instance(out: *mut u8, length: i32) -> i32;
        pub(super) fn emit_event(ty: *const u8, ty_len: i32, data: *const u8, data_len: i32)
        -> i32;
        pub(super) fn abort(message: *const u8, length: i32);
        pub(super) fn call_dependency(
            dependency: i32,
            entry: *const u8,
            entry_len: i32,
            types: *const u8,
            types_len: i32,
            handles: *const u8,
            handle_count: i32,
            args: *const u8,
            args_len: i32,
        ) -> i32;
        pub(super) fn call_contract(
            authorization_index: i32,
            handles: *const u8,
            handle_count: i32,
            arguments: *const u8,
            arguments_len: i32,
        ) -> i32;
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod raw {
    // Private native stand-ins never dereference their pointer arguments.
    macro_rules! unavailable { ($($name:ident($($arg:ident: $ty:ty),*));* $(;)?) => { $(#[allow(clippy::too_many_arguments)] pub(super) unsafe fn $name($(_: $ty),*) -> i32 { -1 })* }; }
    unavailable! {
        get_object_count(); get_object_data_len(handle:i32);
        read_object_data(handle:i32,offset:i32,out:*mut u8,length:i32);
        write_object_data(handle:i32,data:*const u8,length:i32); consume_object(handle:i32);
        create_object(ty:*const u8,ty_len:i32,owner:*const u8,data:*const u8,data_len:i32);
        transfer_object(handle:i32,owner:*const u8); get_args_len();
        read_args(offset:i32,out:*mut u8,length:i32); get_caller(out:*mut u8); get_instance(out:*mut u8,length:i32);
        emit_event(ty:*const u8,ty_len:i32,data:*const u8,data_len:i32);
        call_dependency(dependency:i32,entry:*const u8,entry_len:i32,types:*const u8,types_len:i32,handles:*const u8,handle_count:i32,args:*const u8,args_len:i32);
        call_contract(authorization_index:i32,handles:*const u8,handle_count:i32,arguments:*const u8,arguments_len:i32)
    }
    pub(super) unsafe fn abort(_: *const u8, _: i32) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conversions_reject_truncation_and_negative_results() {
        assert_eq!(success(0), Ok(()));
        assert_eq!(
            abi_len(i32::MAX as usize + 1),
            Err(Error::IntegerOutOfRange)
        );
        assert_eq!(abi_index(u32::MAX), Err(Error::IntegerOutOfRange));
        assert_eq!(nonnegative(-1), Err(Error::HostRejected));
        assert_eq!(success(1), Err(Error::InvalidHostResult));
        assert_eq!(success(-1), Err(Error::HostRejected));
        assert_eq!(written(5, 4), Err(Error::InvalidHostResult));
        assert_eq!(written(4, 4), Ok(4));
    }
    #[test]
    fn handles_are_unique_little_endian_checked_selectors() {
        assert_eq!(
            encode_handles(&[Handle(1), Handle(256)]).unwrap(),
            [1, 0, 0, 0, 0, 1, 0, 0]
        );
        assert_eq!(
            encode_handles(&[Handle(1), Handle(1)]),
            Err(Error::DuplicateHandle)
        );
        assert_eq!(
            encode_handles(&[Handle(u32::MAX)]),
            Err(Error::IntegerOutOfRange)
        );
        assert_eq!(
            encode_handles(&[Handle(0); MAX_DEPENDENCY_HANDLES + 1]),
            Err(Error::TooManyHandles)
        );
    }
    #[test]
    fn native_wrappers_fail_without_linking_or_dereferencing_host_pointers() {
        assert_eq!(call_contract(0, &[], &[]), Err(Error::Unavailable));
        assert_eq!(object_count(), Err(Error::Unavailable));
        assert_eq!(input_handle(0), Err(Error::Unavailable));
        assert_eq!(input_handle(u32::MAX), Err(Error::IntegerOutOfRange));
        assert_eq!(object_data_len(Handle(0)), Err(Error::Unavailable));
        assert_eq!(
            read_object(Handle(0), 0, &mut [0; 4]),
            Err(Error::Unavailable)
        );
        assert_eq!(write_object(Handle(0), &[]), Err(Error::Unavailable));
        assert_eq!(consume_object(Handle(0)), Err(Error::Unavailable));
        assert_eq!(create_object(&[], &[0; 32], &[]), Err(Error::Unavailable));
        assert_eq!(
            transfer_object(Handle(0), &[0; 32]),
            Err(Error::Unavailable)
        );
        assert_eq!(args_len(), Err(Error::Unavailable));
        assert_eq!(read_args(0, &mut []), Err(Error::Unavailable));
        assert_eq!(caller(), Err(Error::Unavailable));
        assert_eq!(instance(&mut []), Err(Error::Unavailable));
        assert_eq!(emit_event(&[], &[]), Err(Error::Unavailable));
        assert_eq!(
            call_dependency(0, "run", &[], &[], &[]),
            Err(Error::Unavailable)
        );
        assert_eq!(abort("no host"), Err(Error::Unavailable));
    }

    #[test]
    fn contract_call_checks_indices_uniqueness_and_bounds_before_native_dispatch() {
        assert_eq!(
            call_contract(u32::MAX, &[], &[]),
            Err(Error::IntegerOutOfRange)
        );
        assert_eq!(
            call_contract(0, &[Handle(u32::MAX)], &[]),
            Err(Error::IntegerOutOfRange)
        );
        assert_eq!(
            call_contract(0, &[Handle(1), Handle(1)], &[]),
            Err(Error::DuplicateHandle)
        );
        let handles: Vec<Handle> = (0..=MAX_DEPENDENCY_HANDLES as u32).map(Handle).collect();
        assert_eq!(call_contract(0, &handles, &[]), Err(Error::TooManyHandles));
        assert_eq!(
            call_contract(i32::MAX as u32, &handles[..MAX_DEPENDENCY_HANDLES], &[1, 2]),
            Err(Error::Unavailable)
        );
    }
}
