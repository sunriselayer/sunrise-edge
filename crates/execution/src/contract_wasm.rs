//! Bounded, reusable WASM publication-admission verifier.
//!
//! [`validate_contract_wasm`] performs **structural WASM admission only**:
//! it checks that a candidate module is a well-formed, resource-bounded
//! core-WASM binary matching a narrow integer-only profile and declaring
//! exactly the requested entrypoints. It is not typed contract authority,
//! does not persist any publication record, and does not itself grant
//! permission to execute any module that passes. Validation never
//! instantiates, starts, runs, or invokes host code; it only parses and
//! statically inspects the module.

use std::collections::BTreeSet;
use std::fmt;

use wasmi::{Config, Engine, Module as WasmiModule};
use wasmparser::{
    Chunk, Encoding, ExternalKind, FuncType, Parser, Payload, TypeRef, ValType, Validator,
    WasmFeatures,
};

/// Versioned identifier for this structural admission profile.
///
/// This identifies only the *shape* of checks [`validate_contract_wasm`]
/// performs. It is not a typed-authority version, not a publication or
/// instance revision, and passing this profile does not authorize
/// execution of the module.
pub const CONTRACT_WASM_ADMISSION_PROFILE_VERSION: u32 = 1;
/// Authority-aware typed host import profile, separately admitted from legacy env.
pub const TYPED_CONTRACT_WASM_PROFILE_VERSION: u32 = 2;

/// Maximum accepted byte length of a candidate contract WASM binary.
pub const MAX_CONTRACT_WASM_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of declared entrypoint names.
pub const MAX_CONTRACT_ENTRYPOINTS: usize = 64;
/// Maximum byte length of a single declared entrypoint name.
pub const MAX_CONTRACT_ENTRYPOINT_NAME_BYTES: usize = 256;

const MAX_TYPES: u32 = 4096;
const MAX_FUNCTIONS: u32 = 4096;
const MAX_IMPORTS: u32 = 11;
const MAX_GLOBALS: u32 = 1024;
const MAX_TABLES: u32 = 1;
const MAX_TABLE_ELEMENTS: u64 = 4096;
const MAX_MEMORIES: u32 = 1;
const MAX_MEMORY_PAGES: u64 = 256;
const MAX_DATA_SEGMENTS: u32 = 1024;
const MAX_ELEMENT_SEGMENTS: u32 = 1024;
const MAX_FUNCTION_LOCALS: u64 = 4096;
const MAX_PARAMS: usize = 64;
const MAX_RESULTS: usize = 1;

const RESERVED_MEMORY_EXPORT_NAME: &str = "memory";
const CORE_WASM_HEADER: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// The exact `"env"` host import signature this profile accepts, matching
/// the host ABI implemented in `wasm_engine`.
struct HostImportSignature {
    name: &'static str,
    params: &'static [ValType],
    results: &'static [ValType],
}

const ALLOWED_HOST_IMPORTS: &[HostImportSignature] = &[
    HostImportSignature {
        name: "get_object_count",
        params: &[],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "get_object_data_len",
        params: &[ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "read_object_data",
        params: &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "write_object_data",
        params: &[ValType::I32, ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "consume_object",
        params: &[ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "create_object",
        params: &[
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
        ],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "get_object_type_hash",
        params: &[ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "emit_event",
        params: &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "get_args_len",
        params: &[],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "read_args",
        params: &[ValType::I32, ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "abort",
        params: &[ValType::I32, ValType::I32],
        results: &[],
    },
];

const TYPED_HOST_IMPORTS: &[HostImportSignature] = &[
    HostImportSignature {
        name: "get_object_count",
        params: &[],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "get_object_data_len",
        params: &[ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "read_object_data",
        params: &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "write_object_data",
        params: &[ValType::I32, ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "consume_object",
        params: &[ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "create_object",
        params: &[
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
        ],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "transfer_object",
        params: &[ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "get_args_len",
        params: &[],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "read_args",
        params: &[ValType::I32, ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "get_caller",
        params: &[ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "get_instance",
        params: &[ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "emit_event",
        params: &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        results: &[ValType::I32],
    },
    HostImportSignature {
        name: "abort",
        params: &[ValType::I32, ValType::I32],
        results: &[],
    },
    HostImportSignature {
        name: "call_dependency",
        params: &[
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I32,
        ],
        results: &[ValType::I32],
    },
];

fn find_host_import(name: &str, profile: u32) -> Option<&'static HostImportSignature> {
    let imports: &[HostImportSignature] = if profile == 2 {
        TYPED_HOST_IMPORTS
    } else {
        ALLOWED_HOST_IMPORTS
    };
    imports.iter().find(|spec| spec.name == name)
}

/// Errors produced while admitting a candidate contract WASM binary.
///
/// Variants are deterministic and stable; they never embed a raw
/// underlying-parser or -engine error message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractWasmValidationError {
    /// The module bytes exceeded [`MAX_CONTRACT_WASM_BYTES`].
    TooManyBytes { actual: usize, maximum: usize },
    /// No entrypoint names were declared.
    NoEntrypointsDeclared,
    /// More entrypoints were declared than [`MAX_CONTRACT_ENTRYPOINTS`].
    TooManyEntrypoints { actual: usize, maximum: usize },
    /// A declared entrypoint name was empty or too long. Do not copy an
    /// oversized caller-supplied name into an error allocation.
    InvalidEntrypointName { actual: usize, maximum: usize },
    /// A declared entrypoint name was duplicated.
    DuplicateEntrypointName { name: String },
    /// A declared entrypoint used the reserved name `"memory"`.
    ReservedEntrypointName { name: String },
    /// The bytes are not a core-WASM binary (e.g. text format or component).
    NotCoreWasmBinary,
    /// The bytes are encoded as a WASM component, not a core module.
    ComponentFormatRejected,
    /// The module declares a start function.
    StartFunctionPresent,
    /// The type section declared more entries than the bound.
    TooManyTypes { actual: u32, maximum: u32 },
    /// The combined imported+defined function count exceeded the bound.
    TooManyFunctions { actual: u32, maximum: u32 },
    /// The import section declared more entries than the bound.
    TooManyImports { actual: u32, maximum: u32 },
    /// The global section declared more entries than the bound.
    TooManyGlobals { actual: u32, maximum: u32 },
    /// The table section declared more tables than the bound.
    TooManyTables { actual: u32, maximum: u32 },
    /// The memory section declared more memories than the bound.
    TooManyMemories { actual: u32, maximum: u32 },
    /// The data section declared more segments than the bound.
    TooManyDataSegments { actual: u32, maximum: u32 },
    /// The element section declared more segments than the bound.
    TooManyElementSegments { actual: u32, maximum: u32 },
    /// A function declared more locals than the bound.
    TooManyFunctionLocals { actual: u64, maximum: u64 },
    /// A function type declared more parameters than the bound.
    TooManyParams { actual: usize, maximum: usize },
    /// A function type declared more results than the bound.
    TooManyResults { actual: usize, maximum: usize },
    /// A table's maximum size exceeded the bound.
    TableElementsExceeded { actual: u64, maximum: u64 },
    /// A table did not declare an explicit maximum size.
    TableMaximumMissing,
    /// The memory's maximum page count exceeded the bound.
    MemoryPagesExceeded { actual: u64, maximum: u64 },
    /// The memory did not declare an explicit maximum size.
    MemoryMaximumMissing,
    /// No memory was exported under the reserved name `"memory"`.
    MissingMemoryExport,
    /// The module imports a memory, which is never permitted.
    ImportedMemory,
    /// The module imports a table, which is never permitted.
    ImportedTable,
    /// The module imports a global, which is never permitted.
    ImportedGlobal,
    /// An import did not match any accepted host function.
    UnknownImport { module: String, name: String },
    /// The same `(module, name)` pair was imported more than once.
    DuplicateImport { module: String, name: String },
    /// An accepted import name was used with the wrong function signature.
    ImportSignatureMismatch { module: String, name: String },
    /// An export exists that is neither the memory export nor a declared
    /// entrypoint.
    UnexpectedExport { name: String },
    /// A declared entrypoint was not exported by the module.
    MissingDeclaredEntrypoint { name: String },
    /// An exported entrypoint function did not have signature `() -> ()`.
    EntrypointSignatureMismatch { name: String },
    /// The module was structurally malformed or used an unsupported feature.
    InvalidModule,
}

impl fmt::Display for ContractWasmValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyBytes { actual, maximum } => {
                write!(f, "module is {actual} bytes, maximum is {maximum}")
            }
            Self::NoEntrypointsDeclared => write!(f, "no entrypoints declared"),
            Self::TooManyEntrypoints { actual, maximum } => {
                write!(f, "{actual} entrypoints declared, maximum is {maximum}")
            }
            Self::InvalidEntrypointName { actual, maximum } => {
                write!(
                    f,
                    "entrypoint name is {actual} bytes; expected 1..={maximum}"
                )
            }
            Self::DuplicateEntrypointName { name } => {
                write!(f, "duplicate entrypoint name: {name:?}")
            }
            Self::ReservedEntrypointName { name } => {
                write!(f, "entrypoint name {name:?} is reserved")
            }
            Self::NotCoreWasmBinary => write!(f, "bytes are not a core wasm binary"),
            Self::ComponentFormatRejected => write!(f, "component format is not accepted"),
            Self::StartFunctionPresent => write!(f, "module declares a start function"),
            Self::TooManyTypes { actual, maximum } => {
                write!(f, "{actual} types declared, maximum is {maximum}")
            }
            Self::TooManyFunctions { actual, maximum } => {
                write!(f, "{actual} functions declared, maximum is {maximum}")
            }
            Self::TooManyImports { actual, maximum } => {
                write!(f, "{actual} imports declared, maximum is {maximum}")
            }
            Self::TooManyGlobals { actual, maximum } => {
                write!(f, "{actual} globals declared, maximum is {maximum}")
            }
            Self::TooManyTables { actual, maximum } => {
                write!(f, "{actual} tables declared, maximum is {maximum}")
            }
            Self::TooManyMemories { actual, maximum } => {
                write!(f, "{actual} memories declared, maximum is {maximum}")
            }
            Self::TooManyDataSegments { actual, maximum } => {
                write!(f, "{actual} data segments declared, maximum is {maximum}")
            }
            Self::TooManyElementSegments { actual, maximum } => {
                write!(
                    f,
                    "{actual} element segments declared, maximum is {maximum}"
                )
            }
            Self::TooManyFunctionLocals { actual, maximum } => {
                write!(f, "function declares {actual} locals, maximum is {maximum}")
            }
            Self::TooManyParams { actual, maximum } => {
                write!(f, "function type has {actual} params, maximum is {maximum}")
            }
            Self::TooManyResults { actual, maximum } => {
                write!(
                    f,
                    "function type has {actual} results, maximum is {maximum}"
                )
            }
            Self::TableElementsExceeded { actual, maximum } => {
                write!(f, "table maximum is {actual}, bound is {maximum}")
            }
            Self::TableMaximumMissing => write!(f, "table does not declare an explicit maximum"),
            Self::MemoryPagesExceeded { actual, maximum } => {
                write!(f, "memory maximum is {actual} pages, bound is {maximum}")
            }
            Self::MemoryMaximumMissing => {
                write!(f, "memory does not declare an explicit maximum")
            }
            Self::MissingMemoryExport => {
                write!(f, "no memory exported under the name \"memory\"")
            }
            Self::ImportedMemory => write!(f, "module imports a memory"),
            Self::ImportedTable => write!(f, "module imports a table"),
            Self::ImportedGlobal => write!(f, "module imports a global"),
            Self::UnknownImport { module, name } => {
                write!(f, "unknown import {module}.{name}")
            }
            Self::DuplicateImport { module, name } => {
                write!(f, "duplicate import {module}.{name}")
            }
            Self::ImportSignatureMismatch { module, name } => {
                write!(f, "import {module}.{name} has an unexpected signature")
            }
            Self::UnexpectedExport { name } => write!(f, "unexpected export {name:?}"),
            Self::MissingDeclaredEntrypoint { name } => {
                write!(f, "declared entrypoint {name:?} was not exported")
            }
            Self::EntrypointSignatureMismatch { name } => {
                write!(f, "entrypoint {name:?} does not have signature () -> ()")
            }
            Self::InvalidModule => write!(f, "module is structurally invalid"),
        }
    }
}

impl std::error::Error for ContractWasmValidationError {}

/// A candidate contract WASM binary that has passed
/// [`validate_contract_wasm`]'s structural admission checks.
///
/// This is **not** typed contract authority, a publication record, or
/// permission to execute the module; it only certifies that the bytes
/// match the bounded structural profile identified by
/// [`CONTRACT_WASM_ADMISSION_PROFILE_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedContractWasm {
    bytes: Vec<u8>,
    entrypoints: Vec<String>,
    profile: u32,
}

impl ValidatedContractWasm {
    /// The admitted module bytes.
    #[must_use]
    pub fn wasm_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The declared entrypoint names, sorted with duplicates rejected.
    #[must_use]
    pub fn entrypoints(&self) -> &[String] {
        &self.entrypoints
    }

    /// The admission profile version this value was validated against.
    #[must_use]
    pub fn profile_version(&self) -> u32 {
        self.profile
    }
}

fn check_binary_header(bytes: &[u8]) -> Result<(), ContractWasmValidationError> {
    if bytes.len() > MAX_CONTRACT_WASM_BYTES {
        return Err(ContractWasmValidationError::TooManyBytes {
            actual: bytes.len(),
            maximum: MAX_CONTRACT_WASM_BYTES,
        });
    }
    if bytes.len() < CORE_WASM_HEADER.len() || bytes[..CORE_WASM_HEADER.len()] != CORE_WASM_HEADER {
        return Err(ContractWasmValidationError::NotCoreWasmBinary);
    }
    Ok(())
}

fn validate_declared_entrypoints(
    declared: &[&str],
) -> Result<Vec<String>, ContractWasmValidationError> {
    if declared.is_empty() {
        return Err(ContractWasmValidationError::NoEntrypointsDeclared);
    }
    if declared.len() > MAX_CONTRACT_ENTRYPOINTS {
        return Err(ContractWasmValidationError::TooManyEntrypoints {
            actual: declared.len(),
            maximum: MAX_CONTRACT_ENTRYPOINTS,
        });
    }
    let mut sorted: Vec<String> = Vec::with_capacity(declared.len());
    for name in declared {
        if name.is_empty() || name.len() > MAX_CONTRACT_ENTRYPOINT_NAME_BYTES {
            return Err(ContractWasmValidationError::InvalidEntrypointName {
                actual: name.len(),
                maximum: MAX_CONTRACT_ENTRYPOINT_NAME_BYTES,
            });
        }
        if *name == RESERVED_MEMORY_EXPORT_NAME {
            return Err(ContractWasmValidationError::ReservedEntrypointName {
                name: (*name).to_string(),
            });
        }
        sorted.push((*name).to_string());
    }
    sorted.sort();
    for pair in sorted.windows(2) {
        if pair[0] == pair[1] {
            return Err(ContractWasmValidationError::DuplicateEntrypointName {
                name: pair[0].clone(),
            });
        }
    }
    Ok(sorted)
}

/// The pinned WASM feature profile: base MVP plus mutable globals, sign
/// extension, and bulk memory. Every other proposal (floats, SIMD, threads,
/// memory64, multi-memory, reference types, component model, and all
/// others) is explicitly disabled and must not be re-enabled by a future
/// `wasmparser`/`wasmi` default.
fn admission_wasm_features() -> WasmFeatures {
    WasmFeatures::empty()
        | WasmFeatures::MUTABLE_GLOBAL
        | WasmFeatures::SIGN_EXTENSION
        | WasmFeatures::BULK_MEMORY
}

fn admission_wasmi_config() -> Config {
    let mut config = Config::default();
    config
        .wasm_mutable_global(true)
        .wasm_sign_extension(true)
        .wasm_bulk_memory(true)
        .wasm_saturating_float_to_int(false)
        .wasm_multi_value(false)
        .wasm_multi_memory(false)
        .wasm_reference_types(false)
        .wasm_tail_call(false)
        .wasm_extended_const(false)
        .wasm_custom_page_sizes(false)
        .wasm_memory64(false)
        .wasm_wide_arithmetic(false)
        .floats(false)
        .consume_fuel(true)
        .ignore_custom_sections(true);
    config
}

/// Parses `bytes` once, bounding every section's metadata against this
/// profile's fixed limits and checking imports/exports/start/locals,
/// *before* any full semantic validation or engine compilation runs.
fn scan_and_bound_module(
    bytes: &[u8],
    entrypoints: &[String],
    profile: u32,
) -> Result<(), ContractWasmValidationError> {
    use ContractWasmValidationError as E;

    let mut types_list: Vec<FuncType> = Vec::new();
    let mut combined_function_types: Vec<FuncType> = Vec::new();
    let mut imported_func_count: u32 = 0;
    let mut saw_memory = false;
    let mut memory_exported = false;
    let mut found_entrypoints = vec![false; entrypoints.len()];
    let mut seen_sections: BTreeSet<u8> = BTreeSet::new();

    let mut parser = Parser::new(0);
    let mut data = bytes;
    loop {
        let (consumed, payload) = match parser.parse(data, true) {
            Ok(Chunk::Parsed { consumed, payload }) => (consumed, payload),
            Ok(Chunk::NeedMoreData(_)) => return Err(E::InvalidModule),
            Err(_) => return Err(E::InvalidModule),
        };
        data = &data[consumed..];

        // Reject repeated sections before a second allocation can bypass a
        // per-section bound. Custom sections may repeat; code bodies are not
        // separate sections. Full validation also checks canonical ordering.
        if let Some((id, _range)) = payload.as_section()
            && id != 0
            && !seen_sections.insert(id)
        {
            return Err(E::InvalidModule);
        }

        match payload {
            Payload::Version { encoding, .. } => {
                if encoding != Encoding::Module {
                    return Err(E::ComponentFormatRejected);
                }
            }
            Payload::TypeSection(reader) => {
                let count = reader.count();
                if count > MAX_TYPES {
                    return Err(E::TooManyTypes {
                        actual: count,
                        maximum: MAX_TYPES,
                    });
                }
                // Decode only flat function types. Parsing a GC recursion
                // group first could allocate many types behind a count of 1.
                let offset: usize = reader.original_position();
                let section: &[u8] = bytes
                    .get(offset..reader.range().end)
                    .ok_or(E::InvalidModule)?;
                let mut raw = wasmparser::BinaryReader::new(section, offset);
                for _ in 0..count {
                    if raw.read_u8().map_err(|_| E::InvalidModule)? != 0x60 {
                        return Err(E::InvalidModule);
                    }
                    let params: Vec<ValType> = read_value_types(&mut raw, MAX_PARAMS, true)?;
                    let results: Vec<ValType> = read_value_types(&mut raw, MAX_RESULTS, false)?;
                    types_list.push(FuncType::new(params, results));
                }
                if !raw.eof() {
                    return Err(E::InvalidModule);
                }
            }
            Payload::ImportSection(reader) => {
                let count = reader.count();
                let maximum: u32 = if profile == 2 {
                    TYPED_HOST_IMPORTS.len() as u32
                } else {
                    MAX_IMPORTS
                };
                if count > maximum {
                    return Err(E::TooManyImports {
                        actual: count,
                        maximum,
                    });
                }
                let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
                for item in reader {
                    let import = item.map_err(|_| E::InvalidModule)?;
                    if import.module.len() > MAX_CONTRACT_ENTRYPOINT_NAME_BYTES
                        || import.name.len() > MAX_CONTRACT_ENTRYPOINT_NAME_BYTES
                    {
                        return Err(E::InvalidModule);
                    }
                    let module = import.module.to_string();
                    let name = import.name.to_string();
                    if !seen.insert((module.clone(), name.clone())) {
                        return Err(E::DuplicateImport { module, name });
                    }
                    match import.ty {
                        TypeRef::Func(type_idx) => {
                            let func_ty = types_list
                                .get(type_idx as usize)
                                .ok_or(E::InvalidModule)?
                                .clone();
                            if module != if profile == 2 { "sunrise" } else { "env" } {
                                return Err(E::UnknownImport { module, name });
                            }
                            let spec = find_host_import(&name, profile).ok_or_else(|| {
                                E::UnknownImport {
                                    module: module.clone(),
                                    name: name.clone(),
                                }
                            })?;
                            if func_ty.params() != spec.params || func_ty.results() != spec.results
                            {
                                return Err(E::ImportSignatureMismatch { module, name });
                            }
                            imported_func_count =
                                imported_func_count.checked_add(1).ok_or(E::InvalidModule)?;
                            combined_function_types.push(func_ty);
                        }
                        TypeRef::Table(_) => return Err(E::ImportedTable),
                        TypeRef::Memory(_) => return Err(E::ImportedMemory),
                        TypeRef::Global(_) => return Err(E::ImportedGlobal),
                        TypeRef::Tag(_) => return Err(E::InvalidModule),
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                let count = reader.count();
                let total = imported_func_count
                    .checked_add(count)
                    .ok_or(E::InvalidModule)?;
                if total > MAX_FUNCTIONS {
                    return Err(E::TooManyFunctions {
                        actual: total,
                        maximum: MAX_FUNCTIONS,
                    });
                }
                for item in reader {
                    let type_idx: u32 = item.map_err(|_| E::InvalidModule)?;
                    let func_ty = types_list
                        .get(type_idx as usize)
                        .ok_or(E::InvalidModule)?
                        .clone();
                    combined_function_types.push(func_ty);
                }
            }
            Payload::TableSection(reader) => {
                let count = reader.count();
                if count > MAX_TABLES {
                    return Err(E::TooManyTables {
                        actual: count,
                        maximum: MAX_TABLES,
                    });
                }
                for item in reader {
                    let table = item.map_err(|_| E::InvalidModule)?;
                    if table.ty.table64
                        || table.ty.shared
                        || table.ty.element_type != wasmparser::RefType::FUNCREF
                        || table.ty.maximum.is_some_and(|max| table.ty.initial > max)
                    {
                        return Err(E::InvalidModule);
                    }
                    match table.ty.maximum {
                        Some(max) if max <= MAX_TABLE_ELEMENTS => {}
                        Some(max) => {
                            return Err(E::TableElementsExceeded {
                                actual: max,
                                maximum: MAX_TABLE_ELEMENTS,
                            });
                        }
                        None => return Err(E::TableMaximumMissing),
                    }
                }
            }
            Payload::MemorySection(reader) => {
                let count = reader.count();
                if count > MAX_MEMORIES {
                    return Err(E::TooManyMemories {
                        actual: count,
                        maximum: MAX_MEMORIES,
                    });
                }
                for item in reader {
                    let memory = item.map_err(|_| E::InvalidModule)?;
                    if memory.memory64
                        || memory.shared
                        || memory.page_size_log2.is_some()
                        || memory.maximum.is_some_and(|max| memory.initial > max)
                    {
                        return Err(E::InvalidModule);
                    }
                    match memory.maximum {
                        Some(max) if max <= MAX_MEMORY_PAGES => {}
                        Some(max) => {
                            return Err(E::MemoryPagesExceeded {
                                actual: max,
                                maximum: MAX_MEMORY_PAGES,
                            });
                        }
                        None => return Err(E::MemoryMaximumMissing),
                    }
                    saw_memory = true;
                }
            }
            Payload::TagSection(_) => return Err(E::InvalidModule),
            Payload::GlobalSection(reader) => {
                let count = reader.count();
                if count > MAX_GLOBALS {
                    return Err(E::TooManyGlobals {
                        actual: count,
                        maximum: MAX_GLOBALS,
                    });
                }
            }
            Payload::ExportSection(reader) => {
                if reader.count() as usize > entrypoints.len() + 1 {
                    return Err(E::InvalidModule);
                }
                for item in reader {
                    let export = item.map_err(|_| E::InvalidModule)?;
                    if export.name.len() > MAX_CONTRACT_ENTRYPOINT_NAME_BYTES {
                        return Err(E::InvalidModule);
                    }
                    let name = export.name.to_string();
                    match export.kind {
                        ExternalKind::Func => {
                            if export.index < imported_func_count {
                                return Err(E::InvalidModule);
                            }
                            if name == RESERVED_MEMORY_EXPORT_NAME {
                                return Err(E::UnexpectedExport { name });
                            }
                            let position = entrypoints
                                .iter()
                                .position(|declared| *declared == name)
                                .ok_or_else(|| E::UnexpectedExport { name: name.clone() })?;
                            let func_ty = combined_function_types
                                .get(export.index as usize)
                                .ok_or(E::InvalidModule)?;
                            if !func_ty.params().is_empty() || !func_ty.results().is_empty() {
                                return Err(E::EntrypointSignatureMismatch { name });
                            }
                            found_entrypoints[position] = true;
                        }
                        ExternalKind::Memory => {
                            if name != RESERVED_MEMORY_EXPORT_NAME {
                                return Err(E::UnexpectedExport { name });
                            }
                            memory_exported = true;
                        }
                        ExternalKind::Table | ExternalKind::Global | ExternalKind::Tag => {
                            return Err(E::UnexpectedExport { name });
                        }
                    }
                }
            }
            Payload::StartSection { .. } => return Err(E::StartFunctionPresent),
            Payload::ElementSection(reader) => {
                let count = reader.count();
                if count > MAX_ELEMENT_SEGMENTS {
                    return Err(E::TooManyElementSegments {
                        actual: count,
                        maximum: MAX_ELEMENT_SEGMENTS,
                    });
                }
            }
            Payload::DataCountSection { count, .. } => {
                if count > MAX_DATA_SEGMENTS {
                    return Err(E::TooManyDataSegments {
                        actual: count,
                        maximum: MAX_DATA_SEGMENTS,
                    });
                }
            }
            Payload::DataSection(reader) => {
                let count = reader.count();
                if count > MAX_DATA_SEGMENTS {
                    return Err(E::TooManyDataSegments {
                        actual: count,
                        maximum: MAX_DATA_SEGMENTS,
                    });
                }
            }
            Payload::CodeSectionStart { count, .. } => {
                if count > MAX_FUNCTIONS {
                    return Err(E::TooManyFunctions {
                        actual: count,
                        maximum: MAX_FUNCTIONS,
                    });
                }
            }
            Payload::CodeSectionEntry(body) => {
                let locals_reader = body.get_locals_reader().map_err(|_| E::InvalidModule)?;
                let mut total_locals: u64 = 0;
                for item in locals_reader {
                    let (count, _ty) = item.map_err(|_| E::InvalidModule)?;
                    total_locals = total_locals
                        .checked_add(u64::from(count))
                        .ok_or(E::InvalidModule)?;
                    if total_locals > MAX_FUNCTION_LOCALS {
                        return Err(E::TooManyFunctionLocals {
                            actual: total_locals,
                            maximum: MAX_FUNCTION_LOCALS,
                        });
                    }
                }
            }
            Payload::CustomSection(_) => {}
            Payload::UnknownSection { .. } => return Err(E::InvalidModule),
            Payload::End(_) => {
                if !data.is_empty() {
                    return Err(E::InvalidModule);
                }
                break;
            }
            _ => return Err(E::InvalidModule),
        }
    }

    if !saw_memory || !memory_exported {
        return Err(E::MissingMemoryExport);
    }
    for (name, found) in entrypoints.iter().zip(found_entrypoints.iter()) {
        if !found {
            return Err(E::MissingDeclaredEntrypoint { name: name.clone() });
        }
    }

    Ok(())
}

fn read_value_types(
    reader: &mut wasmparser::BinaryReader<'_>,
    maximum: usize,
    parameters: bool,
) -> Result<Vec<ValType>, ContractWasmValidationError> {
    use ContractWasmValidationError as E;
    let count: usize = reader.read_var_u32().map_err(|_| E::InvalidModule)? as usize;
    if count > maximum {
        return Err(if parameters {
            E::TooManyParams {
                actual: count,
                maximum,
            }
        } else {
            E::TooManyResults {
                actual: count,
                maximum,
            }
        });
    }
    let mut types: Vec<ValType> = Vec::with_capacity(count);
    for _ in 0..count {
        let ty: ValType = reader.read().map_err(|_| E::InvalidModule)?;
        if !matches!(ty, ValType::I32 | ValType::I64) {
            return Err(E::InvalidModule);
        }
        types.push(ty);
    }
    Ok(types)
}

/// Validates that `bytes` is a bounded, structurally admissible contract
/// WASM binary declaring exactly `declared_entrypoints`.
///
/// This is **structural WASM admission only**: it does not confer typed
/// contract authority, does not persist any publication record, and does
/// not itself grant permission to execute the module. Validation never
/// instantiates, starts, runs, or invokes any host function.
pub fn validate_contract_wasm(
    bytes: &[u8],
    declared_entrypoints: &[&str],
) -> Result<ValidatedContractWasm, ContractWasmValidationError> {
    validate_contract_wasm_profile(
        bytes,
        declared_entrypoints,
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
    )
}

/// Validates one explicitly selected structural import profile; unknown profiles fail closed.
pub fn validate_contract_wasm_profile(
    bytes: &[u8],
    declared_entrypoints: &[&str],
    profile: u32,
) -> Result<ValidatedContractWasm, ContractWasmValidationError> {
    if !matches!(profile, 1 | 2) {
        return Err(ContractWasmValidationError::InvalidModule);
    }
    check_binary_header(bytes)?;
    let entrypoints = validate_declared_entrypoints(declared_entrypoints)?;
    scan_and_bound_module(bytes, &entrypoints, profile)?;

    Validator::new_with_features(admission_wasm_features())
        .validate_all(bytes)
        .map_err(|_| ContractWasmValidationError::InvalidModule)?;

    let config = admission_wasmi_config();
    let engine = Engine::new(&config);
    WasmiModule::new(&engine, bytes).map_err(|_| ContractWasmValidationError::InvalidModule)?;

    Ok(ValidatedContractWasm {
        bytes: bytes.to_vec(),
        entrypoints,
        profile,
    })
}
