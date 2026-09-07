use execution::{
    ContractWasmValidationError as E, ExecutionEngine, ExecutionStatus, MAX_CONTRACT_WASM_BYTES,
    ValidatedContractWasm, WasmExecutionEngine, validate_contract_wasm,
};
use protocol_types::{Digest32, HashAlgorithmId, ProtocolVersion};

const SIMPLE: &str = "(module (memory (export \"memory\") 1 2) (func (export \"run\")))";

fn validate(wat: &str) -> Result<ValidatedContractWasm, E> {
    let bytes: Vec<u8> = wat::parse_str(wat).unwrap();
    validate_contract_wasm(&bytes, &["run"])
}

#[test]
fn accepts_integer_extensions_and_enforces_function_metadata_boundaries() {
    assert!(
        validate(
            r#"(module
        (type $t (func)) (memory (export "memory") 1 2)
        (table 1 1 funcref) (elem (i32.const 0) $helper)
        (func $helper)
        (func (export "run")
          i32.const 255 i32.extend8_s drop
          i64.const 65535 i64.extend16_s drop
          i32.const 0 i32.const 0 i32.const 0 memory.copy
          i32.const 0 call_indirect (type $t)))"#
        )
        .is_ok()
    );
    for (count, accepted) in [(4096, true), (4097, false)] {
        let source: String = format!(
            "(module (memory (export \"memory\") 1 2) (func (export \"run\") (local {})))",
            "i32 ".repeat(count)
        );
        assert_eq!(validate(&source).is_ok(), accepted, "locals {count}");
        let source: String = format!(
            "(module (memory (export \"memory\") 1 2) (func (export \"run\")) {})",
            "(func)".repeat(count - 1)
        );
        assert_eq!(validate(&source).is_ok(), accepted, "functions {count}");
    }
    for (count, accepted) in [(64, true), (65, false)] {
        let source: String = format!(
            "(module (memory (export \"memory\") 1 2) (func (export \"run\")) (func (param {})))",
            "i64 ".repeat(count)
        );
        assert_eq!(validate(&source).is_ok(), accepted, "parameters {count}");
    }
    let with_import: String = format!(
        "(module (import \"env\" \"abort\" (func (param i32 i32))) (memory (export \"memory\") 1 2) (func (export \"run\")) {})",
        "(func)".repeat(4095)
    );
    assert!(matches!(
        validate(&with_import),
        Err(E::TooManyFunctions { actual: 4097, .. })
    ));
}

#[test]
fn stable_binary_and_declared_names_are_preserved_without_execution() {
    let bytes: Vec<u8> = wat::parse_str(SIMPLE).unwrap();
    assert_eq!(bytes, b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x05\x04\x01\x01\x01\x02\x07\x10\x02\x06memory\x02\0\x03run\0\0\x0a\x04\x01\x02\0\x0b");
    let module: ValidatedContractWasm = validate_contract_wasm(&bytes, &["run"]).unwrap();
    assert_eq!(module.wasm_bytes(), bytes);
    assert_eq!(module.profile_version(), 1);
    let multiple: Vec<u8> = wat::parse_str(
        "(module (memory (export \"memory\") 1 2) (func (export \"z\")) (func (export \"a\")))",
    )
    .unwrap();
    let a: ValidatedContractWasm = validate_contract_wasm(&multiple, &["z", "a"]).unwrap();
    let b: ValidatedContractWasm = validate_contract_wasm(&multiple, &["a", "z"]).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.entrypoints(), &["a", "z"]);
    // A valid entrypoint that would loop forever is inspected, never called.
    assert!(
        validate("(module (memory (export \"memory\") 1 2) (func (export \"run\") (loop br 0)))")
            .is_ok()
    );
}

#[test]
fn names_and_binary_format_fail_closed() {
    let bytes: Vec<u8> = wat::parse_str(SIMPLE).unwrap();
    for names in [
        vec![],
        vec![""],
        vec!["run", "run"],
        vec!["memory"],
        vec!["run"; 65],
    ] {
        assert!(validate_contract_wasm(&bytes, &names).is_err());
    }
    let oversized_name: String = "x".repeat(257);
    assert!(matches!(
        validate_contract_wasm(&bytes, &[&oversized_name]),
        Err(E::InvalidEntrypointName { actual: 257, .. })
    ));
    for malformed in [
        b"".as_slice(),
        b"(module)",
        b"\0asm\x0d\0\x01\0",
        b"\0asm\x02\0\0\0",
    ] {
        assert!(matches!(
            validate_contract_wasm(malformed, &["run"]),
            Err(E::NotCoreWasmBinary)
        ));
    }
    assert!(matches!(
        validate_contract_wasm(&vec![0; MAX_CONTRACT_WASM_BYTES + 1], &["run"]),
        Err(E::TooManyBytes { .. })
    ));
    for end in 0..bytes.len() {
        assert!(
            validate_contract_wasm(&bytes[..end], &["run"]).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing: Vec<u8> = bytes;
    trailing.push(0xff);
    assert!(validate_contract_wasm(&trailing, &["run"]).is_err());
}

#[test]
fn exports_must_match_declarations_and_entrypoint_signature() {
    for module in [
        "(module (memory (export \"memory\") 1 2))",
        "(module (memory (export \"memory\") 1 2) (func (export \"run\") (param i32)))",
        "(module (memory (export \"memory\") 1 2) (func (export \"run\") (result i32) i32.const 0))",
        "(module (memory (export \"memory\") 1 2) (func (export \"run\")) (func (export \"extra\")))",
        "(module (memory (export \"memory\") 1 2) (global (export \"run\") i32 (i32.const 0)))",
        "(module (import \"env\" \"get_args_len\" (func (result i32))) (memory (export \"memory\") 1 2) (export \"run\" (func 0)))",
        "(module (memory (export \"memory\") 1 2) (func (export \"run\")) (global (export \"secret\") i32 (i32.const 0)))",
    ] {
        assert!(validate(module).is_err(), "{module}");
    }
}

#[test]
fn imports_are_closed_including_unused_imports() {
    for import in [
        "(import \"wasi_snapshot_preview1\" \"random_get\" (func (param i32 i32) (result i32)))",
        "(import \"env\" \"unknown\" (func))",
        "(import \"env\" \"get_args_len\" (func (result i64)))",
        "(import \"env\" \"get_args_len\" (func (param i32) (result i32)))",
        "(import \"env\" \"m\" (memory 1 2))",
        "(import \"env\" \"t\" (table 1 2 funcref))",
        "(import \"env\" \"g\" (global i32))",
        "(import \"env\" \"get_args_len\" (func (result i32))) (import \"env\" \"get_args_len\" (func (result i32)))",
    ] {
        let module: String =
            format!("(module {import} (memory (export \"memory\") 1 2) (func (export \"run\")))");
        assert!(validate(&module).is_err(), "{module}");
    }
}

#[test]
fn rejects_start_functions_and_unused_unsupported_instructions() {
    assert_eq!(
        validate(
            "(module (memory (export \"memory\") 1 2) (func $start (loop br 0)) (start $start) (func (export \"run\")))"
        ),
        Err(E::StartFunctionPresent)
    );
    for body in [
        "(func f32.const 0 drop)",
        "(func f64.const 0 drop)",
        "(func (local f64))",
        "(global f32 (f32.const 0))",
        "(func v128.const i32x4 0 0 0 0 drop)",
        "(func ref.null extern drop)",
        "(func (result i32 i32) i32.const 0 i32.const 0)",
    ] {
        let module: String =
            format!("(module (memory (export \"memory\") 1 2) (func (export \"run\")) {body})");
        assert!(validate(&module).is_err(), "{module}");
    }
}

#[test]
fn bounds_memory_and_tables_before_instantiation() {
    for memory in [
        "",
        "(memory 1 2)",
        "(memory (export \"memory\") 1)",
        "(memory (export \"memory\") 1 257)",
        "(memory (export \"memory\") 3 2)",
        "(memory (export \"memory\") 1 2 shared)",
        "(memory (export \"memory\") i64 1 2)",
        "(memory (export \"memory\") 1 2) (memory 1 2)",
    ] {
        assert!(
            validate(&format!("(module {memory} (func (export \"run\")))")).is_err(),
            "{memory}"
        );
    }
    for table in [
        "(table 1 funcref)",
        "(table 1 4097 funcref)",
        "(table 3 2 funcref)",
        "(table 1 2 externref)",
        "(table 1 2 funcref) (table 1 2 funcref)",
    ] {
        assert!(
            validate(&format!(
                "(module (memory (export \"memory\") 1 2) {table} (func (export \"run\")))"
            ))
            .is_err(),
            "{table}"
        );
    }
    assert!(validate("(module (memory (export \"memory\") 0 256) (table 0 4096 funcref) (func (export \"run\")))").is_ok());
}

fn leb(mut value: u32) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        let low: u8 = (value & 0x7f) as u8;
        value >>= 7;
        out.push(if value == 0 { low } else { low | 0x80 });
        if value == 0 {
            return out;
        }
    }
}

fn raw_section(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![id];
    out.extend(leb(u32::try_from(payload.len()).unwrap()));
    out.extend_from_slice(payload);
    out
}

#[test]
fn compressed_count_bombs_are_rejected_before_full_type_or_local_allocation() {
    for (section, limit) in [
        (1, 4096),
        (2, 11),
        (3, 4096),
        (4, 1),
        (5, 1),
        (6, 1024),
        (9, 1024),
        (10, 4096),
        (11, 1024),
        (12, 1024),
    ] {
        let mut bytes: Vec<u8> = b"\0asm\x01\0\0\0".to_vec();
        bytes.extend(raw_section(section, &leb(limit + 1)));
        let error: E = validate_contract_wasm(&bytes, &["run"]).unwrap_err();
        // The parser itself rejects a code count larger than its available
        // body bytes, before exposing CodeSectionStart or allocating bodies.
        if section != 10 {
            assert!(
                !matches!(error, E::InvalidModule),
                "must reject count before missing data: {section}: {error}"
            );
        }
    }
    let mut bytes: Vec<u8> = b"\0asm\x01\0\0\0".to_vec();
    let mut ty: Vec<u8> = vec![1, 0x60];
    ty.extend(leb(u32::MAX));
    bytes.extend(raw_section(1, &ty));
    assert!(matches!(
        validate_contract_wasm(&bytes, &["run"]),
        Err(E::TooManyParams { .. })
    ));
    // A recursion group cannot hide an unbounded subtype count behind one type.
    let mut recursive: Vec<u8> = b"\0asm\x01\0\0\0".to_vec();
    recursive.extend(raw_section(1, &[1, 0x4e, 0xff, 0xff, 0xff, 0xff, 0x0f]));
    assert_eq!(
        validate_contract_wasm(&recursive, &["run"]),
        Err(E::InvalidModule)
    );
    // Replace the empty function body with a tiny encoding for u32::MAX locals.
    let simple: Vec<u8> = wat::parse_str(SIMPLE).unwrap();
    let mut locals: Vec<u8> = simple[..simple.len() - 6].to_vec();
    locals.extend(raw_section(
        10,
        &[1, 8, 1, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x7f, 0x0b],
    ));
    assert!(matches!(
        validate_contract_wasm(&locals, &["run"]),
        Err(E::TooManyFunctionLocals {
            actual: 4294967295,
            ..
        })
    ));
    let mut repeated: Vec<u8> = b"\0asm\x01\0\0\0".to_vec();
    repeated.extend(raw_section(1, &[1, 0x60, 0, 0]));
    repeated.extend(raw_section(1, &[1, 0x60, 0, 0]));
    assert_eq!(
        validate_contract_wasm(&repeated, &["run"]),
        Err(E::InvalidModule)
    );
}

#[test]
fn admitted_host_imports_match_real_engine_and_emit_an_event() {
    let source: &str = r#"(module
      (import "env" "get_object_count" (func (result i32)))
      (import "env" "get_object_data_len" (func (param i32) (result i32)))
      (import "env" "read_object_data" (func (param i32 i32 i32 i32) (result i32)))
      (import "env" "write_object_data" (func (param i32 i32 i32) (result i32)))
      (import "env" "consume_object" (func (param i32) (result i32)))
      (import "env" "create_object" (func (param i32 i32 i32 i32 i32 i32) (result i32)))
      (import "env" "get_object_type_hash" (func (param i32 i32) (result i32)))
      (import "env" "emit_event" (func $emit (param i32 i32 i32 i32) (result i32)))
      (import "env" "get_args_len" (func (result i32)))
      (import "env" "read_args" (func (param i32 i32 i32) (result i32)))
      (import "env" "abort" (func (param i32 i32)))
      (memory (export "memory") 1 2)
      (data (i32.const 0) "testpayload")
      (func (export "run") i32.const 0 i32.const 4 i32.const 4 i32.const 7 call $emit drop))"#;
    let module: ValidatedContractWasm = validate(source).unwrap();
    let effects = WasmExecutionEngine
        .execute(
            ProtocolVersion::new(6),
            Digest32::new(HashAlgorithmId::Sha2_256, [1; 32]),
            module.wasm_bytes(),
            "run",
            &[],
            &[],
            10000,
        )
        .unwrap();
    assert_eq!(effects.status, ExecutionStatus::Success);
    assert_eq!(effects.events.len(), 1);
    assert_eq!(effects.events[0].data, b"payload");
    assert!(effects.object_effects.is_empty());
}
