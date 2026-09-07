//! Canonical-file local instance and execution workflow.
use crate::{
    args::{parse_flags, scalar},
    error::CliError,
    hex::decode_hex_32,
    net::{connect_execution, tls_flag_specs},
    parse::parse_u64,
    seed::load_dev_seed,
    signer::{SignerSelection, parse_signer_selection, signer_flag_specs},
};
use std::{
    error::Error,
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    path::Path,
};
use sunrise_edge_client::{call::CallIntent, local_execution::*, *};

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}
fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}
fn read(path: &str, maximum: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes: Vec<u8> = vec![];
    File::open(path)
        .map_err(failure)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() > maximum {
        return Err(invalid("canonical input file too large"));
    }
    Ok(bytes)
}
fn export(path: &str, bytes: &[u8]) -> Result<(), CliError> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(failure)?
        .write_all(bytes)
        .map_err(failure)
}

/// Reserves both destinations before the mutating request; leaves any reserved
/// files in place on failure so callers never overwrite another operation's output.
fn submit_with_outputs(
    result_path: Option<&str>,
    submission_path: Option<&str>,
    submission: &[u8],
    request_id: RequestId,
    nonce: u64,
    submit: impl FnOnce() -> Result<LocalExecutionResult, CliError>,
) -> Result<LocalExecutionResult, CliError> {
    let reserve = |path: &str| -> Result<File, CliError> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(failure)
    };
    let mut result_file: Option<File> = result_path.map(reserve).transpose()?;
    let mut submission_file: Option<File> = submission_path.map(reserve).transpose()?;
    if let Some(file) = &mut submission_file {
        file.write_all(submission).map_err(failure)?;
        file.sync_all().map_err(failure)?;
    }
    println!("request_id={request_id}");
    println!("nonce={nonce}");
    let result: LocalExecutionResult = submit()?;
    if let Some(file) = &mut result_file {
        let recovery = |error: &dyn Error| -> CliError {
            failure(std::io::Error::other(format!(
                "validated execution outcome received but result output failed: {error}; request_id={request_id} nonce={nonce}; replay identical signed bytes with the same request ID and nonce; do not retry with a fresh nonce"
            )))
        };
        let bytes: Vec<u8> =
            encode_local_execution_result(&result).map_err(|error| recovery(&error))?;
        file.write_all(&bytes).map_err(|error| recovery(&error))?;
        file.sync_all().map_err(|error| recovery(&error))?;
    }
    Ok(result)
}

pub(super) fn run<I: IntoIterator<Item = OsString>>(action: &str, args: I) -> Result<(), CliError> {
    let mut specs = vec![
        scalar("--endpoint"),
        scalar("--expected-chain-id"),
        scalar("--expected-protocol-version"),
        scalar("--expected-epoch"),
        scalar("--expected-hash-suite-id"),
        scalar("--expected-domain"),
    ];
    specs.extend(tls_flag_specs());
    if action == "query-instance" {
        specs.extend([
            scalar("--creator"),
            scalar("--instance-seed"),
            scalar("--instance-ref-out"),
        ]);
    } else {
        specs.extend(signer_flag_specs());
        specs.extend([
            scalar("--args"),
            scalar("--type-args"),
            scalar("--gas-limit"),
            scalar("--request-id"),
            scalar("--nonce"),
            scalar("--result-out"),
            scalar("--submission-out"),
        ]);
        if action == "instantiate" {
            specs.extend([scalar("--code-ref"), scalar("--instance-seed")]);
        } else {
            specs.extend([
                scalar("--instance-ref"),
                scalar("--entrypoint"),
                scalar("--access"),
            ]);
        }
    }
    let parsed = parse_flags(args, &specs)?;
    let signer: Option<LocalSigner> = if action == "query-instance" {
        None
    } else {
        match parse_signer_selection(&parsed)? {
            SignerSelection::Local { seed_file } => Some(LocalSigner::from_seed(load_dev_seed(
                Path::new(&seed_file),
            )?)),
            SignerSelection::Ledger { .. } => {
                return Err(invalid("Ledger local execution signing is not supported"));
            }
        }
    };
    let expected: ExpectedProtocolContext = super::transfer::parse_expected_context(&parsed)?;
    let resolver: HashSuiteResolver = local_publication_resolver(&expected)?;
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(failure)?;
    let client = connect_execution(parsed.require("--endpoint")?, &parsed)?;
    client.query_verified_context(&expected)?;
    if action == "query-instance" {
        let creator: [u8; 32] = decode_hex_32("--creator", parsed.require("--creator")?)?;
        let seed: [u8; 32] = decode_hex_32("--instance-seed", parsed.require("--instance-seed")?)?;
        if let Some(record) = client.query_instance(creator, seed, &resolver, &expected)? {
            client.query_executable_interface(&record.code, &resolver, &expected)?;
            if let Some(path) = parsed.get("--instance-ref-out") {
                export(path, &encode_instance_record(&record).map_err(failure)?)?;
            }
            println!("instance_present=true");
            println!("revision={}", record.revision);
            println!(
                "record_digest={}",
                hash_instance_record(&resolver, &record).map_err(failure)?
            );
            println!("code_digest={}", record.code.artifact_digest());
            println!("initializer={}", record.initializer);
        } else {
            println!("instance_present=false");
        }
        return Ok(());
    }
    let signer: LocalSigner = signer.ok_or_else(|| invalid("missing signer"))?;
    let loaded: Option<InstanceRecord> = if action == "call" {
        Some(
            decode_instance_record(&read(parsed.require("--instance-ref")?, 4096)?)
                .map_err(failure)?,
        )
    } else {
        None
    };
    let code: UnverifiedDependencyRef = match &loaded {
        Some(record) => record.code.clone(),
        None => {
            decode_dependency_ref(&read(parsed.require("--code-ref")?, 4096)?).map_err(failure)?
        }
    };
    let interface = client.query_executable_interface(&code, &resolver, &expected)?;
    let initializer: String = interface
        .executable_abi(code.origin())
        .and_then(|metadata| metadata.initializer.clone())
        .ok_or_else(|| invalid("code has no initializer"))?;
    let instance: InstanceRecord = match loaded {
        Some(record) => {
            if client
                .query_instance(record.creator, record.seed, &resolver, &expected)?
                .as_ref()
                != Some(&record)
            {
                return Err(invalid("remote instance differs from pinned instance file"));
            }
            record
        }
        None => InstanceRecord {
            context: context.clone(),
            creator: *signer.address().as_bytes(),
            seed: decode_hex_32("--instance-seed", parsed.require("--instance-seed")?)?,
            code: code.clone(),
            revision: 1,
            initializer: initializer.clone(),
        },
    };
    let access: AccessManifest = if action == "call" {
        decode_access_manifest(
            &read(parsed.require("--access")?, call::MAX_CALL_INTENT_BYTES)?,
            32,
        )
        .map_err(failure)?
    } else {
        AccessManifest::new()
    };
    let type_arguments = if let Some(path) = parsed.get("--type-args") {
        package_types::decode_scoped_type_arguments(expected.chain_id(), &read(path, 32 * 1024)?)
            .map_err(failure)?
    } else {
        vec![]
    };
    let arguments: Vec<u8> = read(parsed.require("--args")?, call::MAX_CALL_ARGUMENT_BYTES)?;
    let request_id: RequestId = RequestId::new(decode_hex_32(
        "--request-id",
        parsed.require("--request-id")?,
    )?)?;
    let nonce: u64 = if let Some(value) = parsed.get("--nonce") {
        parse_u64("--nonce", value)?
    } else {
        let value = client.query_next_nonce(signer.address())?;
        if value.epoch() != expected.epoch() {
            return Err(invalid("nonce epoch differs from expected context"));
        }
        value.next_nonce()
    };
    let mode: LocalExecutionMode = if action == "instantiate" {
        LocalExecutionMode::Instantiate
    } else {
        LocalExecutionMode::Call
    };
    let call: CallIntent = CallIntent {
        context,
        request_id: *request_id.as_bytes(),
        sender: *signer.address().as_bytes(),
        nonce,
        code,
        instance: instance_target(&resolver, &instance).map_err(failure)?,
        entrypoint: if action == "instantiate" {
            initializer
        } else {
            parsed.require("--entrypoint")?.to_owned()
        },
        type_arguments,
        access,
        arguments,
        gas_limit: parse_u64("--gas-limit", parsed.require("--gas-limit")?)?,
    };
    let signed = build_signed_local_execution(
        &signer, &resolver, &expected, mode, call, &instance, &interface,
    )?;
    let result = submit_with_outputs(
        parsed.get("--result-out"),
        parsed.get("--submission-out"),
        &encode_signed_local_execution(&signed).map_err(failure)?,
        request_id,
        nonce,
        || {
            client
                .submit_local_execution(&signed, &resolver, &resolver)
                .map_err(CliError::from)
        },
    )?;
    println!(
        "execution_success={}",
        matches!(result.effects.status, ExecutionStatus::Success)
    );
    println!("gas_used={}", result.effects.gas_used);
    println!(
        "object_effect_count={}",
        result.effects.object_effects.len()
    );
    println!("event_count={}", result.effects.events.len());
    if matches!(result.effects.status, ExecutionStatus::Failure { .. }) {
        return Err(invalid(
            "contract trapped; zero-fee rejection consumed nonce, replay identical bytes",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn existing_result_or_same_output_paths_stop_before_submit() {
        for existing in [true, false] {
            let path = std::env::temp_dir().join(format!(
                "sunrise-output-reservation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            if existing {
                File::options()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"preserve")
                    .unwrap();
            }
            let called = Cell::new(false);
            let name = path.to_str().unwrap();
            let result = submit_with_outputs(
                Some(name),
                if existing { None } else { Some(name) },
                b"signed",
                RequestId::new([3; 32]).unwrap(),
                7,
                || {
                    called.set(true);
                    Err(invalid("unexpected POST"))
                },
            );
            assert!(result.is_err());
            assert!(
                !called.get(),
                "transport POST must not occur before output reservation succeeds"
            );
            assert_eq!(
                std::fs::read(&path).unwrap(),
                if existing {
                    b"preserve".as_slice()
                } else {
                    b"".as_slice()
                }
            );
            std::fs::remove_file(&path).unwrap();
        }
    }
}
