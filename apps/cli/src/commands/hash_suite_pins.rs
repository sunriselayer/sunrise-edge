//! Strict bounded local schedule flags, not genesis or transport authority.

use std::ffi::OsString;

use sunrise_edge_client::{Epoch, HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule};

use crate::{
    args::{ArgsError, FlagSpec, ParsedArgs, parse_flags},
    error::CliError,
    parse::{parse_u16, parse_u64},
};

const MAX_SUITE_ENTRIES: usize = 64;
const MAX_SUITE_ARGUMENT_BYTES: usize = 256;

fn invalid(message: impl Into<String>) -> CliError {
    CliError::LocalExecution(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    )))
}

/// Only the explicit schedule and declared successor directory lists are
/// repeatable. Scalar pins stay strict before any file access.
pub(super) fn parse_pinned_flags<I: IntoIterator<Item = OsString>>(
    args: I,
    specs: &[FlagSpec],
) -> Result<(ParsedArgs, Vec<HashSuiteSchedule>), CliError> {
    let args: Vec<OsString> = args.into_iter().collect();
    if !args.iter().any(|token: &OsString| token == "--suite") {
        // Keep every historical no-schedule diagnostic and validation order.
        let parsed: ParsedArgs = parse_flags(args, specs)?;
        if super::successor_pins::successor_requested(&parsed) {
            super::successor_pins::successor_budget(&parsed)?;
            return Err(invalid(
                "successor workflows require one to 64 explicit --suite entries for the independently pinned full schedule",
            ));
        }
        return Ok((parsed, Vec::new()));
    }
    let mut scalar_args: Vec<OsString> = Vec::new();
    let mut schedules: Vec<HashSuiteSchedule> = Vec::new();
    let mut iterator = args.into_iter();
    while let Some(token) = iterator.next() {
        if token != "--suite" {
            // A repeatable flag cannot hide inside a missing scalar value.
            // Consume known scalar pairs before extracting schedules, with
            // the same missing-value rule as the ordinary strict parser.
            let scalar_flag: Option<&FlagSpec> = token
                .to_str()
                .and_then(|name: &str| specs.iter().find(|spec| spec.name == name))
                .filter(|spec| spec.takes_value);
            let scalar_value: Option<OsString> = if let Some(spec) = scalar_flag {
                let value: OsString = iterator.next().ok_or(ArgsError::MissingValue(spec.name))?;
                if value
                    .to_str()
                    .is_some_and(|text: &str| text.starts_with("--"))
                {
                    return Err(ArgsError::MissingValue(spec.name).into());
                }
                Some(value)
            } else {
                None
            };
            scalar_args.push(token);
            if let Some(value) = scalar_value {
                scalar_args.push(value);
            }
            continue;
        }
        let value: OsString = iterator.next().ok_or(ArgsError::MissingValue("--suite"))?;
        let value: &str = value.to_str().ok_or(ArgsError::NonUtf8Value("--suite"))?;
        if value.starts_with("--") {
            return Err(ArgsError::MissingValue("--suite").into());
        }
        if schedules.len() == MAX_SUITE_ENTRIES {
            return Err(invalid("at most 64 --suite entries are accepted"));
        }
        schedules.push(parse_suite(value)?);
    }
    let parsed: ParsedArgs = parse_flags(scalar_args, specs)?;
    if super::successor_pins::successor_requested(&parsed) {
        super::successor_pins::successor_budget(&parsed)?;
    }
    Ok((parsed, schedules))
}

/// A complete locally configured schedule, with the declared current suite
/// checked independently. An endpoint cannot choose this resolver.
pub(super) fn publication_resolver(
    expected: &sunrise_edge_client::ExpectedProtocolContext,
    schedules: Vec<HashSuiteSchedule>,
) -> Result<sunrise_edge_client::HashSuiteResolver, CliError> {
    if schedules.is_empty() {
        return sunrise_edge_client::local_publication_resolver(expected)
            .map_err(|error| CliError::LocalExecution(Box::new(error)));
    }
    let resolver: sunrise_edge_client::HashSuiteResolver =
        sunrise_edge_client::HashSuiteResolver::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            schedules,
        )
        .map_err(|error| CliError::LocalExecution(Box::new(error)))?;
    if resolver
        .suite_for_epoch(expected.epoch())
        .map_err(|error| CliError::LocalExecution(Box::new(error)))?
        .id
        != expected.hash_suite_id()
    {
        return Err(invalid(
            "--expected-hash-suite-id differs from the independently pinned current hash suite",
        ));
    }
    Ok(resolver)
}

fn parse_suite(value: &str) -> Result<HashSuiteSchedule, CliError> {
    if value.len() > MAX_SUITE_ARGUMENT_BYTES {
        return Err(invalid("--suite exceeds its bounded argument size"));
    }
    let fields: Vec<&str> = value.split(':').collect();
    if fields.len() != 8 {
        return Err(invalid(
            "--suite needs epoch:id:transaction:object:effects:code:config:certificate",
        ));
    }
    let epoch: Epoch = Epoch::new(parse_u64("--suite", fields[0])?);
    let id: u16 = parse_u16("--suite", fields[1])?;
    if id == 0 {
        return Err(invalid("--suite id must be nonzero"));
    }
    let algorithm = |index: usize| -> Result<HashAlgorithmId, CliError> {
        match fields[index] {
            "1" => Ok(HashAlgorithmId::Sha2_256),
            "2" => Ok(HashAlgorithmId::Sha3_256),
            _ => Err(invalid("unsupported --suite hash algorithm id")),
        }
    };
    Ok(HashSuiteSchedule {
        activation_epoch: epoch,
        suite: HashSuite {
            id: HashSuiteId::new(id),
            transaction_hash: algorithm(2)?,
            object_digest: algorithm(3)?,
            effects_hash: algorithm(4)?,
            code_hash: algorithm(5)?,
            config_hash: algorithm(6)?,
            certificate_hash: algorithm(7)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::scalar;

    const FLAGS: &[FlagSpec] = &[scalar("--request-id"), scalar("--out")];

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn suite_repetition_does_not_relax_other_flags_or_unused_inputs() {
        let values: Vec<OsString> = args(&[
            "--suite",
            "0:1:1:1:1:1:1:1",
            "--suite",
            "2:2:2:2:2:2:2:2",
            "--request-id",
            "request",
        ]);
        let (parsed, schedules) = parse_pinned_flags(values, FLAGS).unwrap();
        assert_eq!(schedules.len(), 2);
        assert_eq!(parsed.require("--request-id").unwrap(), "request");
        for values in [
            args(&["--endpoint", "unused"]),
            args(&["--request-id", "one", "--request-id", "two"]),
            args(&["--suite", "--out", "unused"]),
            args(&["--suite", "0:0:1:1:1:1:1:1"]),
            args(&["--suite", "0:1:3:1:1:1:1:1"]),
            args(&["--request-id", "--suite", "0:1:1:1:1:1:1:1", "request"]),
        ] {
            assert!(parse_pinned_flags(values, FLAGS).is_err());
        }
    }

    #[test]
    fn suite_count_bytes_and_integer_bounds_do_not_truncate() {
        for value in ["0:65536:1:1:1:1:1:1", "18446744073709551616:1:1:1:1:1:1:1"] {
            assert!(parse_suite(value).is_err());
        }
        assert!(parse_suite(&"x".repeat(MAX_SUITE_ARGUMENT_BYTES + 1)).is_err());
        let values: Vec<OsString> = (0..=MAX_SUITE_ENTRIES)
            .flat_map(|_| [OsString::from("--suite"), OsString::from("0:1:1:1:1:1:1:1")])
            .collect();
        assert!(parse_pinned_flags(values, FLAGS).is_err());
    }

    #[test]
    fn absent_suite_preserves_original_duplicate_flag_error_order() {
        let error: CliError =
            parse_pinned_flags(args(&["--request-id", "one", "--request-id"]), FLAGS).unwrap_err();
        assert!(matches!(
            error,
            CliError::Args(ArgsError::DuplicateFlag("--request-id"))
        ));
    }
}
