//! Literal compatibility controls for ordinary operator input and output.

use super::{
    FlagSet, canonical_flag_u64, hex_lower, parse_canonical_u64, parse_chain,
    parse_decimal_hash_schedule, parse_decimal_hash_suite, parse_domain, parse_epoch,
    parse_hash_suite, parse_hex_32, parse_protocol_version, parse_u64_bounded, parse_validator,
    positive_canonical_flag_u64,
};
use protocol_types::{Epoch, HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule};
use std::ffi::OsString;

#[test]
fn canonical_decimal_preserves_values_and_exact_form_errors() {
    let valid: &[(&str, u64)] = &[("0", 0), ("1", 1), ("18446744073709551615", u64::MAX)];
    for &(input, expected) in valid {
        assert_eq!(parse_canonical_u64(input, "--count").unwrap(), expected);
    }
    let invalid: &[(&str, &str)] = &[
        ("", "invalid --count"),
        ("-1", "invalid --count"),
        (" 1", "invalid --count"),
        ("1 ", "invalid --count"),
        ("18446744073709551616", "invalid --count"),
        ("01", "--count must be canonical unsigned decimal"),
        ("+1", "--count must be canonical unsigned decimal"),
        ("+0", "--count must be canonical unsigned decimal"),
    ];
    for &(input, expected) in invalid {
        assert_eq!(
            parse_canonical_u64(input, "--count")
                .unwrap_err()
                .to_string(),
            expected
        );
    }
}

#[test]
fn canonical_flag_helpers_preserve_consumption_and_error_order() {
    let tokens: Vec<OsString> = ["--count", "0", "--positive", "2"]
        .into_iter()
        .map(OsString::from)
        .collect();
    let mut flags: FlagSet = FlagSet::parse(tokens, &["--count", "--positive"], &[]).unwrap();
    assert_eq!(canonical_flag_u64(&mut flags, "--count").unwrap(), 0);
    assert_eq!(
        positive_canonical_flag_u64(&mut flags, "--positive").unwrap(),
        2
    );
    assert_eq!(
        canonical_flag_u64(&mut flags, "--count")
            .unwrap_err()
            .to_string(),
        "missing required --count"
    );
    flags.finish().unwrap();

    let cases: &[(&[&str], &str)] = &[
        (&[], "missing required --count"),
        (
            &["--count", "bad", "--count", "0"],
            "--count must be supplied exactly once",
        ),
        (&["--count", "bad"], "invalid --count"),
        (
            &["--count", "+0"],
            "--count must be canonical unsigned decimal",
        ),
        (&["--count", "0"], "--count must be positive"),
    ];
    for &(values, expected) in cases {
        let tokens: Vec<OsString> = values
            .iter()
            .map(|value: &&str| OsString::from(*value))
            .collect();
        let mut flags: FlagSet = FlagSet::parse(tokens, &["--count"], &[]).unwrap();
        assert_eq!(
            positive_canonical_flag_u64(&mut flags, "--count")
                .unwrap_err()
                .to_string(),
            expected
        );
        flags.finish().unwrap();
    }
}

#[test]
fn hex_decoder_preserves_mixed_case_zero_and_exact_input_errors() {
    let mixed: &str = "aBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaB";
    assert_eq!(parse_hex_32(mixed, "--value").unwrap(), [0xab; 32]);
    let zero: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(parse_hex_32(zero, "--value").unwrap(), [0; 32]);
    for value in [
        "",
        "00",
        "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        " aBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBa",
    ] {
        assert_eq!(
            parse_hex_32(value, "--value").unwrap_err(),
            "--value must be 64 hex digits"
        );
    }
}

#[test]
fn scalar_parsers_preserve_values_and_decimal_spellings() {
    assert_eq!(
        parse_chain(" edge test ".to_string()).unwrap().as_str(),
        " edge test "
    );
    assert_eq!(parse_protocol_version("+0001").unwrap().get(), 1);
    assert_eq!(
        parse_protocol_version("4294967295").unwrap().get(),
        u32::MAX
    );
    assert_eq!(parse_epoch("0").unwrap().get(), 0);
    assert_eq!(parse_epoch("+0001").unwrap().get(), 1);
    assert_eq!(parse_epoch("18446744073709551615").unwrap().get(), u64::MAX);
    assert_eq!(parse_u64_bounded("+0002", "--limit", 1, 2).unwrap(), 2);
    assert_eq!(parse_u64_bounded("0", "--limit", 0, u64::MAX).unwrap(), 0);
    assert_eq!(
        parse_u64_bounded("18446744073709551615", "--limit", 0, u64::MAX).unwrap(),
        u64::MAX
    );
}

#[test]
fn scalar_parsers_preserve_exact_diagnostics() {
    for value in ["", " ", "\t\n"] {
        assert_eq!(
            parse_chain(value.to_string()).unwrap_err(),
            "invalid --chain-id"
        );
    }
    assert_eq!(
        parse_protocol_version("0").unwrap_err(),
        "zero --protocol-version"
    );
    for value in ["", "-1", " 1", "1 ", "4294967296", "invalid"] {
        assert_eq!(
            parse_protocol_version(value).unwrap_err(),
            "invalid --protocol-version"
        );
    }
    for value in ["", "-1", " 1", "1 ", "18446744073709551616", "invalid"] {
        assert_eq!(parse_epoch(value).unwrap_err(), "invalid --epoch");
        assert_eq!(
            parse_u64_bounded(value, "--limit", 1, 2).unwrap_err(),
            "invalid --limit"
        );
    }
    for value in ["0", "3"] {
        assert_eq!(
            parse_u64_bounded(value, "--limit", 1, 2).unwrap_err(),
            "--limit must be 1..=2"
        );
    }
}

#[test]
fn identifier_parsers_preserve_case_length_and_zero_rules() {
    let uppercase: &str = "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
    assert_eq!(parse_validator(uppercase).unwrap().as_bytes(), &[0xab; 32]);
    assert_eq!(parse_domain(uppercase).unwrap().as_bytes(), &[0xab; 32]);
    let zero: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(parse_validator(zero).unwrap().as_bytes(), &[0; 32]);
    assert_eq!(parse_domain(zero).unwrap_err(), "zero --domain");
    for value in [
        "",
        "00",
        "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
    ] {
        assert_eq!(
            parse_validator(value).unwrap_err(),
            "--validator-id must be 64 hex digits"
        );
        assert_eq!(
            parse_domain(value).unwrap_err(),
            "--domain must be 64 hex digits"
        );
    }
}

#[test]
fn decimal_suite_preserves_field_mapping_and_boundaries() {
    let expected: HashSuiteSchedule = HashSuiteSchedule {
        activation_epoch: Epoch::new(u64::MAX),
        suite: HashSuite {
            id: HashSuiteId::new(u16::MAX),
            transaction_hash: HashAlgorithmId::Sha2_256,
            object_digest: HashAlgorithmId::Sha3_256,
            effects_hash: HashAlgorithmId::Sha2_256,
            code_hash: HashAlgorithmId::Sha3_256,
            config_hash: HashAlgorithmId::Sha2_256,
            certificate_hash: HashAlgorithmId::Sha3_256,
        },
    };
    assert_eq!(
        parse_decimal_hash_suite("18446744073709551615:65535:1:2:1:2:1:2").unwrap(),
        expected
    );
    let alternate: HashSuiteSchedule = HashSuiteSchedule {
        activation_epoch: Epoch::new(0),
        suite: HashSuite {
            id: HashSuiteId::new(1),
            transaction_hash: HashAlgorithmId::Sha2_256,
            object_digest: HashAlgorithmId::Sha3_256,
            effects_hash: HashAlgorithmId::Sha2_256,
            code_hash: HashAlgorithmId::Sha3_256,
            config_hash: HashAlgorithmId::Sha2_256,
            certificate_hash: HashAlgorithmId::Sha3_256,
        },
    };
    assert_eq!(
        parse_decimal_hash_suite("+00:+01:01:+2:+01:02:1:2").unwrap(),
        alternate
    );
}

#[test]
fn decimal_suite_preserves_exact_errors_and_first_error_order() {
    let cases: &[(&str, &str)] = &[
        (
            "bad:0:bad",
            "--suite needs epoch:id:transaction:object:effects:code:config:certificate (decimal wire ids)",
        ),
        (
            "0:1:1:1:1:1:1:1:1",
            "--suite needs epoch:id:transaction:object:effects:code:config:certificate (decimal wire ids)",
        ),
        ("bad:0:bad:1:1:1:1:1", "invalid suite epoch"),
        ("18446744073709551616:1:1:1:1:1:1:1", "invalid suite epoch"),
        ("0:65536:bad:1:1:1:1:1", "invalid suite id"),
        ("0:0:bad:1:1:1:1:1", "zero suite id"),
        ("0:1:bad:3:1:1:1:1", "invalid hash algorithm id"),
        ("0:1:65536:1:1:1:1:1", "invalid hash algorithm id"),
        ("0:1:-1:1:1:1:1:1", "invalid hash algorithm id"),
        ("0:1: 1:1:1:1:1:1", "invalid hash algorithm id"),
        ("0:1:3:bad:1:1:1:1", "unsupported hash algorithm id"),
        ("0:1:0:1:1:1:1:1", "unsupported hash algorithm id"),
        ("0:1:65535:1:1:1:1:1", "unsupported hash algorithm id"),
        ("0:1:1:1:1:1:1:bad", "invalid hash algorithm id"),
    ];
    for &(input, expected) in cases {
        assert_eq!(
            parse_decimal_hash_suite(input).unwrap_err(),
            expected,
            "{input}"
        );
    }
}

#[test]
fn literal_suite_grammar_remains_distinct_from_decimal_wire_ids() {
    assert!(parse_hash_suite("0:1:1:2:1:2:1:2").is_ok());
    for value in ["0:1:01:2:1:2:1:2", "0:1:+1:2:1:2:1:2"] {
        assert!(parse_decimal_hash_suite(value).is_ok());
        assert_eq!(
            parse_hash_suite(value).unwrap_err(),
            "unsupported hash algorithm id"
        );
    }
    assert_eq!(
        parse_hash_suite("0:1:bad:1:1:1:1:1").unwrap_err(),
        "unsupported hash algorithm id"
    );
    assert_eq!(
        parse_hash_suite("0:1:1").unwrap_err(),
        "--suite needs epoch:id:transaction:object:effects:code:config:certificate"
    );
}

#[test]
fn decimal_schedule_preserves_count_checks_and_supplied_order() {
    let empty: Vec<String> = Vec::new();
    assert_eq!(
        parse_decimal_hash_schedule(&empty).unwrap_err(),
        "at least one --suite is required"
    );
    let one: Vec<String> = vec!["0:1:1:1:1:1:1:1".to_string()];
    assert_eq!(parse_decimal_hash_schedule(&one).unwrap().len(), 1);
    let maximum: Vec<String> = vec!["0:1:1:1:1:1:1:1".to_string(); 64];
    assert_eq!(parse_decimal_hash_schedule(&maximum).unwrap().len(), 64);
    let excess: Vec<String> = vec!["bad".to_string(); 65];
    assert_eq!(
        parse_decimal_hash_schedule(&excess).unwrap_err(),
        "too many --suite entries (maximum 64)"
    );
    let supplied: Vec<String> = vec![
        "2:2:1:1:1:1:1:1".to_string(),
        "0:1:2:2:2:2:2:2".to_string(),
        "2:2:1:1:1:1:1:1".to_string(),
    ];
    let parsed: Vec<HashSuiteSchedule> = parse_decimal_hash_schedule(&supplied).unwrap();
    assert_eq!(
        parsed
            .iter()
            .map(|entry: &HashSuiteSchedule| entry.activation_epoch.get())
            .collect::<Vec<u64>>(),
        vec![2, 0, 2]
    );
    assert_eq!(
        parsed
            .iter()
            .map(|entry: &HashSuiteSchedule| entry.suite.id.get())
            .collect::<Vec<u16>>(),
        vec![2, 1, 2]
    );
    let invalid: Vec<String> = vec!["0:1:bad:1:1:1:1:1".to_string(), "bad".to_string()];
    assert_eq!(
        parse_decimal_hash_schedule(&invalid).unwrap_err(),
        "invalid hash algorithm id"
    );
}

#[test]
fn hex_output_preserves_literal_empty_zero_high_and_full_width_values() {
    assert_eq!(hex_lower(&[]), "");
    assert_eq!(hex_lower(&[0, 15, 16, 127, 128, 255]), "000f107f80ff");
    let bytes: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    assert_eq!(
        hex_lower(&bytes),
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
}
