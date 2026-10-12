//! Real maintained age controls and independent LOCAL framing/quota vectors.
//! Pure transport vectors are not business-proof or custody qualification.
use super::*;
use envelope::Entry;
use sha2::{Digest, Sha256};
use std::{
    io::{self, Cursor, Read, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use transport::{CipherPhase, CipherReader, PlainReader};

fn encrypted(bytes: &[u8], identity: &age::x25519::Identity) -> Vec<u8> {
    let recipient: age::x25519::Recipient = identity.to_public();
    let mut output: Vec<u8> = Vec::new();
    let mut writer: age::stream::StreamWriter<&mut Vec<u8>> = transport::encryptor(&recipient)
        .unwrap()
        .wrap_output(&mut output)
        .unwrap();
    writer.write_all(bytes).unwrap();
    writer.finish().unwrap();
    output
}

struct ObservedInput {
    cursor: Cursor<Vec<u8>>,
    zeros: Arc<AtomicUsize>,
    errors: bool,
}
impl Read for ObservedInput {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.errors {
            return Err(io::Error::other("AGE-SECRET-KEY-1-secret-like-IO"));
        }
        assert!(
            !bytes.is_empty(),
            "zero-size read must not stand for physical EOF"
        );
        let count: usize = self.cursor.read(bytes)?;
        if count == 0 {
            self.zeros.fetch_add(1, Ordering::SeqCst);
        }
        Ok(count)
    }
}

#[test]
fn real_age_exact_cipher_cap_short_full64k_and_multichunk_need_pre_auth_and_later_physical_zero() {
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    for size in [1usize, 23, 65536, 65537, 131072] {
        let original: Vec<u8> = vec![0x6b; size];
        let bytes: Vec<u8> = encrypted(&original, &identity);
        let limits: RecoveryLimits = RecoveryLimits {
            ciphertext_bytes: bytes.len() as u64,
            plaintext_bytes: size as u64,
            ..RecoveryLimits::default()
        };
        let budget: ArchiveReadBudget = limits.budget().unwrap();
        let zeros: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let input: ObservedInput = ObservedInput {
            cursor: Cursor::new(bytes),
            zeros: Arc::clone(&zeros),
            errors: false,
        };
        let phase: CipherPhase = CipherPhase::header();
        let mut cipher: CipherReader<'_, ObservedInput> =
            CipherReader::new(input, &phase, &budget, &limits);
        {
            let decrypted = transport::decrypt(&mut cipher, &phase, &identity).unwrap();
            let mut plain = PlainReader::new(decrypted, limits.plaintext_bytes, &budget);
            let mut actual: Vec<u8> = Vec::new();
            plain.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, original);
            assert_eq!(plain.observed(), size as u64);
            plain.authenticated_eof().unwrap();
        }
        // This zero happened while age retained the reader, not solely as a
        // post-authentication observation. The later probe must be ADDITIONAL.
        let before: usize = zeros.load(Ordering::SeqCst);
        assert!(before > 0);
        assert!(cipher.physical_zeros() > 0);
        assert_eq!(cipher.observed(), limits.ciphertext_bytes);
        cipher.physical_eof().unwrap();
        assert_eq!(zeros.load(Ordering::SeqCst), before + 1);
        assert_eq!(cipher.observed(), limits.ciphertext_bytes);
    }
}

#[test]
fn cap_plus_one_is_counted_never_delivered_and_permanently_refused_before_auth() {
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    for size in [17usize, 65536] {
        let original: Vec<u8> = vec![0x73; size];
        let mut bytes: Vec<u8> = encrypted(&original, &identity);
        let exact: u64 = bytes.len() as u64;
        bytes.push(0x91);
        let limits: RecoveryLimits = RecoveryLimits {
            ciphertext_bytes: exact,
            ..RecoveryLimits::default()
        };
        let budget: ArchiveReadBudget = limits.budget().unwrap();
        let phase: CipherPhase = CipherPhase::header();
        let mut cipher = CipherReader::new(Cursor::new(bytes), &phase, &budget, &limits);
        {
            let mut decrypted = transport::decrypt(&mut cipher, &phase, &identity).unwrap();
            let mut actual: Vec<u8> = Vec::new();
            assert!(decrypted.read_to_end(&mut actual).is_err());
            assert!(actual.len() <= original.len());
        }
        assert_eq!(cipher.observed(), exact + 1);
        assert!(cipher.physical_eof().is_err());
        assert!(cipher.read(&mut [0; 1]).is_err());
    }
}

#[test]
fn header_exhaustion_never_returns_synthetic_zero_and_has_no_phase_reset() {
    let limits: RecoveryLimits = RecoveryLimits {
        header_bytes: 9,
        ciphertext_bytes: 100,
        ..RecoveryLimits::default()
    };
    let budget: ArchiveReadBudget = limits.budget().unwrap();
    let phase: CipherPhase = CipherPhase::header();
    let mut cipher = CipherReader::new(Cursor::new(vec![0x41; 10]), &phase, &budget, &limits);
    assert_eq!(cipher.read(&mut [0; 9]).unwrap(), 9);
    assert_eq!(cipher.observed(), 9);
    assert!(cipher.read(&mut [0; 1]).is_err());
    assert_eq!(cipher.physical_zeros(), 0);
    assert!(cipher.read(&mut [0; 1]).is_err());
}

#[test]
fn exact_cipher_cap_real_probe_io_error_refuses_before_authentication_opaquely() {
    struct ProbeFailure(Cursor<Vec<u8>>);
    impl Read for ProbeFailure {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.0.position() == self.0.get_ref().len() as u64 {
                Err(io::Error::other("AGE-SECRET-KEY-1-secret-like-cap-probe"))
            } else {
                self.0.read(bytes)
            }
        }
    }
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    let bytes: Vec<u8> = encrypted(&[0x41; 23], &identity);
    let limits: RecoveryLimits = RecoveryLimits {
        ciphertext_bytes: bytes.len() as u64,
        ..RecoveryLimits::default()
    };
    let budget: ArchiveReadBudget = limits.budget().unwrap();
    let phase: CipherPhase = CipherPhase::header();
    let mut cipher: CipherReader<'_, ProbeFailure> =
        CipherReader::new(ProbeFailure(Cursor::new(bytes)), &phase, &budget, &limits);
    {
        let mut decrypted: age::stream::StreamReader<&mut CipherReader<'_, ProbeFailure>> =
            transport::decrypt(&mut cipher, &phase, &identity).unwrap();
        let error: io::Error = decrypted.read_to_end(&mut Vec::new()).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("AGE-SECRET-KEY"));
    }
    assert_eq!(cipher.observed(), limits.ciphertext_bytes);
    assert_eq!(cipher.physical_zeros(), 0);
    assert!(cipher.physical_eof().is_err());
    assert!(cipher.read(&mut [0; 1]).is_err());
}

#[test]
fn real_age_wrong_key_tamper_truncation_concatenation_and_plain_cap_refuse() {
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    let wrong: age::x25519::Identity = age::x25519::Identity::generate();
    let original: Vec<u8> = encrypted(&vec![0x5a; 65536], &identity);
    let mut tampered: Vec<u8> = original.clone();
    let last: usize = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut concat: Vec<u8> = original.clone();
    concat.extend_from_slice(&original);
    for (bytes, key, plain_cap) in [
        (original.clone(), &wrong, 65536u64),
        (tampered, &identity, 65536),
        (original[..last].to_vec(), &identity, 65536),
        (concat, &identity, 65536),
        (original.clone(), &identity, 65535),
    ] {
        let limits: RecoveryLimits = RecoveryLimits {
            ciphertext_bytes: bytes.len() as u64,
            ..RecoveryLimits::default()
        };
        let budget: ArchiveReadBudget = limits.budget().unwrap();
        let phase: CipherPhase = CipherPhase::header();
        let mut cipher = CipherReader::new(Cursor::new(bytes), &phase, &budget, &limits);
        let result: Result<(), RecoveryError> = (|| {
            {
                let decrypted = transport::decrypt(&mut cipher, &phase, key)?;
                let mut plain = PlainReader::new(decrypted, plain_cap, &budget);
                let mut buffer: [u8; 1024] = [0; 1024];
                loop {
                    if plain
                        .read(&mut buffer)
                        .map_err(|_| RecoveryError::Transport)?
                        == 0
                    {
                        break;
                    }
                }
                plain.authenticated_eof()?;
            }
            cipher.physical_eof()
        })();
        assert!(result.is_err());
    }
}

#[test]
fn opaque_io_age_input_and_all_error_channels_never_retain_secret_like_text() {
    let secret: &str = "AGE-SECRET-KEY-1-secret-like-IO";
    let limits: RecoveryLimits = RecoveryLimits::default();
    let budget: ArchiveReadBudget = limits.budget().unwrap();
    let phase: CipherPhase = CipherPhase::header();
    let input: ObservedInput = ObservedInput {
        cursor: Cursor::new(Vec::new()),
        zeros: Arc::new(AtomicUsize::new(0)),
        errors: true,
    };
    let mut cipher = CipherReader::new(input, &phase, &budget, &limits);
    let error: io::Error = cipher.read(&mut [0; 1]).unwrap_err();
    assert!(!format!("{error} {error:?}").contains(secret));
    if let Some(source) = error.source() {
        assert!(!source.to_string().contains(secret));
    }
    for error in [
        RecoveryError::InvalidInput,
        RecoveryError::Quota,
        RecoveryError::Inventory,
        RecoveryError::Transport,
        RecoveryError::Attachment,
        RecoveryError::Proof,
        RecoveryError::Publication,
        RecoveryError::Unsupported,
    ] {
        assert!(!format!("{error} {error:?}").contains(secret));
        assert!(error.source().is_none());
    }
    assert!(transport::parse_recipient(secret).is_err());
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    assert!(transport::decrypt(&mut cipher, &phase, &identity).is_err());
}

fn literal_entries(links: u16) -> Vec<Entry> {
    Role::required(links)
        .unwrap()
        .into_iter()
        .map(|role: Role| Entry {
            role,
            name: match role.tag {
                1 => "genesis.bin",
                2 | 4 | 6 => "identity.bin",
                3 | 5 => "identity.bin",
                7 => "certificate.bin",
                _ => unreachable!(),
            }
            .to_owned(),
            length: 1,
            hash: [role.tag; 32],
        })
        .collect()
}

#[test]
fn manifest_ceiling_accounting_round_trip_all_seven_roles() {
    let limits: RecoveryLimits = RecoveryLimits::default();
    for links in [0u16, 1, 16] {
        let entries: Vec<Entry> = literal_entries(links);
        let manifest: Manifest = Manifest::encode(links, entries.clone(), &limits).unwrap();
        let roles: usize = 3 + 4 * links as usize;
        let payload: usize = 16
            + 7 * roles
            + entries
                .iter()
                .map(|entry: &Entry| 45 + entry.name.len())
                .sum::<usize>();
        assert_eq!(manifest.record.len(), payload + 5);
        assert_eq!(manifest.control, (68 + payload + 17 * entries.len()) as u64);
        assert_eq!(manifest.plaintext, manifest.control + entries.len() as u64);
        assert_eq!(&manifest.record[5..7], &links.to_be_bytes());
        assert_eq!(&manifest.record[7..9], &(roles as u16).to_be_bytes());
        assert_eq!(
            &manifest.record[9..13],
            &(entries.len() as u32).to_be_bytes()
        );
        assert_eq!(
            &manifest.record[13..21],
            &(entries.len() as u64).to_be_bytes()
        );
        let mut encoded_prefix: Vec<u8> = b"SE-RECOVERY\0\0\x01".to_vec();
        encoded_prefix.extend_from_slice(&manifest.record);
        let read: Manifest =
            Manifest::read(&mut Cursor::new(encoded_prefix), links, &limits).unwrap();
        assert_eq!(read, manifest);
        let footer: [u8; 49] = manifest.footer().unwrap();
        assert_eq!(&footer[..5], &[3, 0, 0, 0, 44]);
        assert_eq!(&footer[5..9], &(entries.len() as u32).to_be_bytes());
        assert_eq!(&footer[9..17], &(entries.len() as u64).to_be_bytes());
        assert_eq!(&footer[17..], &manifest.hash);
        let first: [u8; 17] = envelope::file_header(0, &entries[0]).unwrap();
        assert_eq!(&first[..9], &[2, 0, 0, 0, 13, 0, 0, 0, 0]);
        assert_eq!(&first[9..], &1u64.to_be_bytes());
    }
}

#[test]
fn independently_constructed_complete_l0_manifest_literal_matches_exact_bytes() {
    let manifest: Manifest =
        Manifest::encode(0, literal_entries(0), &RecoveryLimits::default()).unwrap();
    let mut literal: Vec<u8> = vec![
        1, 0, 0, 0, 207, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3,
    ];
    literal.extend_from_slice(&[
        1, 255, 255, 0, 0, 0, 1, 2, 255, 255, 0, 0, 0, 1, 3, 255, 255, 0, 0, 0, 1,
    ]);
    for (tag, name, length) in [
        (1u8, "genesis.bin", 11u8),
        (2, "identity.bin", 12),
        (3, "identity.bin", 12),
    ] {
        literal.extend_from_slice(&[tag, 255, 255, 0, length]);
        literal.extend_from_slice(name.as_bytes());
        literal.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        literal.extend_from_slice(&[tag; 32]);
    }
    assert_eq!(literal.len(), 212);
    assert_eq!(manifest.record, literal);
    assert_eq!(manifest.control, 326);
    assert_eq!(manifest.plaintext, 329);
}

#[test]
fn independently_constructed_complete_l1_manifest_files_and_footer_match_exact_bytes() {
    // The seven roles and link indices are independent input, not Role::required.
    // Bodies/hash fields are opaque LOCAL layout markers, not business proofs.
    let entries: Vec<Entry> = [
        (
            Role {
                tag: 1,
                link: 65535,
            },
            "genesis.bin",
        ),
        (
            Role {
                tag: 2,
                link: 65535,
            },
            "identity.bin",
        ),
        (
            Role {
                tag: 3,
                link: 65535,
            },
            "identity.bin",
        ),
        (Role { tag: 4, link: 0 }, "identity.bin"),
        (Role { tag: 5, link: 0 }, "identity.bin"),
        (Role { tag: 6, link: 0 }, "identity.bin"),
        (Role { tag: 7, link: 0 }, "certificate.bin"),
    ]
    .into_iter()
    .map(|(role, name): (Role, &str)| Entry {
        role,
        name: name.to_owned(),
        length: 1,
        hash: [role.tag; 32],
    })
    .collect();
    // Fixed M=466, L=1, R=7, N=7, B=7, then seven literal descriptors.
    let mut literal: Vec<u8> = vec![
        1, 0, 0, 1, 210, 0, 1, 0, 7, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 7, 1, 255, 255, 0, 0, 0, 1,
        2, 255, 255, 0, 0, 0, 1, 3, 255, 255, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 1,
        6, 0, 0, 0, 0, 0, 1, 7, 0, 0, 0, 0, 0, 1,
    ];
    let literal_fields: [(u8, u8, u8, &str, u8); 7] = [
        (1, 255, 255, "genesis.bin", 11),
        (2, 255, 255, "identity.bin", 12),
        (3, 255, 255, "identity.bin", 12),
        (4, 0, 0, "identity.bin", 12),
        (5, 0, 0, "identity.bin", 12),
        (6, 0, 0, "identity.bin", 12),
        (7, 0, 0, "certificate.bin", 15),
    ];
    for (tag, high, low, name, length) in literal_fields {
        literal.extend_from_slice(&[tag, high, low, 0, length]);
        literal.extend_from_slice(name.as_bytes());
        literal.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        literal.extend_from_slice(&[tag; 32]);
    }
    assert_eq!(literal.len(), 471);
    // Independently fixed SHA256 of the above 471 original record bytes.
    let expected_hash: [u8; 32] = [
        0x06, 0xdc, 0x76, 0x08, 0x41, 0x57, 0x3a, 0xe6, 0x53, 0x6c, 0x91, 0x65, 0x4c, 0x89, 0x82,
        0x9a, 0x17, 0x03, 0x99, 0x4a, 0x3b, 0xc0, 0x6a, 0x0f, 0xa7, 0x20, 0xa2, 0xc8, 0x36, 0x04,
        0x72, 0x14,
    ];
    let limits: RecoveryLimits = RecoveryLimits::default();
    let manifest: Manifest = Manifest::encode(1, entries.clone(), &limits).unwrap();
    assert_eq!(manifest.record, literal);
    assert_eq!(manifest.hash, expected_hash);
    assert_eq!(
        (manifest.control, manifest.plaintext, manifest.bodies),
        (653, 660, 7)
    );
    let mut framed: Vec<u8> = b"SE-RECOVERY\0\0\x01".to_vec();
    framed.extend_from_slice(&literal);
    let decoded: Manifest = Manifest::read(&mut Cursor::new(&framed), 1, &limits).unwrap();
    assert_eq!(decoded.entries, entries);
    assert_eq!(decoded.record, literal);
    assert_eq!(decoded.hash, expected_hash);
    assert_eq!(
        (decoded.control, decoded.plaintext, decoded.bodies),
        (653, 660, 7)
    );
    let expected_headers: [[u8; 17]; 7] = [
        [2, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [2, 0, 0, 0, 13, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1],
        [2, 0, 0, 0, 13, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1],
        [2, 0, 0, 0, 13, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1],
        [2, 0, 0, 0, 13, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1],
        [2, 0, 0, 0, 13, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 1],
        [2, 0, 0, 0, 13, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1],
    ];
    let mut expected_footer: [u8; 49] = [0; 49];
    expected_footer[..17].copy_from_slice(&[3, 0, 0, 0, 44, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 7]);
    expected_footer[17..].copy_from_slice(&expected_hash);
    assert_eq!(manifest.footer().unwrap(), expected_footer);
    assert_eq!(decoded.footer().unwrap(), expected_footer);
    // Compare every File index and the entire 660-byte prefix/files/footer.
    let mut actual: Vec<u8> = Vec::new();
    manifest.write_prefix(&mut actual).unwrap();
    for (index, entry) in entries.iter().enumerate() {
        let header: [u8; 17] = envelope::file_header(index, entry).unwrap();
        assert_eq!(header, expected_headers[index]);
        framed.extend_from_slice(&expected_headers[index]);
        framed.push(entry.role.tag);
        actual.extend_from_slice(&header);
        actual.push(entry.role.tag);
    }
    framed.extend_from_slice(&expected_footer);
    actual.extend_from_slice(&manifest.footer().unwrap());
    assert_eq!(framed.len(), 660);
    assert_eq!(actual, framed);
    // Alter independent claims, role/link/count descriptors and entry link.
    let mutations: [(usize, u8); 9] = [
        (6, 0),
        (8, 8),
        (12, 8),
        (20, 8),
        (37, 0),
        (44, 1),
        (63, 6),
        (69, 0),
        (242, 1),
    ];
    for (offset, value) in mutations {
        let mut changed: Vec<u8> = b"SE-RECOVERY\0\0\x01".to_vec();
        let mut record: Vec<u8> = literal.clone();
        record[offset] = value;
        changed.extend_from_slice(&record);
        assert!(Manifest::read(&mut Cursor::new(changed), 1, &limits).is_err());
    }
}

#[test]
fn manifest_order_duplicates_link_roles_generated_names_counts_and_control_caps_refuse() {
    let limits: RecoveryLimits = RecoveryLimits::default();
    let entries: Vec<Entry> = literal_entries(1);
    let mut wrong: Vec<Entry> = entries.clone();
    wrong.swap(0, 1);
    assert!(Manifest::encode(1, wrong, &limits).is_err());
    let mut wrong: Vec<Entry> = entries.clone();
    wrong[0].name = "../secret".into();
    assert!(Manifest::encode(1, wrong, &limits).is_err());
    let mut wrong: Vec<Entry> = entries.clone();
    wrong.push(entries[6].clone());
    assert!(Manifest::encode(1, wrong, &limits).is_err());
    let mut wrong: Vec<Entry> = entries.clone();
    wrong[3].role.link = 1;
    assert!(Manifest::encode(1, wrong, &limits).is_err());
    assert!(Manifest::encode(1, entries[..6].to_vec(), &limits).is_err());
    let manifest: Manifest = Manifest::encode(1, entries.clone(), &limits).unwrap();
    let low: RecoveryLimits = RecoveryLimits {
        control_bytes: manifest.control - 1,
        ..limits.clone()
    };
    assert!(Manifest::encode(1, entries, &low).is_err());
    let mut bytes: Vec<u8> = Vec::new();
    manifest.write_prefix(&mut bytes).unwrap();
    let mut control_input: Cursor<Vec<u8>> = Cursor::new(bytes.clone());
    assert!(Manifest::read(&mut control_input, 1, &low).is_err());
    assert_eq!(
        control_input.position(),
        35,
        "fixed claims refuse before reading/allocating the Manifest's variable payload"
    );
    for offset in [0usize, 13, 14, 21, 23, 27, 30] {
        let mut wrong: Vec<u8> = bytes.clone();
        wrong[offset] ^= 0x80;
        assert!(Manifest::read(&mut Cursor::new(wrong), 1, &limits).is_err());
    }
    assert!(Manifest::read(&mut Cursor::new(bytes.clone()), 0, &limits).is_err());
    assert!(
        Manifest::read(
            &mut Cursor::new(bytes[..bytes.len() - 1].to_vec()),
            1,
            &limits
        )
        .is_err()
    );
}

#[test]
fn command_mode_closed_flags_duplicate_quota_and_role_budget_refuse_before_any_io() {
    for values in [
        vec![],
        vec!["activate"],
        vec!["pack-saved", "--identity-file", "/must-not-open"],
        vec!["open-saved", "--genesis-manifest", "/must-not-open"],
        vec!["open-saved", "--expected-links", "17"],
        vec![
            "pack-saved",
            "--expected-links",
            "0",
            "--recipient",
            "AGE-SECRET-KEY-1-secret",
        ],
    ] {
        assert_eq!(
            run(values.into_iter().map(OsString::from)),
            Err(RecoveryError::InvalidInput)
        );
    }
    let mut parsed: FlagSet =
        FlagSet::parse(["--max-files", "32769"].map(OsString::from), LIMITS, &[]).unwrap();
    assert!(RecoveryLimits::parse(&mut parsed).is_err());
    let mut parsed: FlagSet = FlagSet::parse(
        ["--timeout-seconds", "301"].map(OsString::from),
        LIMITS,
        &[],
    )
    .unwrap();
    assert!(RecoveryLimits::parse(&mut parsed).is_err());
    let mut parsed: FlagSet = FlagSet::parse(
        ["--max-files", "1", "--max-files", "1"].map(OsString::from),
        LIMITS,
        &[],
    )
    .unwrap();
    assert!(RecoveryLimits::parse(&mut parsed).is_err());
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf =
            std::env::temp_dir().join(format!("recovery-owner-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove only this test's exclusive temporary root");
    }
}
#[cfg(unix)]
fn private_identity(path: &Path, bytes: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn bounded_identity_private_modes_single_line_no_follow_links_and_opaque_errors() {
    use age::secrecy::ExposeSecret;
    let directory: Directory = Directory::new();
    let path: PathBuf = directory.0.join("identity");
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    let recipient: age::x25519::Recipient = identity.to_public();
    let secret = identity.to_string();
    for mode in [0o400u32, 0o600] {
        private_identity(&path, secret.expose_secret().as_bytes(), mode);
        let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
        let loaded: LoadedIdentity = transport::read_identity(&path, &recipient, &budget).unwrap();
        assert!(loaded.identity.to_public() == recipient);
        loaded.ensure_attached().unwrap();
        let mut line: zeroize::Zeroizing<Vec<u8>> =
            zeroize::Zeroizing::new(secret.expose_secret().as_bytes().to_vec());
        line.push(b'\n');
        private_identity(&path, &line, mode);
        assert!(transport::read_identity(&path, &recipient, &budget).is_ok());
    }
    let marker: &[u8] = b"AGE-SECRET-KEY-1-secret-like-private-input";
    for bytes in [
        Vec::new(),
        marker.to_vec(),
        vec![b'X'; 1025],
        b"one\ntwo".to_vec(),
        b"one\r\n".to_vec(),
        vec![0xff],
    ] {
        private_identity(&path, &bytes, 0o600);
        let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
        let error: RecoveryError = transport::read_identity(&path, &recipient, &budget)
            .err()
            .unwrap();
        assert!(!format!("{error} {error:?}").contains("AGE-SECRET-KEY"));
        assert!(error.source().is_none());
    }
    private_identity(&path, secret.expose_secret().as_bytes(), 0o644);
    assert!(
        transport::read_identity(
            &path,
            &recipient,
            &RecoveryLimits::default().budget().unwrap()
        )
        .is_err()
    );
    private_identity(&path, secret.expose_secret().as_bytes(), 0o600);
    let alias: PathBuf = directory.0.join("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(
        transport::read_identity(
            &path,
            &recipient,
            &RecoveryLimits::default().budget().unwrap()
        )
        .is_err()
    );
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(
        transport::read_identity(
            &alias,
            &recipient,
            &RecoveryLimits::default().budget().unwrap()
        )
        .is_err()
    );
    let wrong: age::x25519::Identity = age::x25519::Identity::generate();
    assert!(
        transport::read_identity(
            &path,
            &wrong.to_public(),
            &RecoveryLimits::default().budget().unwrap()
        )
        .is_err()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn raw_history_capture_names_keep_generated_directory_markers_for_the_defining_owner() {
    let directory: Directory = Directory::new();
    let history: PathBuf = directory.0.join("history");
    let component: PathBuf = history.join("height-00000000000000000001/component-01");
    std::fs::create_dir_all(&component).unwrap();
    for name in [
        "identity.bin",
        "height-00000000000000000001/descriptor.bin",
        "height-00000000000000000001/component-01/chunk-00000000000000000000.bin",
    ] {
        std::fs::write(history.join(name), [1]).unwrap();
    }
    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let source: SourceRole = SourceRole::archive(
        Role {
            tag: 2,
            link: u16::MAX,
        },
        &history,
        &budget,
    )
    .unwrap();
    let names: std::collections::BTreeSet<String> = source.names().unwrap();
    assert_eq!(names.len(), 5);
    assert!(names.contains("height-00000000000000000001/"));
    assert!(names.contains("height-00000000000000000001/component-01/"));
    assert!(
        names.contains("height-00000000000000000001/component-01/chunk-00000000000000000000.bin")
    );
    // This is an actual nested inventory/capture-name control, not a proof
    // qualification: malformed bodies still fail the later defining verifier.
    std::fs::create_dir(history.join("height-1")).unwrap();
    assert!(
        source.names().is_err(),
        "a noncanonical height directory cannot be silently omitted"
    );
    std::fs::remove_dir(history.join("height-1")).unwrap();
    std::fs::create_dir(history.join("height-00000000000000000001/component-99")).unwrap();
    assert!(
        source.names().is_err(),
        "an unknown component directory refuses"
    );
    std::fs::remove_dir(history.join("height-00000000000000000001/component-99")).unwrap();
    for surplus in [
        "height-00000000000000000002",
        "height-00000000000000000001/component-02",
    ] {
        assert_eq!(source.names().unwrap(), names);
        let path: PathBuf = history.join(surplus);
        std::fs::create_dir(&path).unwrap();
        assert!(
            source.names().is_err(),
            "canonical surplus empty directories cannot be cleaned out of capture"
        );
        std::fs::remove_dir(&path).unwrap();
        assert_eq!(source.names().unwrap(), names);
    }
}

#[test]
#[cfg(target_os = "linux")]
fn output_overlap_placement_refuses_before_any_stage_or_cipher_creation() {
    let directory: Directory = Directory::new();
    let history: PathBuf = directory.0.join("history");
    std::fs::create_dir(&history).unwrap();
    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let source: SourceRole = SourceRole::archive(
        Role {
            tag: 2,
            link: u16::MAX,
        },
        &history,
        &budget,
    )
    .unwrap();
    let nested: PathBuf = history.join("out");
    let absent: AbsentOutput = AbsentOutput::new(&nested, &budget).unwrap();
    assert!(source.outside(&absent).is_err());
    assert!(!nested.exists());
    let same: PathBuf = directory.0.join("same");
    let first: AbsentOutput = AbsentOutput::new(&same, &budget).unwrap();
    let second: AbsentOutput = AbsentOutput::new(&same, &budget).unwrap();
    assert!(files::distinct(&first, &second).is_err());
    assert!(!same.exists());
    for recipient in [
        "ssh-ed25519 invalid",
        "age1plugin-unselected",
        "AGE-SECRET-KEY-1-not-a-recipient",
    ] {
        assert!(transport::parse_recipient(recipient).is_err());
    }
}

#[cfg(target_os = "linux")]
fn full_role_sources(
    directory: &Directory,
    budget: &ArchiveReadBudget,
) -> (Vec<SourceRole>, usize) {
    // Filesystem mechanics only: the small literal bodies are not signed
    // histories, a verified successor chain, or a qualified recovery package.
    let source: PathBuf = directory.0.join("source");
    std::fs::create_dir(&source).unwrap();
    let genesis: PathBuf = source.join("genesis.bin");
    std::fs::write(&genesis, [0x61]).unwrap();
    let roles: Vec<Role> = Role::required(8).unwrap();
    assert_eq!(roles.len(), 35);
    let mut sources: Vec<SourceRole> = Vec::new();
    let mut expected_files: usize = 0;
    for role in roles {
        if role.tag == 1 {
            sources.push(SourceRole::genesis(&genesis, budget).unwrap());
            expected_files += 1;
            continue;
        }
        let root: PathBuf = role.root(&source).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let names: Vec<&str> = match role.tag {
            2 | 4 | 6 => vec!["identity.bin", "chunk-size.bin", "complete"],
            3 | 5 => vec![
                "identity.bin",
                "package.bin",
                "transfer.bin",
                "source-token.bin",
                "complete",
            ],
            7 => vec!["certificate.bin"],
            _ => panic!("closed generated role"),
        };
        for name in names {
            std::fs::write(root.join(name), [role.tag]).unwrap();
            expected_files += 1;
        }
        let heights: u64 = match role.tag {
            2 => 15,
            4 => u64::from(role.link) * 2 + 1,
            6 => u64::from(role.link) * 2 + 2,
            _ => 0,
        };
        for height in 1..=heights {
            let height_root: PathBuf = root.join(format!("height-{height:020}"));
            std::fs::create_dir(&height_root).unwrap();
            std::fs::write(height_root.join("descriptor.bin"), [role.tag]).unwrap();
            expected_files += 1;
            for kind in 1..=6_u16 {
                let component: PathBuf = height_root.join(format!("component-{kind:02}"));
                std::fs::create_dir(&component).unwrap();
                let name: &str = "chunk-00000000000000000000.bin";
                assert!(
                    role.file_limit(&format!("height-{height:020}/component-{kind:02}/{name}"))
                        .is_ok()
                );
                std::fs::write(component.join(name), [role.tag]).unwrap();
                expected_files += 1;
            }
        }
        sources.push(SourceRole::archive(role, &root, budget).unwrap());
    }
    (sources, expected_files)
}

#[test]
#[cfg(target_os = "linux")]
fn full_thirtyfive_role_capture_keeps_generated_history_inventory_with_default_budget() {
    let directory: Directory = Directory::new();
    let limits: RecoveryLimits = RecoveryLimits::default();
    let budget: ArchiveReadBudget = limits.budget().unwrap();
    let (sources, expected_files): (Vec<SourceRole>, usize) =
        full_role_sources(&directory, &budget);
    let capture: PathBuf = directory.0.join("capture");
    let mut stage: PrivateStage =
        PrivateStage::create(&AbsentOutput::new(&capture, &budget).unwrap(), &budget).unwrap();
    let result: Result<envelope::Manifest, RecoveryError> = stage.capture(&sources, 8, &limits);
    let live: bool = budget.check().is_ok();
    let manifest: envelope::Manifest = result.unwrap_or_else(|error: RecoveryError| {
        panic!("35-role capture refused: {error:?}, original_budget_live={live}, captured={:?}/{expected_files}", stage.capture_counts_for_test())
    });
    assert_eq!(manifest.entries.len(), expected_files);
    stage.check(&manifest).unwrap();
    for entry in &manifest.entries {
        assert_eq!(entry.length, 1);
        let mut body: Vec<u8> = Vec::new();
        stage.write_body(&mut body, entry).unwrap();
        let expected: u8 = if entry.role.tag == 1 {
            0x61
        } else {
            entry.role.tag
        };
        assert_eq!(body, [expected]);
        assert_eq!(entry.hash, <[u8; 32]>::from(Sha256::digest([expected])));
    }
    assert!(budget.check().is_ok());
    assert!(!capture.join(envelope::COMPLETE).exists());

    // Exercise all actual filesystem terminal passes with maintained age.
    // No defining business verifier is invoked for these skeleton bytes.
    stage.check(&manifest).unwrap();
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    let ciphertext: PathBuf = directory.0.join("saved.age");
    let mut publication: CipherPublication =
        CipherPublication::create(AbsentOutput::new(&ciphertext, &budget).unwrap(), &budget)
            .unwrap();
    let counted: CipherWriter<'_, &mut std::fs::File> =
        CipherWriter::new(publication.writer(), &budget, limits.ciphertext_bytes);
    let mut writer: age::stream::StreamWriter<CipherWriter<'_, &mut std::fs::File>> =
        transport::encryptor(&identity.to_public())
            .unwrap()
            .wrap_output(counted)
            .unwrap();
    manifest.write_prefix(&mut writer).unwrap();
    let mut expected: Vec<u8> = Vec::new();
    manifest.write_prefix(&mut expected).unwrap();
    for (index, entry) in manifest.entries.iter().enumerate() {
        let header: [u8; 17] = envelope::file_header(index, entry).unwrap();
        writer.write_all(&header).unwrap();
        stage.write_body(&mut writer, entry).unwrap();
        expected.extend_from_slice(&header);
        expected.push(if entry.role.tag == 1 {
            0x61
        } else {
            entry.role.tag
        });
    }
    let footer: [u8; 49] = manifest.footer().unwrap();
    writer.write_all(&footer).unwrap();
    expected.extend_from_slice(&footer);
    let finished: Result<(u64, [u8; 32]), RecoveryError> = writer
        .finish()
        .map(|counted: CipherWriter<'_, &mut std::fs::File>| counted.observation())
        .map_err(|_| RecoveryError::Transport);
    let counts: PackedDiagnosticCounts = finish_pack_publication(
        finished,
        &mut stage,
        publication,
        &manifest,
        &footer,
        limits.ciphertext_bytes,
        &budget,
    )
    .unwrap();
    assert_eq!(counts.links, 8);
    assert_eq!(counts.files, expected_files);
    assert_eq!(
        std::fs::read(capture.join(envelope::COMPLETE)).unwrap(),
        footer
    );
    let input: AttachedRegularFile = AttachedRegularFile::open(
        &ciphertext,
        limits.ciphertext_bytes,
        &budget,
        AttachedFilePolicy::public(),
    )
    .unwrap();
    let phase: CipherPhase = CipherPhase::header();
    let mut cipher: CipherReader<'_, AttachedRegularFile> =
        CipherReader::new(input, &phase, &budget, &limits);
    let mut actual: Vec<u8> = Vec::new();
    {
        let decrypted: age::stream::StreamReader<&mut CipherReader<'_, AttachedRegularFile>> =
            transport::decrypt(&mut cipher, &phase, &identity).unwrap();
        let mut plain: PlainReader<'_, _> =
            PlainReader::new(decrypted, limits.plaintext_bytes, &budget);
        plain.read_to_end(&mut actual).unwrap();
        plain.authenticated_eof().unwrap();
    }
    cipher.physical_eof().unwrap();
    assert_eq!(actual, expected);
    assert!(budget.check().is_ok());
}

#[test]
#[cfg(target_os = "linux")]
fn full_thirtyfive_role_capture_former_observation_limit_refuses_all_clones_without_completion() {
    let directory: Directory = Directory::new();
    let limits: RecoveryLimits = RecoveryLimits {
        observations: 262_144,
        ..RecoveryLimits::default()
    };
    let budget: ArchiveReadBudget = limits.budget().unwrap();
    let sibling: ArchiveReadBudget = budget.clone();
    let (sources, expected_files): (Vec<SourceRole>, usize) =
        full_role_sources(&directory, &budget);
    let capture: PathBuf = directory.0.join("capture");
    let mut stage: PrivateStage =
        PrivateStage::create(&AbsentOutput::new(&capture, &budget).unwrap(), &budget).unwrap();
    let error: RecoveryError = stage.capture(&sources, 8, &limits).unwrap_err();
    assert_eq!(classify_failure(error, &budget), RecoveryError::Quota);
    assert!(budget.check().is_err());
    assert!(sibling.check().is_err());
    assert!(stage.capture_counts_for_test().0 < expected_files);
    assert!(!capture.join(envelope::COMPLETE).exists());
}

#[test]
fn recovery_failure_preserves_live_categories_and_reports_shared_refusal_opaquely() {
    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    for error in [
        RecoveryError::Attachment,
        RecoveryError::Inventory,
        RecoveryError::Proof,
        RecoveryError::Transport,
    ] {
        assert_eq!(classify_failure(error, &budget), error);
    }
    let sibling: ArchiveReadBudget = budget.clone();
    let _refusal: io::Error = sibling.refuse();
    for error in [
        RecoveryError::Attachment,
        RecoveryError::Inventory,
        RecoveryError::Proof,
        RecoveryError::Transport,
    ] {
        let actual: RecoveryError = classify_failure(error, &budget);
        assert_eq!(actual, RecoveryError::Quota);
        assert_eq!(
            format!("{actual} {actual:?}"),
            "recovery quota refused recovery quota refused"
        );
        assert!(actual.source().is_none());
    }
}

#[cfg(target_os = "linux")]
fn prefix_stage(directory: &Directory, budget: &ArchiveReadBudget) -> (PrivateStage, Entry) {
    let path: PathBuf = directory.0.join("capture");
    let mut stage: PrivateStage =
        PrivateStage::create(&AbsentOutput::new(&path, budget).unwrap(), budget).unwrap();
    let entry: Entry = Entry {
        role: Role {
            tag: 2,
            link: u16::MAX,
        },
        name: "identity.bin".to_owned(),
        length: 1,
        hash: Sha256::digest([0x67]).into(),
    };
    stage.receive(&mut Cursor::new([0x67]), &entry).unwrap();
    let mut original: Vec<u8> = Vec::new();
    stage.write_body(&mut original, &entry).unwrap();
    assert_eq!(original, [0x67]);
    (stage, entry)
}

#[test]
#[cfg(target_os = "linux")]
fn staged_prefix_replacement_refuses_even_when_final_child_inode_is_preserved() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let directory: Directory = Directory::new();
    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let (stage, entry): (PrivateStage, Entry) = prefix_stage(&directory, &budget);
    let prefix: PathBuf = stage.root().join("current");
    let child: PathBuf = prefix.join("history");
    let original: std::fs::Metadata = std::fs::metadata(&child).unwrap();
    let saved: PathBuf = stage.root().join("original-current");
    std::fs::rename(&prefix, &saved).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&prefix)
        .unwrap();
    std::fs::rename(saved.join("history"), &child).unwrap();
    let actual: std::fs::Metadata = std::fs::metadata(&child).unwrap();
    assert_eq!(
        (actual.dev(), actual.ino()),
        (original.dev(), original.ino())
    );
    let mut exposed: Vec<u8> = Vec::new();
    assert_eq!(
        stage.write_body(&mut exposed, &entry),
        Err(RecoveryError::Attachment)
    );
    assert!(exposed.is_empty());
    assert!(budget.check().is_ok());
    assert!(!stage.root().join(envelope::COMPLETE).exists());
}

#[test]
#[cfg(target_os = "linux")]
fn staged_root_and_prefix_symlink_type_or_mode_changes_refuse_before_body_exposure() {
    use std::os::unix::fs::PermissionsExt;
    for case in [
        "prefix-symlink",
        "root-symlink",
        "prefix-file",
        "prefix-mode",
        "root-mode",
    ] {
        let directory: Directory = Directory::new();
        let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
        let (mut stage, entry): (PrivateStage, Entry) = prefix_stage(&directory, &budget);
        let changed: PathBuf = if matches!(case, "root-symlink" | "root-mode") {
            stage.root().to_path_buf()
        } else {
            stage.root().join("current")
        };
        if matches!(case, "prefix-mode" | "root-mode") {
            std::fs::set_permissions(&changed, std::fs::Permissions::from_mode(0o755)).unwrap();
        } else {
            let saved: PathBuf = directory.0.join("original-prefix");
            std::fs::rename(&changed, &saved).unwrap();
            if case == "prefix-file" {
                std::fs::write(&changed, b"not a directory").unwrap();
            } else {
                std::os::unix::fs::symlink(&saved, &changed).unwrap();
            }
        }
        let mut exposed: Vec<u8> = Vec::new();
        assert_eq!(
            stage.write_body(&mut exposed, &entry),
            Err(RecoveryError::Attachment),
            "{case}"
        );
        assert!(exposed.is_empty(), "{case}");
        let attempted: Entry = Entry {
            role: Role {
                tag: 3,
                link: u16::MAX,
            },
            ..entry
        };
        let mut input: Cursor<[u8; 1]> = Cursor::new([0x67]);
        assert_eq!(
            stage.receive(&mut input, &attempted),
            Err(RecoveryError::Attachment),
            "{case}"
        );
        assert_eq!(input.position(), 0, "{case}");
        assert!(budget.check().is_ok());
        assert!(!stage.root().join(envelope::COMPLETE).exists());
    }
}

#[test]
#[cfg(target_os = "linux")]
fn staged_unknown_preexisting_directory_is_not_adopted_by_held_parent_creation() {
    use std::os::unix::fs::DirBuilderExt;
    let directory: Directory = Directory::new();
    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let capture: PathBuf = directory.0.join("capture");
    let mut stage: PrivateStage =
        PrivateStage::create(&AbsentOutput::new(&capture, &budget).unwrap(), &budget).unwrap();
    let foreign: PathBuf = capture.join("current");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&foreign)
        .unwrap();
    let sentinel: PathBuf = foreign.join("sentinel");
    std::fs::write(&sentinel, b"retain unknown material").unwrap();
    let entry: Entry = Entry {
        role: Role {
            tag: 2,
            link: u16::MAX,
        },
        name: "identity.bin".to_owned(),
        length: 1,
        hash: Sha256::digest([0x67]).into(),
    };
    assert_eq!(
        stage.receive(&mut Cursor::new([0x67]), &entry),
        Err(RecoveryError::Publication)
    );
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"retain unknown material"
    );
    assert!(!foreign.join("history").exists());
    assert!(!capture.join(envelope::COMPLETE).exists());
}

#[test]
#[cfg(target_os = "linux")]
fn staged_downward_budget_refusal_prevents_later_parent_creation_or_body_reads() {
    let directory: Directory = Directory::new();
    let limits: RecoveryLimits = RecoveryLimits {
        observations: 4096,
        ..RecoveryLimits::default()
    };
    let budget: ArchiveReadBudget = limits.budget().unwrap();
    let (mut stage, original): (PrivateStage, Entry) = prefix_stage(&directory, &budget);
    let original_path: PathBuf = stage.root().join("current/history/identity.bin");
    let mut original_file: std::fs::File = std::fs::File::open(&original_path).unwrap();
    let before: std::fs::Metadata = original_file.metadata().unwrap();
    let sibling: ArchiveReadBudget = budget.clone();
    assert!(sibling.charge_observations(4096).is_err());
    let entry: Entry = Entry {
        role: Role {
            tag: 3,
            link: u16::MAX,
        },
        ..original
    };
    let mut input: Cursor<[u8; 1]> = Cursor::new([0x67]);
    assert_eq!(stage.receive(&mut input, &entry), Err(RecoveryError::Quota));
    assert_eq!(input.position(), 0);
    assert!(budget.check().is_err());
    assert!(sibling.check().is_err());
    assert!(!stage.root().join("current/cut").exists());
    assert!(!stage.root().join(envelope::COMPLETE).exists());
    // Only this original preheld fixture descriptor observes the retained byte.
    let mut actual: [u8; 1] = [0];
    original_file.read_exact(&mut actual).unwrap();
    assert_eq!(actual, [0x67]);
    let mut probe: [u8; 1] = [0];
    assert_eq!(original_file.read(&mut probe).unwrap(), 0);
    let after: std::fs::Metadata = original_file.metadata().unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.uid(),
            before.nlink(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec()
        ),
        (
            after.dev(),
            after.ino(),
            after.mode(),
            after.uid(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        )
    );
}

#[test]
#[cfg(target_os = "linux")]
fn exclusive_equal_existing_refusal_streamed_hash_publication_and_owned_incomplete_residue() {
    use sha2::{Digest, Sha256};
    let directory: Directory = Directory::new();
    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let output: PathBuf = directory.0.join("cipher");
    let bytes: Vec<u8> = vec![0x6c; 65537];
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    let absent: AbsentOutput = AbsentOutput::new(&output, &budget).unwrap();
    let mut publication: CipherPublication = CipherPublication::create(absent, &budget).unwrap();
    publication.writer().write_all(&bytes).unwrap();
    publication
        .publish(bytes.len() as u64, hash, bytes.len() as u64)
        .unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
    assert!(AbsentOutput::new(&output, &budget).is_err()); // Even identical.
    assert!(!CipherPublication::pending_path(&output).unwrap().exists());
    let failed: PathBuf = directory.0.join("failed-cipher");
    let mut publication: CipherPublication =
        CipherPublication::create(AbsentOutput::new(&failed, &budget).unwrap(), &budget).unwrap();
    publication.writer().write_all(&bytes).unwrap();
    assert!(
        publication
            .publish(bytes.len() as u64, [0; 32], bytes.len() as u64)
            .is_err()
    );
    assert!(!failed.exists());
    assert_eq!(
        std::fs::read(CipherPublication::pending_path(&failed).unwrap()).unwrap(),
        bytes
    );
    assert!(
        CipherPublication::create(AbsentOutput::new(&failed, &budget).unwrap(), &budget).is_err(),
        "owned failed pending file is never adopted on retry"
    );
    let stage_path: PathBuf = directory.0.join("stage");
    let _stage: PrivateStage =
        PrivateStage::create(&AbsentOutput::new(&stage_path, &budget).unwrap(), &budget).unwrap();
    assert!(AbsentOutput::new(&stage_path, &budget).is_err());
    assert!(!stage_path.join(envelope::COMPLETE).exists());
}

#[test]
#[cfg(target_os = "linux")]
fn staged_full_stamps_hashes_surplus_directory_and_late64k_mutation_refuse_without_diagnostic() {
    let directory: Directory = Directory::new();
    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let stage_path: PathBuf = directory.0.join("stage");
    let mut stage: PrivateStage =
        PrivateStage::create(&AbsentOutput::new(&stage_path, &budget).unwrap(), &budget).unwrap();
    let mut entry: Entry = Entry {
        role: Role {
            tag: 1,
            link: u16::MAX,
        },
        name: "genesis.bin".to_owned(),
        length: 65537,
        hash: [0; 32],
    };
    use sha2::{Digest, Sha256};
    let bytes: Vec<u8> = vec![0x41; 65537];
    entry.hash = Sha256::digest(&bytes).into();
    stage
        .receive(&mut Cursor::new(bytes.clone()), &entry)
        .unwrap();
    stage.write_body(&mut std::io::sink(), &entry).unwrap();
    let path: PathBuf = stage_path.join("genesis/genesis.bin");
    let mut wrong: Vec<u8> = bytes;
    wrong[65536] ^= 1;
    std::fs::write(&path, wrong).unwrap();
    assert!(
        stage.write_body(&mut std::io::sink(), &entry).is_err(),
        "complete stamp and full streamed body checks reach beyond64KiB"
    );
    assert!(!stage_path.join(envelope::COMPLETE).exists());
    // Inventory is not only files: an unexpected empty directory refuses.
    std::fs::create_dir(stage_path.join("foreign")).unwrap();
    let manifest: Manifest = Manifest {
        links: 0,
        entries: vec![entry],
        bodies: 65537,
        control: 0,
        plaintext: 0,
        record: Vec::new(),
        hash: [0; 32],
    };
    assert!(stage.check(&manifest).is_err());
    assert!(!stage_path.join(envelope::COMPLETE).exists());
}

#[test]
#[cfg(target_os = "linux")]
fn local_file_footer_framing_hash_index_trailing_data_and_quotas_have_no_completion_oracle() {
    use sha2::{Digest, Sha256};
    let limits: RecoveryLimits = RecoveryLimits::default();
    let mut entries: Vec<Entry> = literal_entries(0);
    for entry in &mut entries {
        entry.hash = Sha256::digest([entry.role.tag]).into();
    }
    let manifest: Manifest = Manifest::encode(0, entries, &limits).unwrap();
    let mut frame: Vec<u8> = Vec::new();
    manifest.write_prefix(&mut frame).unwrap();
    let first: usize = frame.len();
    for (index, entry) in manifest.entries.iter().enumerate() {
        frame.extend_from_slice(&envelope::file_header(index, entry).unwrap());
        frame.push(entry.role.tag);
    }
    let footer: usize = frame.len();
    frame.extend_from_slice(&manifest.footer().unwrap());
    assert_eq!(frame.len() as u64, manifest.plaintext);
    let directory: Directory = Directory::new();
    for (case, changed) in std::iter::once(("positive", frame.clone())).chain([
        ("unknown-file-tag", {
            let mut data = frame.clone();
            data[first] = 9;
            data
        }),
        ("wrong-record-length", {
            let mut data = frame.clone();
            data[first + 4] ^= 1;
            data
        }),
        ("reordered-index", {
            let mut data = frame.clone();
            data[first + 8] = 1;
            data
        }),
        ("body-hash", {
            let mut data = frame.clone();
            data[first + 17] ^= 1;
            data
        }),
        ("footer-hash", {
            let mut data = frame.clone();
            data[footer + 48] ^= 1;
            data
        }),
        ("footer-count", {
            let mut data = frame.clone();
            data[footer + 8] ^= 1;
            data
        }),
        ("trailing-record", {
            let mut data = frame.clone();
            data.push(3);
            data
        }),
        ("truncated-footer", frame[..frame.len() - 1].to_vec()),
    ]) {
        let budget: ArchiveReadBudget = limits.budget().unwrap();
        let path: PathBuf = directory.0.join(case);
        let mut stage: PrivateStage =
            PrivateStage::create(&AbsentOutput::new(&path, &budget).unwrap(), &budget).unwrap();
        let mut plain = PlainReader::new(Cursor::new(changed), manifest.plaintext, &budget);
        let result: Result<(), RecoveryError> = (|| {
            let (actual, actual_footer) = envelope::receive(&mut plain, &mut stage, 0, &limits)?;
            plain.authenticated_eof()?;
            assert_eq!(actual, manifest);
            assert_eq!(actual_footer, manifest.footer().unwrap());
            Ok(())
        })();
        if case == "positive" {
            assert!(result.is_ok());
            stage.check(&manifest).unwrap();
        } else {
            assert!(result.is_err(), "{case}");
        }
        // Even the structurally positive vector has NO business proofs and
        // therefore NO diagnostic; a parser result is not qualification.
        assert!(!path.join(envelope::COMPLETE).exists());
    }
    let low: RecoveryLimits = RecoveryLimits {
        plaintext_bytes: manifest.plaintext - 1,
        ..limits
    };
    assert!(Manifest::encode(0, manifest.entries, &low).is_err());
}

#[test]
fn ciphertext_writer_real_cap_and_secret_like_io_failures_are_opaque_and_permanent() {
    struct Failing;
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("AGE-SECRET-KEY-1-failing-write"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("AGE-SECRET-KEY-1-failing-flush"))
        }
    }
    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let mut failed = transport::CipherWriter::new(Failing, &budget, 100);
    let error: io::Error = failed.write(&[1]).unwrap_err();
    assert!(!format!("{error} {error:?}").contains("AGE-SECRET-KEY"));
    assert!(failed.flush().is_err());
    assert!(failed.write(&[1]).is_err());
    let mut output: Vec<u8> = Vec::new();
    let mut capped = transport::CipherWriter::new(&mut output, &budget, 3);
    assert_eq!(capped.write(&[1, 2, 3]).unwrap(), 3);
    assert!(capped.write(&[4]).is_err());
    assert!(capped.flush().is_err());
    drop(capped);
    assert_eq!(output, [1, 2, 3]);
}

#[test]
fn ciphertext_writer_accepts_repeated_short_writes_through_real_age_finish_and_round_trip() {
    struct ShortSink {
        accepted: Arc<Mutex<Vec<u8>>>,
        maximum_write: usize,
        calls: Arc<AtomicUsize>,
    }
    impl Write for ShortSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.is_empty() {
                return Ok(0);
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            let written: usize = bytes.len().min(self.maximum_write);
            self.accepted
                .lock()
                .map_err(|_| io::Error::other("local test sink poisoned"))?
                .extend_from_slice(&bytes[..written]);
            Ok(written)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    let recipient: age::x25519::Recipient = identity.to_public();
    let plaintext: Vec<u8> = (0..4097usize)
        .map(|index: usize| (index.wrapping_mul(37) & 0xff) as u8)
        .collect();
    let accepted: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let sink: ShortSink = ShortSink {
        accepted: Arc::clone(&accepted),
        maximum_write: 7,
        calls: Arc::clone(&calls),
    };
    let mut cipher: transport::CipherWriter<'_, ShortSink> =
        transport::CipherWriter::new(sink, &budget, 1_000_000);
    {
        let mut age_writer: age::stream::StreamWriter<&mut transport::CipherWriter<'_, ShortSink>> =
            transport::encryptor(&recipient)
                .unwrap()
                .wrap_output(&mut cipher)
                .unwrap();
        age_writer.write_all(&plaintext).unwrap();
        age_writer.finish().unwrap();
    }
    let encrypted: Vec<u8> = accepted
        .lock()
        .map_err(|_| io::Error::other("local test sink poisoned"))
        .unwrap()
        .clone();
    assert!(calls.load(Ordering::SeqCst) > 1);
    let (observed, digest): (u64, [u8; 32]) = cipher.observation();
    assert_eq!(observed, encrypted.len() as u64);
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&encrypted)));

    let limits: RecoveryLimits = RecoveryLimits {
        ciphertext_bytes: encrypted.len() as u64,
        plaintext_bytes: plaintext.len() as u64,
        ..RecoveryLimits::default()
    };
    let read_budget: ArchiveReadBudget = limits.budget().unwrap();
    let phase: CipherPhase = CipherPhase::header();
    let mut reader: CipherReader<'_, Cursor<Vec<u8>>> =
        CipherReader::new(Cursor::new(encrypted), &phase, &read_budget, &limits);
    let mut actual: Vec<u8> = Vec::new();
    {
        let decrypted: age::stream::StreamReader<&mut CipherReader<'_, Cursor<Vec<u8>>>> =
            transport::decrypt(&mut reader, &phase, &identity).unwrap();
        let mut plain: PlainReader<
            '_,
            age::stream::StreamReader<&mut CipherReader<'_, Cursor<Vec<u8>>>>,
        > = PlainReader::new(decrypted, limits.plaintext_bytes, &read_budget);
        plain.read_to_end(&mut actual).unwrap();
        plain.authenticated_eof().unwrap();
    }
    assert_eq!(actual, plaintext);
    reader.physical_eof().unwrap();
}

#[test]
fn ciphertext_writer_nonempty_write_zero_is_opaque_and_permanently_refused() {
    struct ZeroSink {
        calls: Arc<AtomicUsize>,
    }
    impl Write for ZeroSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(0)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let mut writer: transport::CipherWriter<'_, ZeroSink> = transport::CipherWriter::new(
        ZeroSink {
            calls: Arc::clone(&calls),
        },
        &budget,
        32,
    );
    assert_eq!(writer.write(&[]).unwrap(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let error: io::Error = writer.write(b"nonempty").unwrap_err();
    assert!(!format!("{error} {error:?}").contains("SECRET"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(writer.write(b"again").is_err());
    assert!(writer.flush().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let (observed, digest): (u64, [u8; 32]) = writer.observation();
    assert_eq!(observed, 0);
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&[] as &[u8])));
}

#[test]
fn ciphertext_writer_short_write_budget_refusal_counts_only_accepted_prefix() {
    struct RefusingShortSink {
        accepted: Arc<Mutex<Vec<u8>>>,
        calls: Arc<AtomicUsize>,
        budget: ArchiveReadBudget,
    }
    impl Write for RefusingShortSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            assert!(!bytes.is_empty());
            self.calls.fetch_add(1, Ordering::SeqCst);
            let written: usize = bytes.len().min(3);
            self.accepted
                .lock()
                .unwrap()
                .extend_from_slice(&bytes[..written]);
            let _: io::Error = self.budget.refuse();
            Ok(written)
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("the refused writer must not flush its sink")
        }
    }

    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let accepted: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let sink: RefusingShortSink = RefusingShortSink {
        accepted: Arc::clone(&accepted),
        calls: Arc::clone(&calls),
        budget: budget.clone(),
    };
    let mut writer: transport::CipherWriter<'_, RefusingShortSink> =
        transport::CipherWriter::new(sink, &budget, 128);
    let input: &[u8] = b"independent ciphertext bytes";
    let error: io::Error = writer.write(input).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "recovery transport refused");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(*accepted.lock().unwrap(), input[..3]);
    assert!(budget.check().is_err());
    assert!(writer.write(b"later").is_err());
    assert!(writer.flush().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let (observed, digest): (u64, [u8; 32]) = writer.observation();
    assert_eq!(observed, 3);
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&input[..3])));
}

#[test]
fn ciphertext_writer_partial_progress_then_error_preserves_exact_prefix_and_latches() {
    struct PartialThenError {
        accepted: Arc<Mutex<Vec<u8>>>,
        offered_first: Arc<Mutex<Vec<u8>>>,
        calls: Arc<AtomicUsize>,
        first_write: usize,
    }
    impl Write for PartialThenError {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let call: usize = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                self.offered_first
                    .lock()
                    .map_err(|_| io::Error::other("local test sink poisoned"))?
                    .extend_from_slice(bytes);
                let written: usize = bytes.len().min(self.first_write);
                self.accepted
                    .lock()
                    .map_err(|_| io::Error::other("local test sink poisoned"))?
                    .extend_from_slice(&bytes[..written]);
                Ok(written)
            } else {
                Err(io::Error::other("AGE-SECRET-KEY-1-short-write-error"))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let accepted: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let offered_first: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let mut writer: transport::CipherWriter<'_, PartialThenError> = transport::CipherWriter::new(
        PartialThenError {
            accepted: Arc::clone(&accepted),
            offered_first: Arc::clone(&offered_first),
            calls: Arc::clone(&calls),
            first_write: 5,
        },
        &budget,
        128,
    );
    let input: &[u8] = b"independent deterministic cipher bytes";
    let error: io::Error = writer.write_all(input).unwrap_err();
    assert!(!format!("{error} {error:?}").contains("AGE-SECRET-KEY"));
    let expected_prefix: Vec<u8> = input[..5].to_vec();
    assert_eq!(*accepted.lock().unwrap(), expected_prefix);
    assert_eq!(*offered_first.lock().unwrap(), input);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(writer.write(b"later").is_err());
    assert_eq!(*accepted.lock().unwrap(), input[..5]);
    let (observed, digest): (u64, [u8; 32]) = writer.observation();
    assert_eq!(observed, 5);
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&input[..5])));
}

#[test]
fn real_age_finish_final_chunk_write_failure_is_opaque_and_never_completes() {
    struct FinishState {
        accepted: Vec<u8>,
        reject_writes: bool,
        rejected_write_calls: usize,
    }
    struct FinishSink {
        state: Arc<Mutex<FinishState>>,
    }
    impl Write for FinishSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut state: std::sync::MutexGuard<'_, FinishState> = self
                .state
                .lock()
                .map_err(|_| io::Error::other("local test sink poisoned"))?;
            if state.reject_writes {
                state.rejected_write_calls += 1;
                return Err(io::Error::other("AGE-SECRET-KEY-1-final-chunk-failure"));
            }
            state.accepted.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    let recipient: age::x25519::Recipient = identity.to_public();
    let state: Arc<Mutex<FinishState>> = Arc::new(Mutex::new(FinishState {
        accepted: Vec::new(),
        reject_writes: false,
        rejected_write_calls: 0,
    }));
    let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
    let sink: FinishSink = FinishSink {
        state: Arc::clone(&state),
    };
    let mut cipher: transport::CipherWriter<'_, FinishSink> =
        transport::CipherWriter::new(sink, &budget, 1_000_000);
    let finish_error: Option<io::Error>;
    {
        let mut age_writer: age::stream::StreamWriter<
            &mut transport::CipherWriter<'_, FinishSink>,
        > = transport::encryptor(&recipient)
            .unwrap()
            .wrap_output(&mut cipher)
            .unwrap();
        age_writer
            .write_all(b"finalization-boundary plaintext")
            .unwrap();
        state.lock().unwrap().reject_writes = true;
        finish_error = age_writer.finish().err();
    }
    let completed: bool = finish_error.is_none();
    assert!(!completed);
    assert!(!format!("{finish_error:?}").contains("AGE-SECRET-KEY"));
    let accepted: Vec<u8> = state.lock().unwrap().accepted.clone();
    let rejected_write_calls: usize = state.lock().unwrap().rejected_write_calls;
    assert!(rejected_write_calls > 0);
    assert!(cipher.write(b"after-final-chunk-error").is_err());
    assert!(cipher.flush().is_err());
    assert_eq!(state.lock().unwrap().accepted, accepted);
    assert_eq!(
        state.lock().unwrap().rejected_write_calls,
        rejected_write_calls
    );
    let (observed, digest): (u64, [u8; 32]) = cipher.observation();
    assert_eq!(observed, accepted.len() as u64);
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&accepted)));
}

// These direct terminal controls have no signed business fixture or SQL
// authority. Counts and marker bytes are not full-CLI or entry-count evidence.
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

#[cfg(target_os = "linux")]
const PACK_TERMINAL_FILE_BOUND: u64 = 64 * 1024;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PackTerminalFileStamp {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    length: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(target_os = "linux")]
impl PackTerminalFileStamp {
    fn read(metadata: &std::fs::Metadata) -> Self {
        assert!(metadata.is_file(), "checkpoint must be a regular file");
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            length: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

#[cfg(target_os = "linux")]
struct PackTerminalCheckpoint {
    file: std::fs::File,
    stamp: PackTerminalFileStamp,
    bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl PackTerminalCheckpoint {
    fn new(path: &Path, budget: &ArchiveReadBudget) -> Self {
        budget.check().expect("budget before checkpoint open");
        let named: std::fs::Metadata = std::fs::symlink_metadata(path).unwrap();
        let stamp: PackTerminalFileStamp = PackTerminalFileStamp::read(&named);
        assert_eq!(stamp.mode & 0o7777, 0o600);
        assert_eq!(stamp.uid, transport::effective_uid().unwrap());
        assert_eq!(stamp.links, 1);
        assert!(stamp.length <= PACK_TERMINAL_FILE_BOUND);
        let mut file: std::fs::File = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .unwrap();
        assert_eq!(
            PackTerminalFileStamp::read(&file.metadata().unwrap()),
            stamp
        );
        let mut bytes: Vec<u8> = vec![0; usize::try_from(stamp.length).unwrap()];
        file.read_exact(&mut bytes).unwrap();
        let mut probe: [u8; 1] = [0];
        assert_eq!(file.read(&mut probe).unwrap(), 0, "held physical EOF");
        assert_eq!(
            PackTerminalFileStamp::read(&file.metadata().unwrap()),
            stamp
        );
        assert_eq!(
            PackTerminalFileStamp::read(&std::fs::symlink_metadata(path).unwrap()),
            stamp
        );
        budget.check().expect("budget after checkpoint EOF");
        Self { file, stamp, bytes }
    }

    fn assert_unchanged(&self, path: &Path, budget: &ArchiveReadBudget) {
        assert_eq!(
            PackTerminalFileStamp::read(&self.file.metadata().unwrap()),
            self.stamp
        );
        let current: Self = Self::new(path, budget);
        assert_eq!(current.stamp, self.stamp);
        assert_eq!(current.bytes, self.bytes);
        assert_eq!(
            PackTerminalFileStamp::read(&self.file.metadata().unwrap()),
            self.stamp
        );
    }

    fn assert_owned_final(&self, path: &Path, budget: &ArchiveReadBudget) -> Self {
        let current: Self = Self::new(path, budget);
        let mut expected: PackTerminalFileStamp = self.stamp;
        // Only this invocation's successful hard-link/unlink ctime change is
        // exempted; final nlink is independently required to be one.
        expected.ctime = current.stamp.ctime;
        expected.ctime_nsec = current.stamp.ctime_nsec;
        assert_eq!(current.stamp, expected);
        assert_eq!(current.bytes, self.bytes);
        assert_eq!(
            PackTerminalFileStamp::read(&self.file.metadata().unwrap()),
            current.stamp
        );
        current
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct PackTerminalRootIdentity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[cfg(target_os = "linux")]
impl PackTerminalRootIdentity {
    fn read(metadata: &std::fs::Metadata) -> Self {
        assert!(metadata.is_dir(), "fixture root must remain a directory");
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
        }
    }
}

#[cfg(target_os = "linux")]
struct PackTerminalDirectory {
    path: PathBuf,
    held: std::fs::File,
    identity: PackTerminalRootIdentity,
}

#[cfg(target_os = "linux")]
impl PackTerminalDirectory {
    fn new(budget: &ArchiveReadBudget) -> Self {
        budget.check().expect("budget before fixture root creation");
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "recovery-pack-terminal-{}-{sequence}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let named: std::fs::Metadata = std::fs::symlink_metadata(&path).unwrap();
        let identity: PackTerminalRootIdentity = PackTerminalRootIdentity::read(&named);
        assert_eq!(identity.mode & 0o7777, 0o700);
        assert_eq!(identity.uid, transport::effective_uid().unwrap());
        let held: std::fs::File = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        assert_eq!(
            PackTerminalRootIdentity::read(&held.metadata().unwrap()),
            identity
        );
        Self {
            path,
            held,
            identity,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for PackTerminalDirectory {
    fn drop(&mut self) {
        // Directory nlink/length/times legitimately change as children are
        // created. Cleanup binds the held/named identity, type, mode, UID/GID.
        assert_eq!(
            PackTerminalRootIdentity::read(&self.held.metadata().unwrap()),
            self.identity
        );
        assert_eq!(
            PackTerminalRootIdentity::read(&std::fs::symlink_metadata(&self.path).unwrap()),
            self.identity
        );
        std::fs::remove_dir_all(&self.path).expect("remove only the identity-bound fixture root");
    }
}

#[cfg(target_os = "linux")]
fn pack_terminal_create_private(path: &Path, bytes: &[u8], budget: &ArchiveReadBudget) {
    budget.check().expect("budget before fixture leaf creation");
    assert!(bytes.len() as u64 <= PACK_TERMINAL_FILE_BOUND);
    let mut file: std::fs::File = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    budget.check().expect("budget after fixture leaf creation");
}

#[cfg(target_os = "linux")]
fn pack_terminal_absent(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => panic!("expected absent terminal leaf"),
    }
}

#[cfg(target_os = "linux")]
struct PackTerminalFixture {
    budget: ArchiveReadBudget,
    limits: RecoveryLimits,
    stage: PrivateStage,
    manifest: Manifest,
    footer: [u8; 49],
    plaintext: Vec<u8>,
    payloads: Vec<(PathBuf, PackTerminalCheckpoint)>,
    sentinel: PackTerminalCheckpoint,
    // Drop all other fixture handles before identity-bound directory cleanup.
    directory: PackTerminalDirectory,
}

#[cfg(target_os = "linux")]
impl PackTerminalFixture {
    fn new() -> Self {
        let limits: RecoveryLimits = RecoveryLimits {
            files: 3,
            observations: 4096,
            heights: 64,
            components: 64,
            file_bytes: PACK_TERMINAL_FILE_BOUND,
            control_bytes: 1024,
            plaintext_bytes: 1024,
            ciphertext_bytes: PACK_TERMINAL_FILE_BOUND,
            header_bytes: 16 * 1024,
            ..RecoveryLimits::default()
        };
        let budget: ArchiveReadBudget = limits.budget().unwrap();
        budget.check_roles(3).unwrap();
        let directory: PackTerminalDirectory = PackTerminalDirectory::new(&budget);
        let sentinel_path: PathBuf = directory.path.join("foreign-sentinel.bin");
        pack_terminal_create_private(&sentinel_path, b"unrelated private sentinel\0", &budget);
        let sentinel: PackTerminalCheckpoint = PackTerminalCheckpoint::new(&sentinel_path, &budget);
        let mut entries: Vec<Entry> = Vec::new();
        // Independent L0 fields and one-byte bodies; these are not business proofs.
        for (tag, name, body) in [
            (1u8, "genesis.bin", [1u8]),
            (2, "identity.bin", [2]),
            (3, "identity.bin", [3]),
        ] {
            entries.push(Entry {
                role: Role { tag, link: 65535 },
                name: name.to_owned(),
                length: 1,
                hash: Sha256::digest(body).into(),
            });
        }
        let manifest: Manifest = Manifest::encode(0, entries, &limits).unwrap();
        let mut literal: Vec<u8> = vec![
            1, 0, 0, 0, 207, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 1, 255, 255, 0, 0, 0,
            1, 2, 255, 255, 0, 0, 0, 1, 3, 255, 255, 0, 0, 0, 1,
        ];
        for (tag, name, name_length, body) in [
            (1u8, "genesis.bin", 11u8, [1u8]),
            (2, "identity.bin", 12, [2]),
            (3, "identity.bin", 12, [3]),
        ] {
            literal.extend_from_slice(&[tag, 255, 255, 0, name_length]);
            literal.extend_from_slice(name.as_bytes());
            literal.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
            literal.extend_from_slice(&Sha256::digest(body));
        }
        assert_eq!(literal.len(), 212);
        assert_eq!(manifest.record, literal);
        assert_eq!(
            (
                manifest.links,
                manifest.bodies,
                manifest.control,
                manifest.plaintext
            ),
            (0, 3, 326, 329)
        );
        let mut footer: [u8; 49] = [0; 49];
        footer[..17].copy_from_slice(&[3, 0, 0, 0, 44, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3]);
        footer[17..].copy_from_slice(&Sha256::digest(&literal));
        assert_eq!(manifest.footer().unwrap(), footer);
        let mut plaintext: Vec<u8> = b"SE-RECOVERY\0\0\x01".to_vec();
        plaintext.extend_from_slice(&literal);
        for (index, body) in [(0u8, 1u8), (1, 2), (2, 3)] {
            plaintext.extend_from_slice(&[2, 0, 0, 0, 13, 0, 0, 0, index, 0, 0, 0, 0, 0, 0, 0, 1]);
            plaintext.push(body);
        }
        plaintext.extend_from_slice(&footer);
        assert_eq!(plaintext.len(), 329);
        let capture: PathBuf = directory.path.join("capture");
        let absent_capture: AbsentOutput = AbsentOutput::new(&capture, &budget).unwrap();
        let mut stage: PrivateStage = PrivateStage::create(&absent_capture, &budget).unwrap();
        assert_eq!(stage.root(), capture.as_path());
        for (entry, body) in manifest.entries.iter().zip([[1u8], [2], [3]]) {
            let mut input: Cursor<[u8; 1]> = Cursor::new(body);
            stage.receive(&mut input, entry).unwrap();
            let mut probe: [u8; 1] = [0];
            assert_eq!(input.read(&mut probe).unwrap(), 0);
        }
        stage.check(&manifest).unwrap();
        let mut payloads: Vec<(PathBuf, PackTerminalCheckpoint)> = Vec::new();
        for (name, body) in [
            ("genesis/genesis.bin", [1u8]),
            ("current/history/identity.bin", [2]),
            ("current/cut/identity.bin", [3]),
        ] {
            let path: PathBuf = capture.join(name);
            let checkpoint: PackTerminalCheckpoint = PackTerminalCheckpoint::new(&path, &budget);
            assert_eq!(checkpoint.bytes, body);
            payloads.push((path, checkpoint));
        }
        Self {
            budget,
            limits,
            stage,
            manifest,
            footer,
            plaintext,
            payloads,
            sentinel,
            directory,
        }
    }

    fn assert_retained_inputs(&self) {
        for (path, checkpoint) in &self.payloads {
            checkpoint.assert_unchanged(path, &self.budget);
        }
        self.sentinel.assert_unchanged(
            &self.directory.path.join("foreign-sentinel.bin"),
            &self.budget,
        );
    }
}

#[cfg(target_os = "linux")]
fn pack_terminal_write_stage<W: Write>(fixture: &PackTerminalFixture, output: &mut W) {
    fixture.manifest.write_prefix(output).unwrap();
    for (index, entry) in fixture.manifest.entries.iter().enumerate() {
        output
            .write_all(&envelope::file_header(index, entry).unwrap())
            .unwrap();
        fixture.stage.write_body(output, entry).unwrap();
    }
    output.write_all(&fixture.footer).unwrap();
}

#[cfg(target_os = "linux")]
fn pack_terminal_real_finish(
    fixture: &PackTerminalFixture,
    publication: &mut CipherPublication,
    identity: &age::x25519::Identity,
) -> Result<(u64, [u8; 32]), RecoveryError> {
    let counted: CipherWriter<'_, &mut std::fs::File> = CipherWriter::new(
        publication.writer(),
        &fixture.budget,
        fixture.limits.ciphertext_bytes,
    );
    let recipient: age::x25519::Recipient = identity.to_public();
    let mut encrypted: age::stream::StreamWriter<CipherWriter<'_, &mut std::fs::File>> =
        transport::encryptor(&recipient)
            .unwrap()
            .wrap_output(counted)
            .unwrap();
    pack_terminal_write_stage(fixture, &mut encrypted);
    encrypted
        .finish()
        .map(|counted: CipherWriter<'_, &mut std::fs::File>| counted.observation())
        .map_err(|_| RecoveryError::Transport)
}

#[cfg(target_os = "linux")]
#[test]
fn pack_terminal_real_age_finish_error_has_no_diagnostic_counts_or_completion_file() {
    struct FinishSink<'a> {
        file: &'a mut std::fs::File,
        armed: &'a std::cell::Cell<bool>,
        rejected: &'a std::cell::Cell<usize>,
    }
    impl Write for FinishSink<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.is_empty() {
                return Ok(0);
            }
            if self.armed.get() {
                self.rejected
                    .set(self.rejected.get().checked_add(1).unwrap());
                return Err(io::Error::other("AGE-SECRET-KEY-1-terminal-finish-refusal"));
            }
            self.file.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }

    let mut fixture: PackTerminalFixture = PackTerminalFixture::new();
    let output: PathBuf = fixture.directory.path.join("closure.age");
    let pending: PathBuf = CipherPublication::pending_path(&output).unwrap();
    let absent_output: AbsentOutput = AbsentOutput::new(&output, &fixture.budget).unwrap();
    let mut publication: CipherPublication =
        CipherPublication::create(absent_output, &fixture.budget).unwrap();
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    let recipient: age::x25519::Recipient = identity.to_public();
    let armed: std::cell::Cell<bool> = std::cell::Cell::new(false);
    let rejected: std::cell::Cell<usize> = std::cell::Cell::new(0);
    let sink: FinishSink<'_> = FinishSink {
        file: publication.writer(),
        armed: &armed,
        rejected: &rejected,
    };
    let counted: CipherWriter<'_, FinishSink<'_>> =
        CipherWriter::new(sink, &fixture.budget, fixture.limits.ciphertext_bytes);
    let mut encrypted: age::stream::StreamWriter<CipherWriter<'_, FinishSink<'_>>> =
        transport::encryptor(&recipient)
            .unwrap()
            .wrap_output(counted)
            .unwrap();
    pack_terminal_write_stage(&fixture, &mut encrypted);
    let before: PackTerminalCheckpoint = PackTerminalCheckpoint::new(&pending, &fixture.budget);
    assert!(
        !before.bytes.is_empty(),
        "real age header reached the pending file"
    );
    armed.set(true);
    let finished: Result<(u64, [u8; 32]), RecoveryError> = encrypted
        .finish()
        .map(|counted: CipherWriter<'_, FinishSink<'_>>| counted.observation())
        .map_err(|_| RecoveryError::Transport);
    assert!(finished.is_err(), "actual age finish must refuse");
    assert!(
        rejected.get() > 0,
        "actual final emission attempted a nonempty write"
    );
    assert_eq!(fixture.stage.complete_entry_count_for_test(), 0_usize);
    let result: Result<PackedDiagnosticCounts, RecoveryError> = finish_pack_publication(
        finished,
        &mut fixture.stage,
        publication,
        &fixture.manifest,
        &fixture.footer,
        fixture.limits.ciphertext_bytes,
        &fixture.budget,
    );
    assert_eq!(fixture.stage.complete_entry_count_for_test(), 0_usize);
    let error: RecoveryError = match result {
        Err(error) => error,
        Ok(_) => panic!("finish refusal returned printable diagnostic counts"),
    };
    assert_eq!(error, RecoveryError::Transport);
    assert!(!format!("{error} {error:?}").contains("AGE-SECRET-KEY"));
    assert!(std::error::Error::source(&error).is_none());
    pack_terminal_absent(&output);
    pack_terminal_absent(
        &fixture
            .directory
            .path
            .join("capture/recovery-complete-v1.bin"),
    );
    before.assert_unchanged(&pending, &fixture.budget);
    fixture.assert_retained_inputs();
}

#[cfg(target_os = "linux")]
#[test]
fn pack_terminal_late_equal_output_refusal_preserves_foreign_leaf_and_no_diagnostic_counts() {
    let mut fixture: PackTerminalFixture = PackTerminalFixture::new();
    let output: PathBuf = fixture.directory.path.join("closure.age");
    let pending: PathBuf = CipherPublication::pending_path(&output).unwrap();
    let absent_output: AbsentOutput = AbsentOutput::new(&output, &fixture.budget).unwrap();
    let mut publication: CipherPublication =
        CipherPublication::create(absent_output, &fixture.budget).unwrap();
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    let finished: Result<(u64, [u8; 32]), RecoveryError> =
        pack_terminal_real_finish(&fixture, &mut publication, &identity);
    let (length, hash): (u64, [u8; 32]) = finished.as_ref().copied().unwrap();
    let owned: PackTerminalCheckpoint = PackTerminalCheckpoint::new(&pending, &fixture.budget);
    assert_eq!(length, owned.bytes.len() as u64);
    assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(&owned.bytes)));
    pack_terminal_create_private(&output, &owned.bytes, &fixture.budget);
    let foreign: PackTerminalCheckpoint = PackTerminalCheckpoint::new(&output, &fixture.budget);
    assert_eq!(foreign.bytes, owned.bytes);
    assert_eq!(foreign.stamp.dev, owned.stamp.dev);
    assert_ne!(
        foreign.stamp.ino, owned.stamp.ino,
        "equal bytes are a foreign inode"
    );
    assert_eq!(fixture.stage.complete_entry_count_for_test(), 0_usize);
    let result: Result<PackedDiagnosticCounts, RecoveryError> = finish_pack_publication(
        finished,
        &mut fixture.stage,
        publication,
        &fixture.manifest,
        &fixture.footer,
        fixture.limits.ciphertext_bytes,
        &fixture.budget,
    );
    assert_eq!(fixture.stage.complete_entry_count_for_test(), 0_usize);
    let error: RecoveryError = match result {
        Err(error) => error,
        Ok(_) => panic!("equal-existing refusal returned printable diagnostic counts"),
    };
    assert_eq!(error, RecoveryError::Publication);
    pack_terminal_absent(
        &fixture
            .directory
            .path
            .join("capture/recovery-complete-v1.bin"),
    );
    owned.assert_unchanged(&pending, &fixture.budget);
    foreign.assert_unchanged(&output, &fixture.budget);
    fixture.assert_retained_inputs();
}

#[cfg(target_os = "linux")]
#[test]
fn pack_terminal_ordinary_success_returns_counts_after_publication_and_stage_completion() {
    let mut fixture: PackTerminalFixture = PackTerminalFixture::new();
    let output: PathBuf = fixture.directory.path.join("closure.age");
    let pending: PathBuf = CipherPublication::pending_path(&output).unwrap();
    let absent_output: AbsentOutput = AbsentOutput::new(&output, &fixture.budget).unwrap();
    let mut publication: CipherPublication =
        CipherPublication::create(absent_output, &fixture.budget).unwrap();
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    let finished: Result<(u64, [u8; 32]), RecoveryError> =
        pack_terminal_real_finish(&fixture, &mut publication, &identity);
    let (length, hash): (u64, [u8; 32]) = finished.as_ref().copied().unwrap();
    let owned: PackTerminalCheckpoint = PackTerminalCheckpoint::new(&pending, &fixture.budget);
    assert_eq!(length, owned.bytes.len() as u64);
    assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(&owned.bytes)));
    assert_eq!(fixture.stage.complete_entry_count_for_test(), 0_usize);
    let counts: PackedDiagnosticCounts = finish_pack_publication(
        finished,
        &mut fixture.stage,
        publication,
        &fixture.manifest,
        &fixture.footer,
        fixture.limits.ciphertext_bytes,
        &fixture.budget,
    )
    .unwrap();
    assert_eq!(fixture.stage.complete_entry_count_for_test(), 1_usize);
    assert_eq!(counts.links, 0);
    assert_eq!(counts.files, 3);
    pack_terminal_absent(&pending);
    let final_file: PackTerminalCheckpoint = owned.assert_owned_final(&output, &fixture.budget);
    let marker: PackTerminalCheckpoint = PackTerminalCheckpoint::new(
        &fixture
            .directory
            .path
            .join("capture/recovery-complete-v1.bin"),
        &fixture.budget,
    );
    assert_eq!(marker.bytes, fixture.footer);
    assert_eq!(marker.stamp.length, 49);
    fixture.assert_retained_inputs();

    fixture.budget.check().unwrap();
    let input: std::fs::File = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&output)
        .unwrap();
    assert_eq!(
        PackTerminalFileStamp::read(&input.metadata().unwrap()),
        final_file.stamp
    );
    let limits: RecoveryLimits = RecoveryLimits {
        ciphertext_bytes: length,
        plaintext_bytes: 329,
        ..fixture.limits.clone()
    };
    let phase: CipherPhase = CipherPhase::header();
    let mut cipher: CipherReader<'_, std::fs::File> =
        CipherReader::new(input, &phase, &fixture.budget, &limits);
    {
        let decrypted: age::stream::StreamReader<&mut CipherReader<'_, std::fs::File>> =
            transport::decrypt(&mut cipher, &phase, &identity).unwrap();
        let mut plain: PlainReader<
            '_,
            age::stream::StreamReader<&mut CipherReader<'_, std::fs::File>>,
        > = PlainReader::new(decrypted, limits.plaintext_bytes, &fixture.budget);
        let mut observed: Vec<u8> = Vec::new();
        plain.read_to_end(&mut observed).unwrap();
        assert_eq!(observed, fixture.plaintext);
        assert_eq!(plain.observed(), 329);
        plain.authenticated_eof().unwrap();
    }
    let earlier_zeros: u64 = cipher.physical_zeros();
    cipher.physical_eof().unwrap();
    assert_eq!(cipher.physical_zeros(), earlier_zeros + 1);
    assert_eq!(cipher.observed(), length);
    assert_eq!(
        PackTerminalFileStamp::read(&cipher.inner.metadata().unwrap()),
        final_file.stamp
    );
    final_file.assert_unchanged(&output, &fixture.budget);
    fixture.assert_retained_inputs();
}

#[cfg(target_os = "linux")]
#[test]
fn pack_terminal_direct_complete_refused_budget_is_quota_before_leaf_creation() {
    fn assert_original_stamps(checkpoint: &PackTerminalCheckpoint, path: &Path) {
        let held: std::fs::Metadata = checkpoint.file.metadata().unwrap();
        let named: std::fs::Metadata = std::fs::symlink_metadata(path).unwrap();
        assert_eq!(PackTerminalFileStamp::read(&held), checkpoint.stamp);
        assert_eq!(PackTerminalFileStamp::read(&named), checkpoint.stamp);
    }

    fn assert_original_held_bytes(checkpoint: &PackTerminalCheckpoint, path: &Path) {
        use std::os::unix::fs::FileExt;

        assert!(checkpoint.stamp.length <= PACK_TERMINAL_FILE_BOUND);
        let length: usize = usize::try_from(checkpoint.stamp.length).unwrap();
        assert!(length > 0_usize, "retained fixture leaf must be nonempty");
        assert_eq!(checkpoint.bytes.len(), length);
        assert_original_stamps(checkpoint, path);
        let mut observed: Vec<u8> = vec![0; length];
        let mut offset: usize = 0_usize;
        let mut attempts: usize = 0_usize;
        while offset < length {
            assert!(attempts < length, "finite positive-progress read attempts");
            attempts = attempts.checked_add(1_usize).unwrap();
            let position: u64 = u64::try_from(offset).unwrap();
            let remaining: usize = length.checked_sub(offset).unwrap();
            assert_original_stamps(checkpoint, path);
            let read_result: io::Result<usize> =
                checkpoint.file.read_at(&mut observed[offset..], position);
            assert_original_stamps(checkpoint, path);
            let count: usize = read_result.unwrap();
            assert!(count > 0_usize, "zero progress before saved leaf length");
            assert!(count <= remaining);
            offset = offset.checked_add(count).unwrap();
        }
        assert_eq!(offset, length);
        assert!(attempts <= length);
        let mut probe: [u8; 1] = [0; 1];
        assert_original_stamps(checkpoint, path);
        let probe_result: io::Result<usize> =
            checkpoint.file.read_at(&mut probe, checkpoint.stamp.length);
        assert_original_stamps(checkpoint, path);
        let physical_eof: usize = probe_result.unwrap();
        assert_eq!(physical_eof, 0_usize, "nonempty held positional EOF probe");
        assert_eq!(observed, checkpoint.bytes);
        assert_original_stamps(checkpoint, path);
    }

    fn assert_outer_identity(directory: &PackTerminalDirectory) {
        let held: std::fs::Metadata = directory.held.metadata().unwrap();
        let named: std::fs::Metadata = std::fs::symlink_metadata(&directory.path).unwrap();
        assert_eq!(PackTerminalRootIdentity::read(&held), directory.identity);
        assert_eq!(PackTerminalRootIdentity::read(&named), directory.identity);
    }

    let mut fixture: PackTerminalFixture = PackTerminalFixture::new();
    let marker: PathBuf = fixture.stage.root().join(envelope::COMPLETE);
    let sentinel_path: PathBuf = fixture.directory.path.join("foreign-sentinel.bin");
    assert_eq!(fixture.payloads.len(), 3_usize);
    fixture.stage.check(&fixture.manifest).unwrap();
    assert_eq!(fixture.stage.complete_entry_count_for_test(), 0_usize);
    pack_terminal_absent(&marker);
    fixture.assert_retained_inputs();
    assert_outer_identity(&fixture.directory);

    assert!(fixture.budget.charge_observations(u64::MAX).is_err());
    assert!(fixture.budget.check().is_err());
    assert_eq!(fixture.stage.complete_entry_count_for_test(), 0_usize);
    let result: Result<(), RecoveryError> =
        fixture.stage.complete(&fixture.manifest, &fixture.footer);
    assert_eq!(fixture.stage.complete_entry_count_for_test(), 1_usize);
    let error: RecoveryError = result.unwrap_err();
    assert_eq!(error, RecoveryError::Quota);
    assert!(fixture.budget.check().is_err());
    pack_terminal_absent(&marker);
    assert_outer_identity(&fixture.directory);
    for (path, checkpoint) in &fixture.payloads {
        assert_original_held_bytes(checkpoint, path);
    }
    assert_original_held_bytes(&fixture.sentinel, &sentinel_path);
    assert_outer_identity(&fixture.directory);
    assert!(fixture.budget.check().is_err());
}
