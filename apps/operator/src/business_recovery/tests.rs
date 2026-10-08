//! Real maintained age controls and independent LOCAL framing/quota vectors.
//! Pure transport vectors are not business-proof or custody qualification.
use super::*;
use envelope::Entry;
use std::{
    io::{self, Cursor, Read, Write},
    sync::{
        Arc,
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
        let mut limits: RecoveryLimits = RecoveryLimits::default();
        limits.ciphertext_bytes = bytes.len() as u64;
        limits.plaintext_bytes = size as u64;
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
