//! Real maintained-age and actual selected-store owner controls, not a protocol
//! proof/upgrade or off-host retention qualification.
use super::*;
use age::secrecy::ExposeSecret;
use protocol_types::{Digest32, HashAlgorithmId};
use runtime::{BlobStore, WriterFenceGeneration};
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    blobs: PathBuf,
    anchor: PathBuf,
    identity: PathBuf,
    recipient: age::x25519::Recipient,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root: PathBuf = std::env::temp_dir().join(format!(
            "checkpoint-v2-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("source")).unwrap();
        fs::create_dir(root.join("authority")).unwrap();
        let state: PathBuf = root.join("source/state.sqlite");
        let blobs: PathBuf = root.join("source/blobs.sqlite");
        let anchor: PathBuf = root.join("authority/anchor.sqlite");
        drop(SqliteDurableStore::create_new(&state, namespace(), fence(1)).unwrap());
        let body_owner = runtime_sqlite::SqliteBlobStore::create_new(&blobs).unwrap();
        body_owner
            .put_blob(body_digest(), b"retained immutable content".to_vec())
            .unwrap();
        drop(body_owner);
        let initial = runtime_sqlite::inspect_independent_anchor_inputs(
            &state,
            &blobs,
            namespace().chain_id(),
            namespace().validator_id(),
            namespace().domain(),
        )
        .unwrap();
        runtime_sqlite::enroll_independent_anchor(
            &state,
            &blobs,
            &anchor,
            namespace().chain_id(),
            namespace().validator_id(),
            namespace().domain(),
            initial.state_root,
            initial.body_manifest_root,
            true,
        )
        .unwrap();
        let key: age::x25519::Identity = age::x25519::Identity::generate();
        let identity: PathBuf = root.join("identity");
        use std::os::unix::fs::OpenOptionsExt;
        let mut file: fs::File = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&identity)
            .unwrap();
        file.write_all(key.to_string().expose_secret().as_bytes())
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
        Self {
            root,
            state,
            blobs,
            anchor,
            identity,
            recipient: key.to_public(),
        }
    }
    fn args(&self, packing: bool, name: &str) -> Vec<OsString> {
        let mut values: Vec<OsString> = vec![
            if packing {
                "pack-checkpoint"
            } else {
                "open-checkpoint"
            }
            .into(),
            "--chain-id".into(),
            "checkpoint-tests".into(),
            "--validator-id".into(),
            "01".repeat(32).into(),
            "--domain".into(),
            "02".repeat(32).into(),
            "--independent-anchor-db".into(),
            self.anchor.as_os_str().to_owned(),
            "--recipient".into(),
            self.recipient.to_string().into(),
        ];
        if packing {
            values.extend([
                "--state-db".into(),
                self.state.as_os_str().to_owned(),
                "--blob-db".into(),
                self.blobs.as_os_str().to_owned(),
                "--capture-root".into(),
                self.root.join(name).into_os_string(),
                "--ciphertext-out".into(),
                self.root.join(format!("{name}.age")).into_os_string(),
            ]);
        } else {
            values.extend([
                "--ciphertext-file".into(),
                self.root.join("capture.age").into_os_string(),
                "--identity-file".into(),
                self.identity.as_os_str().to_owned(),
                "--out-dir".into(),
                self.root.join(name).into_os_string(),
            ]);
        }
        values
    }
    fn packed(&self) {
        run(self.args(true, "capture")).unwrap();
    }
    fn no_complete(&self, name: &str) {
        assert!(!self.root.join(name).join(envelope::COMPLETE).exists());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn namespace() -> SqliteNamespace {
    SqliteNamespace::new(
        ChainId::new("checkpoint-tests").unwrap(),
        ValidatorId::new([1; 32]),
        AtomicityDomainId::new([2; 32]).unwrap(),
    )
}
fn fence(n: u64) -> WriterFenceGeneration {
    WriterFenceGeneration::new(n).unwrap()
}
fn body_digest() -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [7; 32])
}

#[test]
fn actual_age_checkpoint_round_trip_without_source_paths_and_fresh_fence_continuation() {
    let f: Fixture = Fixture::new();
    f.packed();
    assert!(f.root.join("capture").join(envelope::COMPLETE).is_file());
    fs::rename(&f.state, f.state.with_extension("lost")).unwrap();
    fs::rename(&f.blobs, f.blobs.with_extension("lost")).unwrap();
    run(f.args(false, "restored")).unwrap();
    assert!(f.root.join("restored").join(envelope::COMPLETE).is_file());
    let state: PathBuf = f.root.join("restored/state.sqlite");
    let blobs: PathBuf = f.root.join("restored/blobs.sqlite");
    let restored =
        SqliteDurableStore::open_anchored(&state, &blobs, &f.anchor, namespace()).unwrap();
    assert_eq!(restored.writer_fence().unwrap(), fence(1));
    restored.advance_writer_fence(fence(1), fence(2)).unwrap();
    let body_owner = runtime_sqlite::SqliteBlobStore::open_existing(&blobs).unwrap();
    assert_eq!(
        body_owner.get_blob(&body_digest()).unwrap(),
        Some(b"retained immutable content".to_vec())
    );
    drop(body_owner);
    drop(restored);
    assert!(run(f.args(false, "stale")).is_err());
    f.no_complete("stale");
    use std::os::unix::fs::PermissionsExt;
    for name in [
        "state.sqlite",
        "blobs.sqlite",
        envelope::MANIFEST,
        envelope::COMPLETE,
    ] {
        assert_eq!(
            fs::metadata(f.root.join("restored").join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert_eq!(
        fs::metadata(f.root.join("restored"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn actual_age_checkpoint_truncation_concatenation_wrong_key_quotas_and_existing_outputs_refuse() {
    let f: Fixture = Fixture::new();
    f.packed();
    let original: Vec<u8> = fs::read(f.root.join("capture.age")).unwrap();
    for (name, bytes) in [
        ("truncated", original[..original.len() - 1].to_vec()),
        (
            "concatenated",
            [original.as_slice(), original.as_slice()].concat(),
        ),
    ] {
        fs::write(f.root.join("capture.age"), bytes).unwrap();
        assert!(run(f.args(false, name)).is_err());
        f.no_complete(name);
    }
    fs::write(f.root.join("capture.age"), &original).unwrap();
    for (name, flag, value) in [
        ("plain-cap", "--max-plaintext-bytes", "1"),
        ("file-cap", "--max-file-bytes", "1"),
        ("cipher-cap", "--max-ciphertext-bytes", "1"),
        ("header-cap", "--max-header-bytes", "1"),
        ("control-cap", "--max-control-bytes", "1"),
        ("observation-cap", "--max-observations", "1"),
    ] {
        let mut args: Vec<OsString> = f.args(false, name);
        args.extend([flag.into(), value.into()]);
        assert!(run(args).is_err());
        f.no_complete(name);
    }
    let wrong: age::x25519::Identity = age::x25519::Identity::generate();
    fs::write(&f.identity, wrong.to_string().expose_secret().as_bytes()).unwrap();
    assert!(run(f.args(false, "wrong-key")).is_err());
    f.no_complete("wrong-key");
    let mut wrong_recipient: Vec<OsString> = f.args(false, "actual-wrong-key");
    let index: usize = wrong_recipient
        .iter()
        .position(|value| value == "--recipient")
        .unwrap();
    wrong_recipient[index + 1] = wrong.to_public().to_string().into();
    assert!(run(wrong_recipient).is_err());
    f.no_complete("actual-wrong-key");
    fs::create_dir(f.root.join("existing")).unwrap();
    fs::write(f.root.join("existing/kept"), b"kept").unwrap();
    assert!(run(f.args(false, "existing")).is_err());
    assert_eq!(fs::read(f.root.join("existing/kept")).unwrap(), b"kept");
}

#[test]
fn checkpoint_missing_authority_wrong_namespace_and_live_lease_refuse_before_completion() {
    let f: Fixture = Fixture::new();
    f.packed();
    let store =
        SqliteDurableStore::open_anchored(&f.state, &f.blobs, &f.anchor, namespace()).unwrap();
    assert!(run(f.args(false, "live-owner")).is_err());
    f.no_complete("live-owner");
    drop(store);
    let mut args: Vec<OsString> = f.args(false, "wrong-namespace");
    let index: usize = args.iter().position(|value| value == "--chain-id").unwrap();
    args[index + 1] = "foreign".into();
    assert!(run(args).is_err());
    f.no_complete("wrong-namespace");
    let missing: PathBuf = f.anchor.with_file_name("missing.sqlite");
    let mut args: Vec<OsString> = f.args(false, "missing");
    let index: usize = args
        .iter()
        .position(|value| value == "--independent-anchor-db")
        .unwrap();
    args[index + 1] = missing.as_os_str().to_owned();
    assert!(run(args).is_err());
    f.no_complete("missing");
    assert!(!missing.exists());
    assert!(!missing.with_file_name("missing.sqlite.lease").exists());
}

#[test]
fn valid_age_with_rehashed_executable_schema_and_body_substitution_remains_unqualified() {
    use sha2::{Digest, Sha256};
    let f: Fixture = Fixture::new();
    f.packed();
    let payload: Vec<u8> = fs::read(f.root.join("capture").join(envelope::MANIFEST)).unwrap();
    let mut prefix: Vec<u8> = super::super::envelope::MAGIC.to_vec();
    prefix.extend(2u16.to_be_bytes());
    prefix.push(1);
    prefix.extend((payload.len() as u32).to_be_bytes());
    prefix.extend(payload);
    let manifest: envelope::Manifest =
        envelope::Manifest::read(&mut &prefix[..], &RecoveryLimits::default()).unwrap();
    for (index,(body,sql)) in [
        (false,"CREATE TRIGGER injected AFTER INSERT ON durable_state BEGIN DELETE FROM durable_state; END"),
        (true,"UPDATE blobs SET content=x'ff'"),
    ].into_iter().enumerate() {
        let changed:PathBuf=f.root.join(format!("modified-{index}.sqlite"));
        fs::copy(f.root.join("capture").join(if body {"blobs.sqlite"} else {"state.sqlite"}),&changed).unwrap();
        let connection:rusqlite::Connection=rusqlite::Connection::open(&changed).unwrap();connection.execute_batch(sql).unwrap();drop(connection);
        let mut bytes:[Vec<u8>;2]=[fs::read(f.root.join("capture/state.sqlite")).unwrap(),fs::read(f.root.join("capture/blobs.sqlite")).unwrap()];bytes[usize::from(body)]=fs::read(&changed).unwrap();
        let bodies:[(u64,[u8;32]);2]=std::array::from_fn(|i|(bytes[i].len() as u64,Sha256::digest(&bytes[i]).into()));
        let forged:envelope::Manifest=envelope::Manifest::new(manifest.point.clone(),bodies,&RecoveryLimits::default()).unwrap();
        let mut encrypted:Vec<u8>=Vec::new();let mut writer=transport::encryptor(&f.recipient).unwrap().wrap_output(&mut encrypted).unwrap();forged.prefix(&mut writer).unwrap();
        for (i,file) in bytes.iter().enumerate() {writer.write_all(&forged.file_header(i).unwrap()).unwrap();writer.write_all(file).unwrap();}
        writer.write_all(&forged.footer()).unwrap();writer.finish().unwrap();
        fs::write(f.root.join("capture.age"),encrypted).unwrap();
        let name:String=format!("schema-or-body-{index}");assert_eq!(run(f.args(false,&name)),Err(RecoveryError::Proof));f.no_complete(&name);
    }
}
