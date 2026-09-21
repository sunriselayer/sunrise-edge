//! Shared real-devnet CLI test harness helpers.

use execution::{ObjectEffect, paid_execution::PaidExecutionResult};
use objects::{ObjectId, ObjectRef, decode_object};
use public_standard_asset::coin_amount;
use runtime::{
    DurableOperationContext, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
};
use std::{
    fs,
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::Duration,
};
use sunrise_edge_client::{
    HttpObjectQueryResult, LocalSigner, LoopbackHttpTransport, decode_paid_execution_result,
};
use sunrise_edge_devnet::DevnetConfig;

pub struct TestDirectory(pub PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ignored: Result<(), std::io::Error> = fs::remove_dir_all(&self.0);
        }
    }
}

pub fn test_directory(label: &str) -> TestDirectory {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path: PathBuf = std::env::temp_dir().join(format!(
        "sunrise-cli-{label}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    TestDirectory(path)
}

pub fn write_seed(path: &Path, byte: u8) {
    fs::write(path, format!("{byte:02x}").repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

pub fn devnet_config(
    directory: &Path,
    owner: &LocalSigner,
    fee_recipient: &LocalSigner,
    chain_id: &str,
    epoch: u64,
) -> DevnetConfig {
    DevnetConfig::parse_from(vec![
        "--data-dir".into(),
        directory.display().to_string(),
        "--listen".into(),
        "127.0.0.1:7400".into(),
        "--chain-id".into(),
        chain_id.into(),
        "--epoch".into(),
        epoch.to_string(),
        "--dev-owner".into(),
        owner.address().to_string(),
        "--fee-recipient".into(),
        fee_recipient.address().to_string(),
        "--max-concurrent".into(),
        "4".into(),
    ])
    .unwrap()
}

pub fn operation(generation: WriterFenceGeneration, sequence: u8) -> DurableOperationContext {
    DurableOperationContext::new(
        generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([sequence; 16]).unwrap(),
    )
}

pub fn transport(address: SocketAddr) -> LoopbackHttpTransport {
    LoopbackHttpTransport::new(
        address,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(1024 * 1024).unwrap(),
    )
    .unwrap()
}

pub fn decode_result(path: &Path) -> PaidExecutionResult {
    decode_paid_execution_result(&fs::read(path).unwrap()).unwrap()
}

pub fn application_created_object(result: &PaidExecutionResult) -> ObjectId {
    let charged = result.charged.as_ref().unwrap();
    let fee_id: ObjectId = charged.fee_output.id;
    let refund_id: Option<ObjectId> = charged
        .refund_output
        .as_ref()
        .map(|value: &ObjectRef| value.id);
    let created: Vec<ObjectId> = result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect: &ObjectEffect| match effect {
            ObjectEffect::Created(object)
                if object.id != fee_id && Some(object.id) != refund_id =>
            {
                Some(object.id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), 1);
    created[0]
}

pub fn current_coin_amount(result: &HttpObjectQueryResult) -> u64 {
    let HttpObjectQueryResult::CurrentInline {
        canonical_object_bytes,
        ..
    } = result
    else {
        panic!("expected a current inline Coin");
    };
    coin_amount(&decode_object(canonical_object_bytes).unwrap().data).unwrap()
}
