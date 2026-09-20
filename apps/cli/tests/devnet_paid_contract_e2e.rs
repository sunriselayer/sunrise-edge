//! Real SQLite/native-HTTP/CLI paid Publish -> Instantiate -> Call activation.

use abi::{
    AccessManifest,
    call_values::{CallValue, ValueLayout, encode_call_value},
    encode_access_manifest,
    executable_abi::{ExecutableAbi, encode_executable_abi},
    package_types::PackageOrigin,
    public_abi::{EntrypointDeclaration, PackageAbi},
};
use execution::paid_execution::{
    PaidExecutionResult, PaidExecutionStatus, decode_paid_execution_result,
};
use execution::publication::PublicationContext;
use objects::ObjectId;
use protocol_types::AtomicityDomainId;
use runtime::{Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock};
use std::{ffi::OsString, fs, path::PathBuf, sync::Arc};
use sunrise_edge_client::LocalSigner;
use sunrise_edge_devnet::{
    DevnetConfig, STANDARD_ASSET_MODULE_WASM, boot_local_store, build_devnet_protocol_context,
    build_standard_asset_module, compose_devnet_router_with_contract_policies,
    install_paid_contracts, seed::verify_or_seed_protocol_context,
};

struct OwnedDirectory(PathBuf);
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _removed: Result<(), std::io::Error> = fs::remove_dir_all(&self.0);
        }
    }
}

fn write_seed(path: &std::path::Path) {
    fs::write(path, "07".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paid_publish_instantiate_and_call_cross_cli_http_and_sqlite() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "sunrise-cli-paid-contract-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let _owned_directory = OwnedDirectory(directory.clone());
    let signer: LocalSigner = LocalSigner::from_seed([7; 32]);
    let treasury: LocalSigner = LocalSigner::from_seed([9; 32]);
    let config: DevnetConfig = DevnetConfig::parse_from(vec![
        "--data-dir".into(),
        directory.display().to_string(),
        "--listen".into(),
        "127.0.0.1:7400".into(),
        "--chain-id".into(),
        "cli-paid-contract".into(),
        "--epoch".into(),
        "0".into(),
        "--dev-owner".into(),
        signer.address().to_string(),
        "--fee-treasury-owner".into(),
        treasury.address().to_string(),
        "--enable-paid-contracts".into(),
        "--max-concurrent".into(),
        "4".into(),
    ])
    .unwrap();
    let seed_path: PathBuf = directory.join("seed");
    write_seed(&seed_path);

    let origin: PackageOrigin = PackageOrigin::unverified(
        config.chain_id().clone(),
        *signer.address().as_bytes(),
        [0x31; 32],
    )
    .unwrap();
    let entrypoints: Vec<EntrypointDeclaration> = vec![
        EntrypointDeclaration {
            name: "init".to_owned(),
            type_parameters: Vec::new(),
            objects: Vec::new(),
        },
        EntrypointDeclaration {
            name: "run".to_owned(),
            type_parameters: Vec::new(),
            objects: Vec::new(),
        },
    ];
    let empty_layout: ValueLayout = ValueLayout::Tuple(Vec::new());
    let abi: Vec<u8> = encode_executable_abi(&ExecutableAbi {
        call: abi::call_values::CallAbi {
            objects: PackageAbi {
                origin,
                constructors: Vec::new(),
                entrypoints,
            },
            arguments: vec![empty_layout.clone(), empty_layout.clone()],
            bodies: Vec::new(),
        },
        initializer: Some("init".to_owned()),
        transferable_constructors: Vec::new(),
        results: vec![Vec::new(), Vec::new()],
    })
    .unwrap();
    let wasm: Vec<u8> = wat::parse_str(
        "(module (memory (export \"memory\") 1 2) (func (export \"init\")) (func (export \"run\")))",
    )
    .unwrap();
    let args: Vec<u8> = encode_call_value(&empty_layout, &CallValue::Tuple(Vec::new())).unwrap();
    let access: Vec<u8> = encode_access_manifest(&AccessManifest::new()).unwrap();
    fs::write(directory.join("contract.wasm"), wasm).unwrap();
    fs::write(directory.join("contract.abi"), abi).unwrap();
    fs::write(directory.join("args"), args).unwrap();
    fs::write(directory.join("access"), access).unwrap();

    let boot = boot_local_store(&config).unwrap();
    let generation = boot.boot_generation();
    let protocol =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
    let module =
        build_standard_asset_module(protocol, STANDARD_ASSET_MODULE_WASM.to_vec()).unwrap();
    let resolver = module.resolver().clone();
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(sunrise_edge_devnet::genesis::DEVNET_DOMAIN_BYTES).unwrap();
    let operation = |sequence: u8| -> DurableOperationContext {
        DurableOperationContext::new(
            generation,
            StorageDeadline::new(SystemClock.now_unix_millis().unwrap() + 30_000).unwrap(),
            StorageCorrelationId::new([sequence; 16]).unwrap(),
        )
    };
    verify_or_seed_protocol_context(
        boot.store(),
        &resolver,
        config.epoch(),
        generation,
        &operation(1),
        true,
    )
    .unwrap();
    let context: PublicationContext = PublicationContext::new(
        config.chain_id().clone(),
        resolver.protocol_version(),
        config.epoch(),
    )
    .unwrap();
    let activation = install_paid_contracts(
        boot.store(),
        &operation(2),
        domain,
        &resolver,
        &context,
        config.dev_owners(),
        config.fee_treasury_owner(),
    )
    .unwrap();
    let fee_coin: ObjectId = activation.fee_coins[0].1;
    let (store, blobs) = boot.into_parts();
    let router = compose_devnet_router_with_contract_policies(
        Arc::new(store),
        Arc::new(blobs),
        module,
        generation,
        4,
        2,
        ObjectId::new([0xFE; 32]),
        None,
        None,
        Some(native_http::PaidExecutionComposition::new(
            activation.base_policy,
            activation.fee_policy,
        )),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint: String = listener.local_addr().unwrap().to_string();
    let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(native_http::serve_with_policy(
        listener,
        router,
        native_http::NativeHttpServePolicy::default(),
        async {
            let _ignored = shutdown.await;
        },
    ));

    let path: PathBuf = directory.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let file = |name: &str| -> String { path.join(name).display().to_string() };
        let invoke = |action: &str, extra: Vec<String>| {
            let mut values: Vec<String> = vec![
                "contract".to_owned(),
                action.to_owned(),
                "--endpoint".to_owned(),
                endpoint.clone(),
                "--expected-chain-id".to_owned(),
                "cli-paid-contract".to_owned(),
                "--expected-protocol-version".to_owned(),
                resolver.protocol_version().get().to_string(),
                "--expected-epoch".to_owned(),
                "0".to_owned(),
                "--expected-hash-suite-id".to_owned(),
                "1".to_owned(),
                "--expected-domain".to_owned(),
                domain.to_string(),
                "--seed-file".to_owned(),
                file("seed"),
                "--fee-source".to_owned(),
                fee_coin.to_string(),
                "--fee-access".to_owned(),
                "write".to_owned(),
                "--max-fee".to_owned(),
                "1000000".to_owned(),
                "--gas-limit".to_owned(),
                "200000".to_owned(),
            ];
            values.extend(extra);
            sunrise_edge_cli::run(values.into_iter().map(OsString::from)).unwrap();
        };
        invoke(
            "paid-publish",
            vec![
                "--request-id".into(),
                "41".repeat(32),
                "--nonce".into(),
                "0".into(),
                "--wasm".into(),
                file("contract.wasm"),
                "--abi".into(),
                file("contract.abi"),
                "--entrypoints".into(),
                "init,run".into(),
                "--origin-seed".into(),
                "31".repeat(32),
                "--dependency-ref-out".into(),
                file("contract.ref"),
                "--result-out".into(),
                file("publish.result"),
                "--submission-out".into(),
                file("publish.signed"),
            ],
        );
        invoke(
            "paid-instantiate",
            vec![
                "--request-id".into(),
                "42".repeat(32),
                "--nonce".into(),
                "1".into(),
                "--code-ref".into(),
                file("contract.ref"),
                "--instance-seed".into(),
                "32".repeat(32),
                "--args".into(),
                file("args"),
                "--instance-ref-out".into(),
                file("instance.ref"),
                "--result-out".into(),
                file("instantiate.result"),
                "--submission-out".into(),
                file("instantiate.signed"),
            ],
        );
        invoke(
            "paid-call",
            vec![
                "--request-id".into(),
                "43".repeat(32),
                "--nonce".into(),
                "2".into(),
                "--instance-ref".into(),
                file("instance.ref"),
                "--entrypoint".into(),
                "run".into(),
                "--access".into(),
                file("access"),
                "--args".into(),
                file("args"),
                "--result-out".into(),
                file("call.result"),
                "--submission-out".into(),
                file("call.signed"),
            ],
        );
        for name in ["publish.result", "instantiate.result", "call.result"] {
            let result: PaidExecutionResult =
                decode_paid_execution_result(&fs::read(file(name)).unwrap()).unwrap();
            assert_eq!(result.status, PaidExecutionStatus::Success);
            assert!(result.charged.is_some());
        }
    })
    .await;
    let _ignored = stop.send(());
    server.await.unwrap().unwrap();
    outcome.unwrap();
}
