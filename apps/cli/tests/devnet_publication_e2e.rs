//! CLI publication and exact replay across real file-backed SQLite restarts.

use abi::{
    call_values::{CallAbi, ValueLayout, encode_call_abi},
    public_abi::{EntrypointDeclaration, PackageAbi},
};
use runtime::{DurableOperationContext, StorageCorrelationId, StorageDeadline};
use std::{ffi::OsString, fs, path::PathBuf, sync::Arc};
use sunrise_edge_client::{LocalSigner, PackageOrigin};
use sunrise_edge_devnet::{
    DevnetConfig, STANDARD_ASSET_MODULE_WASM, boot_local_store, build_devnet_protocol_context,
    build_standard_asset_module, compose_devnet_router_with_publication,
};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_publish_query_dependency_and_exact_replay_survive_sqlite_restart() {
    let directory = Directory(std::env::temp_dir().join(format!(
        "sunrise-publication-product-{}",
        std::process::id()
    )));
    fs::create_dir_all(&directory.0).unwrap();
    let signer: LocalSigner = LocalSigner::from_seed([7; 32]);
    let treasury: LocalSigner = LocalSigner::from_seed([8; 32]);
    let args: Vec<String> = vec![
        "--data-dir".into(),
        directory.0.display().to_string(),
        "--listen".into(),
        "127.0.0.1:7400".into(),
        "--chain-id".into(),
        "publication-product".into(),
        "--epoch".into(),
        "9".into(),
        "--dev-owner".into(),
        signer.address().to_string(),
        "--fee-treasury-owner".into(),
        treasury.address().to_string(),
        "--max-concurrent".into(),
        "4".into(),
        "--enable-local-publication".into(),
    ];
    let config = DevnetConfig::parse_from(args).unwrap();
    assert!(config.local_publication());
    let seed_path = directory.0.join("seed");
    fs::write(&seed_path, "07".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let wasm_hex: &str = "0061736d0100000001040160000003020100050401010102071002066d656d6f727902000372756e00000a040102000b";
    let wasm: Vec<u8> = (0..wasm_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&wasm_hex[i..i + 2], 16).unwrap())
        .collect();
    fs::write(directory.0.join("module.wasm"), wasm).unwrap();
    for seed in [2_u8, 3] {
        let origin = PackageOrigin::unverified(
            config.chain_id().clone(),
            *signer.address().as_bytes(),
            [seed; 32],
        )
        .unwrap();
        let abi = CallAbi {
            objects: PackageAbi {
                origin,
                constructors: vec![],
                entrypoints: vec![EntrypointDeclaration {
                    name: "run".into(),
                    type_parameters: vec![],
                    objects: vec![],
                }],
            },
            arguments: vec![ValueLayout::Tuple(vec![])],
            bodies: vec![],
        };
        fs::write(
            directory.0.join(format!("abi{seed}")),
            encode_call_abi(&abi).unwrap(),
        )
        .unwrap();
    }
    let mut original_policy: Option<Vec<u8>> = None;
    for boot_index in 0..3 {
        let boot = boot_local_store(&config).unwrap();
        let generation = boot.boot_generation();
        let context =
            build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap();
        let module =
            build_standard_asset_module(context, STANDARD_ASSET_MODULE_WASM.to_vec()).unwrap();
        let protocol_version = module.resolver().protocol_version().get().to_string();
        let operation = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([9; 16]).unwrap(),
        );
        let domain = sunrise_edge_client::AtomicityDomainId::new(
            sunrise_edge_devnet::genesis::DEVNET_DOMAIN_BYTES,
        )
        .unwrap();
        let policy = sunrise_edge_devnet::publication::seed_local_publication_policy(
            boot.store(),
            &operation,
            domain,
            module.resolver(),
            config.epoch(),
        )
        .unwrap();
        if let Some(original) = &original_policy {
            assert_eq!(&policy.encode().unwrap(), original);
        } else {
            original_policy = Some(policy.encode().unwrap());
        }
        let (store, blobs) = boot.into_parts();
        let router = compose_devnet_router_with_publication(
            Arc::new(store),
            Arc::new(blobs),
            module,
            generation,
            4,
            4,
            objects::ObjectId::new([0xfe; 32]),
            if boot_index < 2 { Some(policy) } else { None },
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(native_http::serve(listener, router, async {
            let _ = shutdown.await;
        }));
        let directory_path = directory.0.clone();
        let publisher = signer.address().to_string();
        tokio::task::spawn_blocking(move || {
            let base: Vec<String> = vec![
                "--endpoint".into(),
                endpoint,
                "--expected-chain-id".into(),
                "publication-product".into(),
                "--expected-protocol-version".into(),
                protocol_version,
                "--expected-epoch".into(),
                "9".into(),
                "--expected-hash-suite-id".into(),
                "1".into(),
                "--expected-domain".into(),
                domain.to_string(),
            ];
            let invoke = |action: &str, extra: Vec<String>| {
                let mut args: Vec<OsString> = vec!["contract".into(), action.into()];
                args.extend(base.iter().map(OsString::from));
                args.extend(extra.into_iter().map(OsString::from));
                sunrise_edge_cli::run(args).map_err(Box::new)
            };
            let publish = |seed: u8, nonce: u64, dependency: bool| {
                let mut flags = vec![
                    "--seed-file".into(),
                    directory_path.join("seed").display().to_string(),
                    "--wasm".into(),
                    directory_path.join("module.wasm").display().to_string(),
                    "--abi".into(),
                    directory_path
                        .join(format!("abi{seed}"))
                        .display()
                        .to_string(),
                    "--entrypoints".into(),
                    "run".into(),
                    "--origin-seed".into(),
                    format!("{seed:02x}").repeat(32),
                    "--request-id".into(),
                    format!("{seed:02x}").repeat(32),
                    "--nonce".into(),
                    nonce.to_string(),
                ];
                if dependency {
                    flags.extend([
                        "--dependencies".into(),
                        directory_path.join("dependency").display().to_string(),
                    ]);
                }
                invoke("publish", flags)
            };
            if boot_index == 2 {
                assert!(
                    publish(2, 0, false).is_err(),
                    "publication is opt-in even for an existing store"
                );
                return;
            }
            publish(2, 0, false).unwrap();
            publish(2, 0, false).unwrap();
            let mut query_flags = vec![
                "--publisher".into(),
                publisher.clone(),
                "--origin-seed".into(),
                "02".repeat(32),
            ];
            if boot_index == 0 {
                query_flags.extend([
                    "--dependency-ref-out".into(),
                    directory_path.join("dependency").display().to_string(),
                ]);
            }
            invoke("query", query_flags).unwrap();
            publish(3, 1, true).unwrap();
            // Same request id with a different nonce is never exact replay.
            assert!(publish(2, 2, false).is_err());
            invoke(
                "query",
                vec![
                    "--publisher".into(),
                    publisher,
                    "--origin-seed".into(),
                    "03".repeat(32),
                ],
            )
            .unwrap();
        })
        .await
        .unwrap();
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
