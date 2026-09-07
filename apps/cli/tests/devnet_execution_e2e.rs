//! Real CLI files and HTTP: inventory execution and exact replay after SQLite reopen.
#[path = "../../../crates/execution/tests/common/inventory.rs"]
mod inventory;

use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::{AccessEntry, AccessManifest, encode_access_manifest};
use execution::local_execution::{LocalExecutionResult, decode_local_execution_result};
use execution::{ExecutionStatus, ObjectEffect};
use hashing::HashSuiteResolver;
use objects::{AccessMode, Object, ObjectRef};
use protocol_types::HashPurpose;
use runtime::{DurableOperationContext, StorageCorrelationId, StorageDeadline};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use sunrise_edge_client::{LocalSigner, PackageOrigin};
use sunrise_edge_devnet::{
    DevnetConfig, STANDARD_ASSET_MODULE_WASM, boot_local_store, build_devnet_protocol_context,
    build_standard_asset_module,
};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn object(effect: &ObjectEffect) -> Object {
    match effect {
        ObjectEffect::Created(value)
        | ObjectEffect::Mutated {
            new_object: value, ..
        } => value.clone(),
        _ => panic!("expected surviving object"),
    }
}
fn access(path: &Path, resolver: &HashSuiteResolver, entries: &[(&Object, AccessMode)]) {
    let manifest = AccessManifest {
        entries: entries
            .iter()
            .map(|(object, mode)| AccessEntry {
                object_ref: ObjectRef {
                    id: object.id,
                    version: object.version,
                    digest: resolver
                        .hash_for_purpose(
                            protocol_types::Epoch::new(9),
                            HashPurpose::Object,
                            &objects::encode_object(object).unwrap(),
                        )
                        .unwrap(),
                },
                mode: *mode,
            })
            .collect(),
    };
    fs::write(path, encode_access_manifest(&manifest).unwrap()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_inventory_success_trap_and_exact_files_survive_restart() {
    let directory = Directory(
        std::env::temp_dir().join(format!("sunrise-cli-execution-{}", std::process::id())),
    );
    fs::create_dir(&directory.0).unwrap();
    let signer = LocalSigner::from_seed([7; 32]);
    let recipient = LocalSigner::from_seed([9; 32]);
    let config = DevnetConfig::parse_from(vec![
        "--data-dir".into(),
        directory.0.display().to_string(),
        "--listen".into(),
        "127.0.0.1:7400".into(),
        "--chain-id".into(),
        "cli-inventory".into(),
        "--epoch".into(),
        "9".into(),
        "--dev-owner".into(),
        signer.address().to_string(),
        "--fee-treasury-owner".into(),
        recipient.address().to_string(),
        "--enable-local-execution".into(),
        "--max-concurrent".into(),
        "4".into(),
    ])
    .unwrap();
    fs::write(directory.0.join("seed"), "07".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.0.join("seed"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let origin = |seed: u8| {
        PackageOrigin::unverified(
            config.chain_id().clone(),
            *signer.address().as_bytes(),
            [seed; 32],
        )
        .unwrap()
    };
    for (name, package) in [
        ("policy", inventory::dispatch_policy(&origin(2))),
        ("warehouse", inventory::warehouse(&origin(1), &origin(2))),
    ] {
        fs::write(directory.0.join(format!("{name}.wat")), &package.wat).unwrap();
        fs::write(directory.0.join(format!("{name}.wasm")), &package.wasm).unwrap();
        fs::write(
            directory.0.join(format!("{name}.abi")),
            encode_executable_abi(&ExecutableAbi {
                call: package.abi,
                initializer: package.initializer,
                transferable_constructors: package.transferable_constructors,
            })
            .unwrap(),
        )
        .unwrap();
    }
    for (name, bytes) in [
        ("init", inventory::tuple_arguments(&[42, 100, 20])),
        ("reserve", inventory::tuple_arguments(&[1001, 12])),
        ("large", inventory::tuple_arguments(&[1002, 25])),
        ("empty", inventory::tuple_arguments(&[])),
        (
            "recipient",
            inventory::recipient_argument(*recipient.address().as_bytes()),
        ),
    ] {
        fs::write(directory.0.join(name), bytes).unwrap();
    }
    for boot_index in 0..2 {
        let boot = boot_local_store(&config).unwrap();
        let generation = boot.boot_generation();
        let module = build_standard_asset_module(
            build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap(),
            STANDARD_ASSET_MODULE_WASM.to_vec(),
        )
        .unwrap();
        let resolver = module.resolver().clone();
        let domain = sunrise_edge_client::AtomicityDomainId::new(
            sunrise_edge_devnet::genesis::DEVNET_DOMAIN_BYTES,
        )
        .unwrap();
        let operation = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([9; 16]).unwrap(),
        );
        let policies = sunrise_edge_devnet::local_execution::seed_local_execution_policies(
            boot.store(),
            &operation,
            domain,
            &resolver,
            config.epoch(),
        )
        .unwrap();
        let (store, blobs) = boot.into_parts();
        let router = sunrise_edge_devnet::composition::compose_devnet_router_with_local_execution(
            Arc::new(store),
            Arc::new(blobs),
            module,
            generation,
            4,
            5,
            objects::ObjectId::new([0xfe; 32]),
            None,
            Some(policies),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(native_http::serve_with_policy(
            listener,
            router,
            native_http::NativeHttpServePolicy::default()
                .with_local_publication(true)
                .with_local_execution(true),
            async {
                let _ = shutdown.await;
            },
        ));
        let path = directory.0.clone();
        let publisher = signer.address().to_string();
        tokio::task::spawn_blocking(move || {
            let file = |name: &str| path.join(name).display().to_string();
            let invoke = |action: &str, extra: Vec<String>| {
                let mut args: Vec<OsString> = vec!["contract".into(), action.into()];
                args.extend(
                    [
                        "--endpoint".into(),
                        endpoint.clone(),
                        "--expected-chain-id".into(),
                        "cli-inventory".into(),
                        "--expected-protocol-version".into(),
                        resolver.protocol_version().get().to_string(),
                        "--expected-epoch".into(),
                        "9".into(),
                        "--expected-hash-suite-id".into(),
                        "1".into(),
                        "--expected-domain".into(),
                        domain.to_string(),
                    ]
                    .into_iter()
                    .map(OsString::from),
                );
                args.extend(extra.into_iter().map(OsString::from));
                sunrise_edge_cli::run(args).map_err(Box::new)
            };
            for (name, seed, nonce, entries) in [
                ("policy", 2_u8, 0, "approve,configure"),
                ("warehouse", 1, 1, "fulfil,init,reserve,transfer"),
            ] {
                let mut flags = vec![
                    "--executable".into(),
                    "--seed-file".into(),
                    file("seed"),
                    "--wasm".into(),
                    file(&format!("{name}.wasm")),
                    "--abi".into(),
                    file(&format!("{name}.abi")),
                    "--entrypoints".into(),
                    entries.into(),
                    "--origin-seed".into(),
                    format!("{seed:02x}").repeat(32),
                    "--request-id".into(),
                    format!("{seed:02x}").repeat(32),
                    "--nonce".into(),
                    nonce.to_string(),
                ];
                if name == "warehouse" {
                    flags.extend(["--dependencies".into(), file("policy.ref")]);
                }
                invoke("publish", flags).unwrap();
                if boot_index == 0 {
                    invoke(
                        "query",
                        vec![
                            "--executable".into(),
                            "--publisher".into(),
                            publisher.clone(),
                            "--origin-seed".into(),
                            format!("{seed:02x}").repeat(32),
                            "--dependency-ref-out".into(),
                            file(&format!("{name}.ref")),
                        ],
                    )
                    .unwrap();
                }
            }
            let execute = |name: &str, nonce: u64, argument: &str, trapped: bool| {
                let mut flags = vec![
                    "--seed-file".into(),
                    file("seed"),
                    "--args".into(),
                    file(argument),
                    "--gas-limit".into(),
                    "1000000".into(),
                    "--request-id".into(),
                    format!("{:02x}", nonce + 10).repeat(32),
                    "--nonce".into(),
                    nonce.to_string(),
                    "--result-out".into(),
                    file(&format!("result-{nonce}-{boot_index}")),
                    "--submission-out".into(),
                    file(&format!("signed-{nonce}-{boot_index}")),
                ];
                let action = if name == "init" {
                    flags.extend([
                        "--code-ref".into(),
                        file("warehouse.ref"),
                        "--instance-seed".into(),
                        "03".repeat(32),
                    ]);
                    "instantiate"
                } else {
                    flags.extend([
                        "--instance-ref".into(),
                        file("instance-0"),
                        "--entrypoint".into(),
                        name.into(),
                        "--access".into(),
                        file(&format!("access-{nonce}")),
                    ]);
                    "call"
                };
                assert_eq!(invoke(action, flags).is_err(), trapped);
                let bytes = fs::read(file(&format!("result-{nonce}-{boot_index}"))).unwrap();
                if boot_index == 1 {
                    assert_eq!(bytes, fs::read(file(&format!("result-{nonce}-0"))).unwrap());
                    assert_eq!(
                        fs::read(file(&format!("signed-{nonce}-1"))).unwrap(),
                        fs::read(file(&format!("signed-{nonce}-0"))).unwrap()
                    );
                }
                decode_local_execution_result(&bytes).unwrap()
            };
            let initial = execute("init", 2, "init", false);
            invoke(
                "query-instance",
                vec![
                    "--creator".into(),
                    publisher,
                    "--instance-seed".into(),
                    "03".repeat(32),
                    "--instance-ref-out".into(),
                    file(&format!("instance-{boot_index}")),
                ],
            )
            .unwrap();
            let cap = object(&initial.effects.object_effects[0]);
            let stock = object(&initial.effects.object_effects[1]);
            let policy = object(&initial.effects.object_effects[2]);
            if boot_index == 0 {
                access(
                    &path.join("access-3"),
                    &resolver,
                    &[(&cap, AccessMode::Read), (&stock, AccessMode::Write)],
                );
            }
            let reserved = execute("reserve", 3, "reserve", false);
            let stock = object(&reserved.effects.object_effects[0]);
            let reservation = object(&reserved.effects.object_effects[1]);
            if boot_index == 0 {
                access(
                    &path.join("access-4"),
                    &resolver,
                    &[
                        (&cap, AccessMode::Read),
                        (&reservation, AccessMode::Consume),
                        (&policy, AccessMode::Read),
                    ],
                );
            }
            let fulfilled = execute("fulfil", 4, "empty", false);
            let shipment = object(&fulfilled.effects.object_effects[1]);
            if boot_index == 0 {
                access(
                    &path.join("access-5"),
                    &resolver,
                    &[(&shipment, AccessMode::Write)],
                );
            }
            let transferred = execute("transfer", 5, "recipient", false);
            assert_ne!(
                object(&transferred.effects.object_effects[0]).owner,
                shipment.owner
            );
            if boot_index == 0 {
                access(
                    &path.join("access-6"),
                    &resolver,
                    &[(&cap, AccessMode::Read), (&stock, AccessMode::Write)],
                );
            }
            let large = execute("reserve", 6, "large", false);
            let reservation = object(&large.effects.object_effects[1]);
            if boot_index == 0 {
                access(
                    &path.join("access-7"),
                    &resolver,
                    &[
                        (&cap, AccessMode::Read),
                        (&reservation, AccessMode::Consume),
                        (&policy, AccessMode::Read),
                    ],
                );
            }
            let rejected: LocalExecutionResult = execute("fulfil", 7, "empty", true);
            assert!(matches!(
                rejected.effects.status,
                ExecutionStatus::Failure { .. }
            ));
            assert!(
                rejected.effects.object_effects.is_empty() && rejected.effects.events.is_empty()
            );
        })
        .await
        .unwrap();
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
    assert_eq!(
        fs::read(directory.0.join("instance-0")).unwrap(),
        fs::read(directory.0.join("instance-1")).unwrap()
    );
}
