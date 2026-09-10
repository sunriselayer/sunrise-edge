//! Real CLI/HTTP inventory composition, scoped rollback and exact SQLite replay.
#[path = "../../../crates/execution/tests/common/general_inventory.rs"]
mod inventory;

use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::{AccessEntry, AccessManifest, encode_access_manifest};
use execution::call_authorization::{
    AuthorizedObject, CallAuthorization, ExecutionTarget, encode_call_authorizations,
};
use execution::local_execution::*;
use execution::{ExecutionStatus, ObjectEffect};
use hashing::HashSuiteResolver;
use objects::{AccessMode, Object, ObjectId, ObjectRef};
use protocol_types::{AtomicityDomainId, Epoch, HashPurpose};
use runtime::{
    DurableDomainStateStore, DurableObjectVersion, DurableOperationContext, DurableRequestId,
    PersistenceLayout, StorageCorrelationId, StorageDeadline, StructuredDurableDomainStateStore,
};
use std::{
    collections::BTreeSet,
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

/// Construct only after this test successfully creates its unique directory.
struct OwnedDirectory(PathBuf);
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _removed: Result<(), std::io::Error> = fs::remove_dir_all(&self.0);
        }
    }
}

fn surviving(effect: &ObjectEffect) -> Option<Object> {
    match effect {
        ObjectEffect::Created(object)
        | ObjectEffect::Mutated {
            new_object: object, ..
        } => Some(object.clone()),
        _ => None,
    }
}
fn created(result: &LocalExecutionResult) -> Vec<Object> {
    result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created(object) => Some(object.clone()),
            _ => None,
        })
        .collect()
}
fn access(path: &Path, resolver: &HashSuiteResolver, entries: &[(&Object, AccessMode)]) {
    let manifest: AccessManifest = AccessManifest {
        entries: entries
            .iter()
            .map(|(object, mode)| AccessEntry {
                object_ref: ObjectRef {
                    id: object.id,
                    version: object.version,
                    digest: resolver
                        .hash_for_purpose(
                            Epoch::new(9),
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
fn authority<S: DurableDomainStateStore>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    id: ObjectId,
) -> ObjectAuthority {
    let row = store
        .get_versioned_durable(
            operation,
            domain,
            &node_core::local_instance_state::object_authority_key(id),
        )
        .unwrap();
    decode_object_authority(row.value().unwrap()).unwrap()
}
fn objects_snapshot<S: StructuredDurableDomainStateStore>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    ids: &[ObjectId],
) -> Vec<String> {
    let mut snapshot: Vec<String> = Vec::new();
    for id in ids {
        snapshot.push(format!(
            "{:?}",
            store.get_object_head(operation, domain, *id).unwrap()
        ));
        snapshot.push(format!(
            "{:?}",
            store
                .get_versioned_durable(
                    operation,
                    domain,
                    &node_core::local_instance_state::object_authority_key(*id)
                )
                .unwrap()
        ));
        for version in 1..=3 {
            snapshot.push(format!(
                "{:?}",
                store
                    .get_object_version(
                        operation,
                        domain,
                        *id,
                        DurableObjectVersion::new(version).unwrap()
                    )
                    .unwrap()
            ));
        }
    }
    snapshot
}
fn snapshot<S: StructuredDurableDomainStateStore>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    ids: &[ObjectId],
    resolver: &HashSuiteResolver,
    sender: objects::Address,
) -> Vec<String> {
    let mut snapshot: Vec<String> = objects_snapshot(store, operation, domain, ids);
    let key: Vec<u8> =
        PersistenceLayout::new(resolver.chain_id().clone(), resolver.protocol_version())
            .sender_nonce_key(*sender.as_bytes(), Epoch::new(9));
    snapshot.push(format!(
        "{:?}",
        store
            .get_versioned_durable(operation, domain, &key)
            .unwrap()
    ));
    for byte in [1, 2, 12, 13, 14, 15, 16, 17] {
        snapshot.push(format!(
            "{:?}",
            store
                .get_request_receipt(
                    operation,
                    domain,
                    DurableRequestId::new([byte; 32]).unwrap()
                )
                .unwrap()
        ));
    }
    snapshot
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_general_inventory_scopes_rollback_and_exact_restart_replay() {
    // Kept on disk on failure for inspection; unique names avoid overwriting prior runs.
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "sunrise-cli-general-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let _owned_directory: OwnedDirectory = OwnedDirectory(directory.clone());
    let signer: LocalSigner = LocalSigner::from_seed([7; 32]);
    let recipient: LocalSigner = LocalSigner::from_seed([9; 32]);
    let config: DevnetConfig = DevnetConfig::parse_from(vec![
        "--data-dir".into(),
        directory.display().to_string(),
        "--listen".into(),
        "127.0.0.1:7400".into(),
        "--chain-id".into(),
        "cli-general-inventory".into(),
        "--epoch".into(),
        "9".into(),
        "--dev-owner".into(),
        signer.address().to_string(),
        "--fee-treasury-owner".into(),
        recipient.address().to_string(),
        "--enable-general-calls".into(),
        "--max-concurrent".into(),
        "4".into(),
    ])
    .unwrap();
    fs::write(directory.join("seed"), "07".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.join("seed"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let origin = |seed: u8| -> PackageOrigin {
        PackageOrigin::unverified(
            config.chain_id().clone(),
            *signer.address().as_bytes(),
            [seed; 32],
        )
        .unwrap()
    };
    for (name, package) in [
        ("policy", inventory::dispatch_policy(&origin(2))),
        ("warehouse", inventory::warehouse(&origin(1), &origin(2), 0)),
    ] {
        fs::write(directory.join(format!("{name}.wat")), &package.wat).unwrap();
        fs::write(directory.join(format!("{name}.wasm")), &package.wasm).unwrap();
        let entrypoints: usize = package.abi.objects.entrypoints.len();
        fs::write(
            directory.join(format!("{name}.abi")),
            encode_executable_abi(&ExecutableAbi {
                call: package.abi,
                initializer: package.initializer,
                transferable_constructors: package.transferable_constructors,
                results: vec![Vec::new(); entrypoints],
            })
            .unwrap(),
        )
        .unwrap();
    }
    for (name, bytes) in [
        ("init", inventory::tuple_arguments(&[42, 100])),
        ("configure", inventory::scalar_argument(20)),
        ("reserve", inventory::tuple_arguments(&[1001, 12])),
        ("large", inventory::tuple_arguments(&[1002, 25])),
        ("empty", inventory::tuple_arguments(&[])),
        (
            "recipient",
            inventory::recipient_argument(*recipient.address().as_bytes()),
        ),
    ] {
        fs::write(directory.join(name), bytes).unwrap();
    }
    let mut final_ids: Vec<ObjectId> = Vec::new();
    let mut final_snapshot: Vec<String> = Vec::new();
    let mut previous_operation: Option<DurableOperationContext> = None;
    for boot_index in 0..2 {
        let boot = boot_local_store(&config).unwrap();
        let generation = boot.boot_generation();
        let module = build_standard_asset_module(
            build_devnet_protocol_context(config.chain_id().clone(), config.epoch()).unwrap(),
            STANDARD_ASSET_MODULE_WASM.to_vec(),
        )
        .unwrap();
        let resolver: HashSuiteResolver = module.resolver().clone();
        let domain: AtomicityDomainId =
            AtomicityDomainId::new(sunrise_edge_devnet::genesis::DEVNET_DOMAIN_BYTES).unwrap();
        let operation: DurableOperationContext = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([9; 16]).unwrap(),
        );
        if let Some(stale) = &previous_operation {
            assert!(
                boot.store()
                    .get_versioned_durable(stale, domain, b"fence-probe")
                    .is_err()
            );
        }
        let local = sunrise_edge_devnet::local_execution::seed_local_execution_policies(
            boot.store(),
            &operation,
            domain,
            &resolver,
            config.epoch(),
        )
        .unwrap();
        let general_operation: DurableOperationContext = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([10; 16]).unwrap(),
        );
        let general = sunrise_edge_devnet::local_execution::seed_general_execution_policies(
            boot.store(),
            &general_operation,
            domain,
            &resolver,
            config.epoch(),
        )
        .unwrap();
        let (store, blobs) = boot.into_parts();
        let store = Arc::new(store);
        if boot_index == 1 {
            assert_eq!(
                snapshot(
                    store.as_ref(),
                    &operation,
                    domain,
                    &final_ids,
                    &resolver,
                    signer.address()
                ),
                final_snapshot
            );
        }
        let router =
            sunrise_edge_devnet::composition::compose_devnet_router_with_execution_policies(
                store.clone(),
                Arc::new(blobs),
                module,
                generation,
                4,
                6,
                ObjectId::new([0xfe; 32]),
                None,
                Some(
                    native_http::LocalExecutionComposition::new(local.0, local.1)
                        .with_policy(general.0, general.1),
                ),
            )
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint: String = listener.local_addr().unwrap().to_string();
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
        let path: PathBuf = directory.clone();
        let sender = signer.address();
        let saved_operation: DurableOperationContext = operation;
        let outcome = tokio::task::spawn_blocking(move || {
            let file = |name: &str| -> String { path.join(name).display().to_string() };
            let invoke = |action: &str, extra: Vec<String>| {
                let mut args: Vec<OsString> =
                    vec!["contract".into(), action.into(), "--general-calls".into()];
                args.extend(
                    [
                        "--endpoint".into(),
                        endpoint.clone(),
                        "--expected-chain-id".into(),
                        "cli-general-inventory".into(),
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
                let mut flags: Vec<String> = vec![
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
                            "--publisher".into(),
                            sender.to_string(),
                            "--origin-seed".into(),
                            format!("{seed:02x}").repeat(32),
                            "--dependency-ref-out".into(),
                            file(&format!("{name}.ref")),
                        ],
                    )
                    .unwrap();
                }
            }
            let flags = |name: &str, nonce: u64, argument: &str| -> (&str, Vec<String>) {
                let mut flags: Vec<String> = vec![
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
                ];
                if name == "init" || name == "configure" {
                    let (package, seed) = if name == "init" {
                        ("warehouse", "03")
                    } else {
                        ("policy", "04")
                    };
                    flags.extend([
                        "--code-ref".into(),
                        file(&format!("{package}.ref")),
                        "--instance-seed".into(),
                        seed.repeat(32),
                    ]);
                    ("instantiate", flags)
                } else {
                    flags.extend([
                        "--instance-ref".into(),
                        file("warehouse-instance-0"),
                        "--entrypoint".into(),
                        name.into(),
                        "--access".into(),
                        file(&format!("access-{nonce}")),
                    ]);
                    if name == "fulfil" {
                        flags.extend([
                            "--authorizations".into(),
                            file(&format!("authorization-{nonce}")),
                        ]);
                    }
                    ("call", flags)
                }
            };
            let execute = |name: &str,
                           nonce: u64,
                           argument: &str,
                           trapped: bool,
                           attempt: usize|
             -> LocalExecutionResult {
                let (action, mut args) = flags(name, nonce, argument);
                args.extend([
                    "--result-out".into(),
                    file(&format!("result-{nonce}-{attempt}")),
                    "--submission-out".into(),
                    file(&format!("signed-{nonce}-{attempt}")),
                ]);
                let result = invoke(action, args);
                assert_eq!(result.is_err(), trapped, "{name} nonce {nonce}: {result:?}");
                let bytes: Vec<u8> = fs::read(file(&format!("result-{nonce}-{attempt}"))).unwrap();
                if attempt != 0 {
                    assert_eq!(bytes, fs::read(file(&format!("result-{nonce}-0"))).unwrap());
                    assert_eq!(
                        fs::read(file(&format!("signed-{nonce}-{attempt}"))).unwrap(),
                        fs::read(file(&format!("signed-{nonce}-0"))).unwrap()
                    );
                }
                decode_local_execution_result(&bytes).unwrap()
            };
            let initial = execute("init", 2, "init", false, boot_index);
            let configured = execute("configure", 3, "configure", false, boot_index);
            let mut records: Vec<InstanceRecord> = Vec::new();
            for (name, seed) in [("warehouse", "03"), ("policy", "04")] {
                invoke(
                    "query-instance",
                    vec![
                        "--creator".into(),
                        sender.to_string(),
                        "--instance-seed".into(),
                        seed.repeat(32),
                        "--instance-ref-out".into(),
                        file(&format!("{name}-instance-{boot_index}")),
                    ],
                )
                .unwrap();
                let bytes: Vec<u8> =
                    fs::read(file(&format!("{name}-instance-{boot_index}"))).unwrap();
                if boot_index == 1 {
                    assert_eq!(
                        bytes,
                        fs::read(file(&format!("{name}-instance-0"))).unwrap()
                    );
                }
                records.push(decode_instance_record(&bytes).unwrap());
            }
            let cap: Object = created(&initial)[0].clone();
            let stock: Object = created(&initial)[1].clone();
            assert_eq!(
                created(&initial).len(),
                2,
                "warehouse initializer cannot create policy state"
            );
            let policy: Object = created(&configured)[0].clone();
            let root_target = instance_target(&resolver, &records[0]).unwrap();
            let policy_target = instance_target(&resolver, &records[1]).unwrap();
            assert_ne!(root_target, policy_target);
            assert_eq!(
                authority(store.as_ref(), &operation, domain, policy.id).instance,
                policy_target
            );
            let authorize = |nonce: u64, reservation: &Object, policy: &Object| {
                access(
                    &path.join(format!("access-{nonce}")),
                    &resolver,
                    &[
                        (&cap, AccessMode::Read),
                        (reservation, AccessMode::Consume),
                        (policy, AccessMode::Write),
                    ],
                );
                let authorization: CallAuthorization = CallAuthorization {
                    caller: ExecutionTarget {
                        instance: root_target.clone(),
                        code: records[0].code.clone(),
                    },
                    callee: ExecutionTarget {
                        instance: policy_target.clone(),
                        code: records[1].code.clone(),
                    },
                    entrypoint: "approve".into(),
                    type_arguments: vec![],
                    objects: vec![AuthorizedObject {
                        object_id: policy.id,
                        mode: AccessMode::Write,
                    }],
                };
                fs::write(
                    path.join(format!("authorization-{nonce}")),
                    encode_call_authorizations(&[authorization]).unwrap(),
                )
                .unwrap();
            };
            if boot_index == 0 {
                access(
                    &path.join("access-4"),
                    &resolver,
                    &[(&cap, AccessMode::Read), (&stock, AccessMode::Write)],
                );
            }
            let reserved = execute("reserve", 4, "reserve", false, boot_index);
            let stock: Object = reserved
                .effects
                .object_effects
                .iter()
                .find_map(surviving)
                .unwrap();
            let reservation: Object = created(&reserved)[0].clone();
            if boot_index == 0 {
                authorize(5, &reservation, &policy);
            }
            let fulfilled = execute("fulfil", 5, "empty", false, boot_index);
            assert!(matches!(fulfilled.effects.status, ExecutionStatus::Success));
            let policy: Object = fulfilled
                .effects
                .object_effects
                .iter()
                .find_map(|effect| match effect {
                    ObjectEffect::Mutated { new_object, .. } if new_object.id == policy.id => {
                        Some(new_object.clone())
                    }
                    _ => None,
                })
                .unwrap();
            assert_eq!(policy.data, inventory::tuple_arguments(&[20, 12]));
            let outputs: Vec<Object> = created(&fulfilled);
            assert_eq!(outputs.len(), 2);
            let approval: &Object = &outputs[0];
            let shipment: &Object = &outputs[1];
            assert_eq!(approval.data, inventory::tuple_arguments(&[12, 12]));
            assert_eq!(shipment.data, inventory::tuple_arguments(&[1001, 42, 12]));
            let approval_authority = authority(store.as_ref(), &operation, domain, approval.id);
            assert_eq!(approval_authority.instance, policy_target);
            assert_eq!(approval_authority.code, records[1].code);
            let shipment_authority = authority(store.as_ref(), &operation, domain, shipment.id);
            assert_eq!(shipment_authority.instance, root_target);
            assert_eq!(shipment_authority.code, records[0].code);
            if boot_index == 0 {
                access(
                    &path.join("access-6"),
                    &resolver,
                    &[(&cap, AccessMode::Read), (&stock, AccessMode::Write)],
                );
            }
            let large = execute("reserve", 6, "large", false, boot_index);
            let large_reservation: Object = created(&large)[0].clone();
            if boot_index == 0 {
                authorize(7, &large_reservation, &policy);
            }
            let ids: Vec<ObjectId> = [&initial, &configured, &reserved, &fulfilled, &large]
                .iter()
                .flat_map(|result| created(result))
                .map(|object| object.id)
                .collect::<BTreeSet<ObjectId>>()
                .into_iter()
                .collect();
            let before_trap = objects_snapshot(store.as_ref(), &operation, domain, &ids);
            let rejected = execute("fulfil", 7, "empty", true, boot_index);
            assert!(matches!(
                rejected.effects.status,
                ExecutionStatus::Failure { .. }
            ));
            assert!(
                rejected.effects.object_effects.is_empty() && rejected.effects.events.is_empty()
            );
            assert_eq!(
                objects_snapshot(store.as_ref(), &operation, domain, &ids),
                before_trap
            );
            let trap_signed =
                decode_signed_local_execution(&fs::read(file("signed-7-0")).unwrap()).unwrap();
            let forbidden_id: ObjectId = derive_local_created_object_id(
                &resolver,
                &trap_signed.intent.call.context,
                &records[1].context,
                &policy_target,
                &records[1].code,
                rejected.effects.tx_hash,
                0,
            )
            .unwrap();
            assert!(
                store
                    .get_versioned_durable(
                        &operation,
                        domain,
                        &node_core::local_instance_state::object_authority_key(forbidden_id)
                    )
                    .unwrap()
                    .value()
                    .is_none()
            );
            let mut ids = ids;
            ids.push(forbidden_id);
            let stable = snapshot(store.as_ref(), &operation, domain, &ids, &resolver, sender);
            if boot_index == 0 {
                execute("fulfil", 5, "empty", false, 2);
                execute("fulfil", 7, "empty", true, 2);
                assert_eq!(
                    snapshot(store.as_ref(), &operation, domain, &ids, &resolver, sender),
                    stable
                );
            }
            let (action, mut conflict) = flags("fulfil", 5, "empty");
            let gas_index: usize = conflict
                .iter()
                .position(|value| value == "1000000")
                .unwrap();
            conflict[gas_index] = "999999".into();
            let conflict_error = invoke(action, conflict).unwrap_err();
            assert!(
                conflict_error.to_string().contains("HTTP status 409"),
                "same request ID with different signed bytes must conflict: {conflict_error}"
            );
            assert_eq!(
                snapshot(store.as_ref(), &operation, domain, &ids, &resolver, sender),
                stable
            );
            (ids, stable)
        })
        .await
        .unwrap();
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
        if boot_index == 1 {
            assert_eq!(outcome.1, final_snapshot);
        }
        final_ids = outcome.0;
        final_snapshot = outcome.1;
        previous_operation = Some(saved_operation);
    }
}
