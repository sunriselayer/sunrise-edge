//! ADR0264 selected actual multi-UID component fixture. Ignored by ordinary
//! validation: only the bounded reviewed Docker controller supplies its inputs.
//! No release executable, signing service, authority token or host setup.
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[allow(dead_code)]
#[path = "support/https_relay.rs"]
mod https_relay;
#[path = "support/offline_genesis_fixture.rs"]
mod offline_genesis_fixture;
#[path = "support/sqlite_durable_image.rs"]
mod sqlite_durable_image;

use canonical_encoding::{decode_canonical_frame, decode_digest32};
use consensus::{
    ConsensusMessage, ConsensusVote, Ed25519ConsensusVerifier, QuorumCertificate,
    UnsupportedSignatureSchemeResponse, decode_proposal, decode_quorum_certificate, decode_vote,
    encode_proposal, encode_quorum_certificate, encode_vote,
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::ordered_economics::{
    OrderedEconomicsPolicy, OrderedProposal, decode_ordered_event_output, decode_ordered_proposal,
    decode_ordered_status, encode_ordered_proposal,
};
use node_wire::ordered_economics::*;
use offline_genesis_fixture::{Fixture, hex};
use protocol_types::{AtomicityDomainId, ChainId, Epoch, ProtocolVersion, ValidatorId};
use rusqlite::{Connection, OpenFlags};
use sqlite_durable_image::{AnchorImage, Image};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::SocketAddr,
    num::NonZeroUsize,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use sunrise_edge_client::ordered_economics_client::{
    ArtifactSink, OrderedEconomicsEndpoint, PeerPhaseOutcome, drive_empty_ordered_round,
    replay_declared_prefix_with_sink,
};
use sunrise_edge_client::{
    Client, Method, RemoteTlsHttpTransport, Transport, WireRequest, WireResponse,
};
use sunrise_edge_operator::common::{parse_hash_suite, parse_hex_32};

const COUNT: usize = 4;
const PUBLIC: &str = "/work/public";
const ARTIFACTS: &str = "/work/artifacts";
const MAX_FILE: usize = 1024 * 1024;
const DOMAIN: [u8; 32] = [0x61; 32];
fn path(tree: &str, index: usize, name: &str) -> PathBuf {
    PathBuf::from(format!("/work/{tree}/v{index}/{name}"))
}
fn read(path: impl AsRef<Path>, cap: usize) -> Vec<u8> {
    let file: File = File::open(path).unwrap();
    assert!(usize::try_from(file.metadata().unwrap().len()).unwrap() <= cap);
    let mut bytes: Vec<u8> = Vec::new();
    file.take(u64::try_from(cap + 1).unwrap())
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= cap);
    bytes
}
fn write_new(path: impl AsRef<Path>, bytes: &[u8], mode: u32) {
    assert!(bytes.len() <= MAX_FILE);
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap();
    // The controller's role umask is077. Only selected public fixture bytes
    // receive0644 explicitly; authority/key/config destinations remain0600.
    file.set_permissions(fs::Permissions::from_mode(mode))
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn pins() -> BTreeMap<String, String> {
    let text: String = String::from_utf8(read(format!("{PUBLIC}/pins"), 16 * 1024)).unwrap();
    let mut pins: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let (key, value): (&str, &str) = line.split_once('=').unwrap();
        assert!(pins.insert(key.into(), value.into()).is_none());
    }
    assert_eq!(pins.len(), 8);
    pins
}
fn policy() -> OrderedEconomicsPolicy {
    let pins: BTreeMap<String, String> = pins();
    let chain: ChainId = ChainId::new(pins["chain-id"].clone()).unwrap();
    let context: PublicationContext =
        PublicationContext::new(chain.clone(), ProtocolVersion::new(7), Epoch::new(0)).unwrap();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain,
        ProtocolVersion::new(7),
        vec![parse_hash_suite("0:1:1:1:1:1:1:1").unwrap()],
    )
    .unwrap();
    let digest_text: String = String::from_utf8(read(format!("{PUBLIC}/digest"), 64)).unwrap();
    let digest: [u8; 32] = parse_hex_32(&digest_text, "fixture public digest").unwrap();
    let root = sunrise_edge_client::load_verified_genesis_root(
        &PathBuf::from(format!("{PUBLIC}/genesis.bin")),
        &resolver,
        digest,
        &context,
    )
    .unwrap();
    assert!(root.admission_profile().is_causal());
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, AtomicityDomainId::new(DOMAIN).unwrap())
            .unwrap();
    assert_eq!(policy.engine().validator_set().validators().len(), COUNT);
    policy
}
fn verifier() -> Ed25519ConsensusVerifier {
    Ed25519ConsensusVerifier::new(UnsupportedSignatureSchemeResponse::InvalidSignature)
}
fn prepare_inputs() {
    let fixture: Fixture = Fixture::with_chain("ordered-multiuid-1017");
    let setup: PathBuf = PathBuf::from("/work/worker/setup");
    let mut args = fixture.args.clone();
    for name in ["authority.key", "validators.txt", "allocations.txt"] {
        write_new(
            setup.join(name),
            &read(fixture.directory.join(name), MAX_FILE),
            0o600,
        );
    }
    for (flag, name) in [
        ("--genesis-key-file", "authority.key"),
        ("--validators-file", "validators.txt"),
        ("--allocations-file", "allocations.txt"),
        ("--output", "genesis.bin"),
    ] {
        offline_genesis_fixture::replace(&mut args, flag, setup.join(name).into_os_string());
    }
    let mut arguments: String = String::new();
    for value in args {
        let value = value.into_string().unwrap();
        assert!(
            !value
                .bytes()
                .any(|byte: u8| matches!(byte, b'\n' | b'\r' | 0))
        );
        arguments.push_str(&value);
        arguments.push('\n');
    }
    write_new(
        format!("{PUBLIC}/author-arguments"),
        arguments.as_bytes(),
        0o644,
    );
    let mut text: String = format!(
        "chain-id={}\nauthority={}\ndomain={}\nsuite=0:1:1:1:1:1:1:1\n",
        fixture.context.chain_id().as_str(),
        hex(&fixture.authority),
        hex(&DOMAIN)
    );
    for (index, public) in fixture.validators.iter().enumerate() {
        text.push_str(&format!("validator-{index}={}\n", hex(public)));
        let seed: [u8; 32] = [0x51 + u8::try_from(index).unwrap(); 32];
        write_new(path("worker", index, "validator.key"), &seed, 0o600);
    }
    write_new(format!("{PUBLIC}/pins"), text.as_bytes(), 0o644);
    // Fixture Drop removes the original private author directory. No validator
    // key bytes are handed to the root controller or frontend process.
}
fn publish_genesis() {
    let bytes: Vec<u8> = read("/work/worker/setup/genesis.bin", MAX_FILE);
    write_new(format!("{PUBLIC}/genesis.bin"), &bytes, 0o644);
    for index in 0..COUNT {
        write_new(path("worker", index, "genesis.bin"), &bytes, 0o600);
    }
    let _verified: OrderedEconomicsPolicy = policy();
    for name in [
        "authority.key",
        "validators.txt",
        "allocations.txt",
        "genesis.bin",
    ] {
        fs::remove_file(PathBuf::from("/work/worker/setup").join(name)).unwrap();
    }
}
fn frontend_inputs() {
    for index in 0..COUNT {
        let name: String = format!("validator-{index}.ordered-custody.sunrise-edge.invalid");
        let ca: https_relay::FixtureCa =
            https_relay::FixtureCa::new(&format!("ordered-custody-{index}-issuer"));
        let leaf: https_relay::FixtureLeaf = ca.issue_leaf(&name);
        for (file, bytes) in [
            ("ca.der", ca.der.as_slice()),
            ("leaf.der", leaf.der.as_slice()),
            ("tls.key", leaf.key_pkcs8_der.as_slice()),
            ("spki.der", leaf.public_key_der.as_slice()),
            ("name", name.as_bytes()),
        ] {
            write_new(path("front", index, file), bytes, 0o600);
        }
        write_new(
            path("front", index, "genesis.bin"),
            &read(format!("{PUBLIC}/genesis.bin"), MAX_FILE),
            0o600,
        );
    }
}
fn endpoints() -> Vec<OrderedEconomicsEndpoint<RemoteTlsHttpTransport>> {
    let pins: BTreeMap<String, String> = pins();
    (0..COUNT)
        .map(|index: usize| {
            let address: SocketAddr =
                String::from_utf8(read(format!("{PUBLIC}/address-{index}"), 128))
                    .unwrap()
                    .parse()
                    .unwrap();
            let name: String = String::from_utf8(read(path("front", index, "name"), 256)).unwrap();
            let ca: Vec<u8> = read(path("front", index, "ca.der"), 16 * 1024);
            let received: Vec<u8> = https_relay::authenticated_leaf(address, &name, &ca);
            assert_eq!(received, read(path("front", index, "leaf.der"), 16 * 1024));
            let transport: RemoteTlsHttpTransport = RemoteTlsHttpTransport::new(
                address,
                &name,
                &ca,
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(5),
                Duration::from_secs(2),
                NonZeroUsize::new(16 * 1024).unwrap(),
                NonZeroUsize::new(MAX_FILE).unwrap(),
            )
            .unwrap();
            OrderedEconomicsEndpoint {
                validator_id: ValidatorId::new(
                    parse_hex_32(&pins[&format!("validator-{index}")], "validator").unwrap(),
                ),
                endpoint_label: address.to_string(),
                client: Client::new(transport),
            }
        })
        .collect()
}
fn send(
    endpoint: &OrderedEconomicsEndpoint<RemoteTlsHttpTransport>,
    method: Method,
    path: &str,
    media: Option<&'static str>,
    body: Vec<u8>,
) -> WireResponse {
    endpoint
        .client
        .transport()
        .send(&WireRequest {
            method,
            path: path.into(),
            content_type: media,
            body,
            deadline: Some(Instant::now().checked_add(Duration::from_secs(2)).unwrap()),
        })
        .unwrap()
}
fn success(response: WireResponse, media: &str) -> Vec<u8> {
    assert_eq!(response.status, 200);
    assert_eq!(response.content_type.as_deref(), Some(media));
    response.body
}
fn save(name: &str, bytes: &[u8]) {
    assert!(!name.contains('/') && name.len() <= 64);
    write_new(format!("{ARTIFACTS}/{name}"), bytes, 0o600);
    // Canonical wire artifacts are public; only this selected copy is readable
    // by the independent worker-UID row oracle. Never publish key/config bytes.
    write_new(format!("{PUBLIC}/wire/{name}"), bytes, 0o644);
}
fn saved(name: &str) -> Vec<u8> {
    read(format!("{PUBLIC}/wire/{name}"), MAX_FILE)
}
fn proposal() -> OrderedProposal {
    decode_ordered_proposal(&saved("round1.proposal")).unwrap()
}
fn propose(repeat: bool) {
    let policy: OrderedEconomicsPolicy = policy();
    let endpoints = endpoints();
    let status = decode_ordered_status(&success(
        send(
            &endpoints[0],
            Method::Get,
            ORDERED_ECONOMICS_STATUS_PATH,
            None,
            Vec::new(),
        ),
        ORDERED_STATUS_MEDIA_TYPE,
    ))
    .unwrap();
    let leader: ValidatorId = policy
        .engine()
        .validator_set()
        .leader(status.current_view)
        .unwrap();
    let endpoint = endpoints
        .iter()
        .find(|endpoint| endpoint.validator_id == leader)
        .unwrap();
    let bytes: Vec<u8> = success(
        send(
            endpoint,
            Method::Post,
            ORDERED_ECONOMICS_PROPOSE_PATH,
            Some(ORDERED_PROPOSE_REQUEST_MEDIA_TYPE),
            OrderedProposeRequest { candidate: None }.encode().unwrap(),
        ),
        ORDERED_PROPOSAL_MEDIA_TYPE,
    );
    let decoded: OrderedProposal = decode_ordered_proposal(&bytes).unwrap();
    policy
        .engine()
        .verify_proposal(&decoded.proposal, &verifier())
        .unwrap();
    assert_eq!(decoded.proposal.leader, leader);
    assert_eq!(decoded.proposal.view, 1);
    assert_eq!(decoded.proposal.height, 1);
    assert!(decoded.candidate.is_none() && decoded.proposal.transactions.is_empty());
    assert_eq!(encode_ordered_proposal(&decoded).unwrap(), bytes);
    if repeat {
        assert_eq!(bytes, saved("round1.proposal"));
    } else {
        save("round1.proposal", &bytes);
    }
}
fn votes(repeat: bool, down: bool) {
    let policy: OrderedEconomicsPolicy = policy();
    let proposal: OrderedProposal = proposal();
    let digest = policy.engine().proposal_digest(&proposal.proposal).unwrap();
    let mut votes: Vec<ConsensusVote> = Vec::new();
    for (index, endpoint) in endpoints().iter().enumerate() {
        let response: WireResponse = send(
            endpoint,
            Method::Post,
            ORDERED_ECONOMICS_PROPOSAL_PATH,
            Some(ORDERED_PROPOSAL_MEDIA_TYPE),
            saved("round1.proposal"),
        );
        if down {
            assert_eq!(response.status, 503);
            assert_eq!(response.body, b"ordered-custody-unavailable");
            continue;
        }
        let bytes: Vec<u8> = success(response, ORDERED_EVENT_OUTPUT_MEDIA_TYPE);
        let event = decode_ordered_event_output(&bytes).unwrap();
        assert_eq!(event.messages.len(), 1);
        assert!(event.committed.is_empty());
        let ConsensusMessage::Vote(vote) = &event.messages[0] else {
            panic!("actual vote absent");
        };
        assert_eq!(vote.validator, endpoint.validator_id);
        assert_eq!(vote.proposal_digest, digest);
        assert_eq!(vote.view, 1);
        assert_eq!(vote.height, 1);
        assert_eq!(vote.signature.len(), 64);
        policy.engine().verify_vote(vote, &verifier()).unwrap();
        votes.push(vote.clone());
        let name: String = format!("vote1-{index}.event");
        if repeat {
            assert_eq!(bytes, saved(&name));
        } else {
            save(&name, &bytes);
            save(&format!("vote1-{index}.vote"), &encode_vote(vote).unwrap());
        }
    }
    if !repeat && !down {
        assert_eq!(votes.len(), COUNT);
        let qc: QuorumCertificate = policy
            .engine()
            .certificate_from_votes(&proposal.proposal, &votes, &verifier())
            .unwrap()
            .unwrap();
        policy
            .engine()
            .verify_certificate(&qc, &verifier())
            .unwrap();
        // The unchanged engine selects the canonical minimal quorum from all
        // four actual responses. Equal-power four-validator quorum is three.
        assert_eq!(qc.votes.len(), 3);
        save(
            "round1.certificate",
            &encode_quorum_certificate(&qc).unwrap(),
        );
    }
}
fn certificate() {
    let qc: QuorumCertificate = decode_quorum_certificate(&saved("round1.certificate")).unwrap();
    for endpoint in endpoints() {
        let bytes: Vec<u8> = success(
            send(
                &endpoint,
                Method::Post,
                ORDERED_ECONOMICS_CERTIFICATE_PATH,
                Some(ORDERED_CERTIFICATE_MEDIA_TYPE),
                saved("round1.certificate"),
            ),
            ORDERED_EVENT_OUTPUT_MEDIA_TYPE,
        );
        let _decoded = decode_ordered_event_output(&bytes).unwrap();
        let status = decode_ordered_status(&success(
            send(
                &endpoint,
                Method::Get,
                ORDERED_ECONOMICS_STATUS_PATH,
                None,
                Vec::new(),
            ),
            ORDERED_STATUS_MEDIA_TYPE,
        ))
        .unwrap();
        assert_eq!(status.high_qc, qc);
        assert_eq!(status.committed_height, 0);
    }
}
struct Sink {
    directory: PathBuf,
    count: usize,
    bytes: usize,
}
impl ArtifactSink for Sink {
    fn persist(&mut self, name: &str, bytes: &[u8]) -> io::Result<()> {
        if name.len() > 128 || name.contains('/') || self.count >= 32 || bytes.len() > MAX_FILE {
            return Err(io::Error::other("fixture artifact bound"));
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("fixture artifact overflow"))?;
        if self.bytes > 8 * MAX_FILE {
            return Err(io::Error::other("fixture artifact total bound"));
        }
        self.count += 1;
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.directory.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()
    }
}
fn sink(name: &str) -> Sink {
    let directory: PathBuf = PathBuf::from(ARTIFACTS).join(name);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    Sink {
        directory,
        count: 0,
        bytes: 0,
    }
}
fn fresh() {
    let policy: OrderedEconomicsPolicy = policy();
    let endpoints = endpoints();
    let parent: QuorumCertificate =
        decode_quorum_certificate(&saved("round1.certificate")).unwrap();
    let result = drive_empty_ordered_round(
        &endpoints,
        &policy,
        Some(&parent),
        Instant::now().checked_add(Duration::from_secs(20)).unwrap(),
        Duration::from_secs(2),
        &mut sink("fresh"),
    )
    .unwrap();
    assert_eq!(result.height, 2);
    assert_eq!(result.qc_formed_from.len(), 3);
    assert_eq!(result.peers.len(), COUNT);
    for peer in result.peers {
        assert!(matches!(peer.vote_phase, PeerPhaseOutcome::Applied(_)));
        assert!(matches!(
            peer.certificate_phase,
            PeerPhaseOutcome::Applied(_)
        ));
    }
    save("round2.proposal", &result.proposal_bytes);
    save("round2.certificate", &result.certificate_bytes);
}
fn replay() {
    let rounds: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (saved("round1.proposal"), saved("round1.certificate")),
        (saved("round2.proposal"), saved("round2.certificate")),
    ];
    let result = replay_declared_prefix_with_sink(
        &endpoints(),
        &policy(),
        &rounds,
        Instant::now().checked_add(Duration::from_secs(20)).unwrap(),
        Duration::from_secs(2),
        &mut sink("replay"),
    )
    .unwrap();
    assert_eq!(result.len(), 2);
    for round in result {
        for phase in [round.observe_phase, round.certificate_phase] {
            assert_eq!(phase.len(), COUNT);
            for (_, result) in phase {
                assert!(matches!(result, PeerPhaseOutcome::Applied(_)));
            }
        }
    }
}
fn bad_input() {
    let endpoints = endpoints();
    let mut proposal: OrderedProposal = proposal();
    proposal.proposal.signature[0] ^= 1;
    for endpoint in &endpoints {
        let response = send(
            endpoint,
            Method::Post,
            ORDERED_ECONOMICS_PROPOSAL_PATH,
            Some(ORDERED_PROPOSAL_MEDIA_TYPE),
            encode_ordered_proposal(&proposal).unwrap(),
        );
        assert_eq!(response.status, 400);
        assert_eq!(response.body, b"invalid-ordered-proposal-signature");
        for route in [
            "/sign",
            "/v1/fastvote/prepare",
            "/v1/conditional-readiness",
            "/tmp/validator.key",
        ] {
            assert_eq!(
                send(endpoint, Method::Post, route, None, Vec::new()).status,
                404
            );
        }
    }
}
fn retained_records(view: u64) {
    let policy: OrderedEconomicsPolicy = policy();
    let pins: BTreeMap<String, String> = pins();
    for index in 0..COUNT {
        let connection: Connection = Connection::open_with_flags(
            path("source", index, "state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        let mut statement = connection
            .prepare("SELECT value FROM durable_state ORDER BY key")
            .unwrap();
        let mut rows = statement.query([]).unwrap();
        let mut found_votes: Vec<u64> = Vec::new();
        let mut high: Vec<u64> = Vec::new();
        let mut leaders: Vec<u64> = Vec::new();
        let mut count: usize = 0;
        let mut total: usize = 0;
        while let Some(row) = rows.next().unwrap() {
            count += 1;
            assert!(count <= 1024);
            let bytes: &[u8] = match row.get_ref(0).unwrap() {
                rusqlite::types::ValueRef::Blob(bytes) => bytes,
                rusqlite::types::ValueRef::Null => continue,
                _ => panic!("unexpected durable value SQL type"),
            };
            total = total.checked_add(bytes.len()).unwrap();
            assert!(bytes.len() <= 512 * 1024 && total <= 16 * MAX_FILE);
            let Ok(frame) = decode_canonical_frame(bytes) else {
                continue;
            };
            match frame.type_id() {
                0x644B => {
                    frame.require_version(1).unwrap();
                    frame.require_only_fields(&[1, 2, 3, 4]).unwrap();
                    let proposal = decode_proposal(frame.required_field(4).unwrap()).unwrap();
                    assert_eq!(
                        encode_proposal(&proposal).unwrap(),
                        frame.required_field(4).unwrap()
                    );
                    assert_eq!(proposal.view, frame.required_u64(1).unwrap());
                    assert_eq!(proposal.leader.as_bytes(), frame.required_field(2).unwrap());
                    assert_eq!(
                        policy.engine().proposal_digest(&proposal).unwrap(),
                        decode_digest32(frame.required_field(3).unwrap()).unwrap()
                    );
                    policy
                        .engine()
                        .verify_proposal(&proposal, &verifier())
                        .unwrap();
                    assert_eq!(
                        hex(proposal.leader.as_bytes()),
                        pins[&format!("validator-{index}")]
                    );
                    let saved: OrderedProposal = decode_ordered_proposal(&saved(&format!(
                        "round{}.proposal",
                        proposal.height
                    )))
                    .unwrap();
                    assert_eq!(proposal, saved.proposal);
                    leaders.push(proposal.view);
                }
                0x644C => {
                    frame.require_version(1).unwrap();
                    frame.require_only_fields(&[1, 2, 3]).unwrap();
                    let vote = decode_vote(frame.required_field(3).unwrap()).unwrap();
                    assert_eq!(
                        encode_vote(&vote).unwrap(),
                        frame.required_field(3).unwrap()
                    );
                    assert_eq!(vote.view, frame.required_u64(1).unwrap());
                    assert_eq!(
                        vote.proposal_digest,
                        decode_digest32(frame.required_field(2).unwrap()).unwrap()
                    );
                    assert_eq!(
                        hex(vote.validator.as_bytes()),
                        pins[&format!("validator-{index}")]
                    );
                    policy.engine().verify_vote(&vote, &verifier()).unwrap();
                    if vote.view == 1 {
                        assert_eq!(
                            frame.required_field(3).unwrap(),
                            saved(&format!("vote1-{index}.vote"))
                        );
                    }
                    found_votes.push(vote.view);
                }
                0x644D => {
                    frame.require_version(1).unwrap();
                    frame.require_only_fields(&[1]).unwrap();
                    high.push(frame.required_u64(1).unwrap());
                }
                _ => {}
            }
        }
        found_votes.sort();
        assert_eq!(found_votes, (1..=view).collect::<Vec<u64>>());
        assert_eq!(high, vec![view]);
        let expected: Vec<u64> = (1..=view)
            .filter(|current| {
                policy
                    .engine()
                    .validator_set()
                    .leader(*current)
                    .unwrap()
                    .as_bytes()
                    == &parse_hex_32(&pins[&format!("validator-{index}")], "validator").unwrap()
            })
            .collect();
        leaders.sort();
        assert_eq!(leaders, expected);
        drop(rows);
        drop(statement);
        connection.close().unwrap();
    }
}
fn images() -> (Vec<Image>, Vec<AnchorImage>) {
    let source: Vec<Image> = (0..COUNT)
        .map(|index| {
            sqlite_durable_image::capture(
                &path("source", index, "state.sqlite"),
                &path("source", index, "body.sqlite"),
            )
        })
        .collect();
    let anchors: Vec<AnchorImage> = (0..COUNT)
        .map(|index| {
            sqlite_durable_image::capture_anchor(&path("authority", index, "anchor.sqlite"))
        })
        .collect();
    for fd in fs::read_dir("/proc/self/fd").unwrap() {
        if let Ok(target) = fs::read_link(fd.unwrap().path()) {
            assert!(
                !target.starts_with("/work/source") && !target.starts_with("/work/authority"),
                "oracle retained DB/lease FD"
            );
        }
    }
    (source, anchors)
}
fn oracle() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let stream: std::os::unix::net::UnixStream = runtime.block_on(async {
        let stream = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::UnixStream::connect("/work/oracle/control.sock"),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stream.peer_cred().unwrap().uid(), 0);
        stream.into_std().unwrap()
    });
    stream.set_nonblocking(false).unwrap();
    let end: Instant = Instant::now()
        .checked_add(Duration::from_secs(210))
        .unwrap();
    let mut stream: BufReader<std::os::unix::net::UnixStream> = BufReader::new(stream);
    let mut baseline: Option<(Vec<Image>, Vec<AnchorImage>)> = None;
    for _ in 0..64 {
        let remaining: Duration = end.checked_duration_since(Instant::now()).unwrap();
        stream
            .get_ref()
            .set_read_timeout(Some(remaining.min(Duration::from_secs(30))))
            .unwrap();
        stream
            .get_ref()
            .set_write_timeout(Some(remaining.min(Duration::from_secs(2))))
            .unwrap();
        let mut phase: String = String::new();
        let count: usize = stream.by_ref().take(65).read_line(&mut phase).unwrap();
        assert!(count > 0 && count <= 64 && phase.ends_with('\n'));
        let phase: &str = phase.trim_end_matches('\n');
        match phase {
            "baseline" => baseline = Some(images()),
            "unchanged" | "finish" => assert_eq!(&images(), baseline.as_ref().unwrap()),
            "fence-2" | "fence-3" => {
                let next = images();
                let previous = baseline.as_ref().unwrap();
                let (from, to): (u64, u64) = if phase == "fence-2" { (1, 2) } else { (2, 3) };
                sqlite_durable_image::assert_only_fence_changed(&previous.0, &next.0, from, to);
                assert_ne!(previous.1, next.1);
                baseline = Some(next);
            }
            "retained-1" => {
                retained_records(1);
                baseline = Some(images());
            }
            "retained-2" => {
                retained_records(2);
                baseline = Some(images());
            }
            _ => panic!("unknown closed oracle phase"),
        }
        stream
            .get_mut()
            .write_all(format!("ok {phase}\n").as_bytes())
            .unwrap();
        if phase == "finish" {
            return;
        }
    }
    panic!("oracle command bound exhausted");
}

#[test]
#[ignore = "requires reviewed bounded Docker multi-UID controller and exact five compiled inputs"]
fn fixture_original_ordered_role_probe() {
    match env::var("SUNRISE_ORDERED_FIXTURE_PHASE").unwrap().as_str() {
        "prepare-inputs" => prepare_inputs(),
        "publish-genesis" => publish_genesis(),
        "frontend-inputs" => frontend_inputs(),
        "propose-first" => propose(false),
        "propose-repeat" => propose(true),
        "votes-first" => votes(false, false),
        "votes-repeat" => votes(true, false),
        "worker-down" => votes(true, true),
        "certificate" => certificate(),
        "fresh" => fresh(),
        "replay" => replay(),
        "bad-input" => bad_input(),
        "oracle" => oracle(),
        _ => panic!("unknown closed fixture phase"),
    }
}
