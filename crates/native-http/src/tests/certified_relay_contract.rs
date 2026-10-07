//! Independent native oracle for DR-0204's closed portable transport.
//! The TSV contains literal values consumed by TS; these expectations use the
//! existing native route and codec owners, not the new TS production policy.
use super::*;

const FIXTURE: &str = include_str!("../../../../adapters/shared/certified-route-contract.tsv");

#[derive(Debug, PartialEq, Eq)]
struct RouteContract<'a> {
    method: &'a str,
    path: &'a str,
    request_bytes: usize,
    response_bytes: usize,
    success: &'a str,
    empty_request: bool,
}

const fn post(
    path: &'static str,
    request_bytes: usize,
    response_bytes: usize,
    success: &'static str,
    empty_request: bool,
) -> RouteContract<'static> {
    RouteContract {
        method: "POST",
        path,
        request_bytes,
        response_bytes,
        success,
        empty_request,
    }
}

const fn get(path: &'static str, response_bytes: usize) -> RouteContract<'static> {
    RouteContract {
        method: "GET",
        path,
        request_bytes: 0,
        response_bytes,
        success: "result",
        empty_request: true,
    }
}

fn native_contract() -> Vec<RouteContract<'static>> {
    use canonical_encoding::MAX_CANONICAL_FRAME_BYTES as canonical;
    use consensus::bundle::MAX_ENCODED_BUNDLE_BYTES as bundle;
    use execution::paid_execution::{MAX_PAID_FEE_POLICY_BYTES, MAX_SIGNED_PAID_INTENT_BYTES};
    use node_wire::*;
    vec![
        post(
            FASTVOTE_PREPARE_PATH,
            MAX_SIGNED_PAID_INTENT_BYTES,
            MAX_FASTVOTE_VOTE_BYTES,
            "result",
            false,
        ),
        post(
            FASTVOTE_CERTIFICATES_PATH,
            MAX_FASTVOTE_APPLY_REQUEST_BYTES,
            canonical,
            "result",
            false,
        ),
        post(
            FASTVOTE_PUBLICATION_SOURCE_PATH,
            MAX_FASTVOTE_APPLY_REQUEST_BYTES,
            bundle,
            "result",
            false,
        ),
        post(
            FASTVOTE_PUBLICATION_RETAIN_PATH,
            bundle,
            consensus::MAX_ENCODED_AVAILABILITY_VOTE_BYTES,
            "result",
            false,
        ),
        post(
            FASTVOTE_PUBLISHED_APPLY_PATH,
            MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES,
            canonical,
            "result",
            false,
        ),
        post(
            FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH,
            MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES,
            bundle,
            "result",
            false,
        ),
        post(
            FASTVOTE_FROZEN_FRONTIER_PAGE_PATH,
            MAX_FRONTIER_PAGE_REQUEST_BYTES,
            MAX_FRONTIER_PAGE_RESPONSE_BYTES,
            "result",
            false,
        ),
        // Existing native handler's one-byte transport guard; semantic body is empty.
        post(
            FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
            1,
            MAX_FRONTIER_VOTE_BYTES,
            "result-or-empty",
            true,
        ),
        post(
            FASTVOTE_DRAIN_SIGNER_PAGE_PATH,
            MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES,
            0,
            "empty",
            false,
        ),
        post(
            FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH,
            MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES,
            0,
            "empty",
            false,
        ),
        post(
            FASTVOTE_DRAIN_UNION_ADVANCE_PATH,
            MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES,
            consensus::MAX_DRAIN_UNION_IDENTITY_BYTES,
            "result-or-empty",
            false,
        ),
        post(
            FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH,
            MAX_DRAIN_SIGNER_PROGRESS_REQUEST_BYTES,
            MAX_DRAIN_SIGNER_PROGRESS_RESPONSE_BYTES,
            "result",
            false,
        ),
        post(
            FASTVOTE_DRAIN_APPLY_PATH,
            MAX_DRAIN_MEMBER_APPLY_REQUEST_BYTES,
            canonical,
            "result",
            false,
        ),
        post(
            FASTVOTE_DRAIN_IMPORT_PATH,
            bundle,
            consensus::MAX_ENCODED_AVAILABILITY_IDENTITY_BYTES,
            "result",
            false,
        ),
        get(QUERY_CONTEXT_PATH, canonical),
        get(QUERY_OBJECT_PATH, canonical),
        get(QUERY_RECEIPT_PATH, canonical),
        get(QUERY_NEXT_NONCE_PATH, canonical),
        get(
            crate::paid_execution::PAID_FEE_POLICY_PATH,
            MAX_PAID_FEE_POLICY_BYTES,
        ),
        get(
            crate::publication::QUERY_PATH,
            node_core::publication::MAX_PUBLICATION_QUERY_RESULT_BYTES,
        ),
        get(crate::local_execution::INSTANCE_PATH, canonical),
    ]
}

fn fixtures() -> Vec<RouteContract<'static>> {
    FIXTURE
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 6, "six independently specified columns");
            let request_bytes: usize = fields[2].parse().unwrap();
            let response_bytes: usize = fields[3].parse().unwrap();
            assert_eq!(request_bytes.to_string(), fields[2]);
            assert_eq!(response_bytes.to_string(), fields[3]);
            assert!(matches!(fields[0], "GET" | "POST"));
            assert!(matches!(fields[4], "result" | "empty" | "result-or-empty"));
            assert!(matches!(fields[5], "0" | "1"));
            RouteContract {
                method: fields[0],
                path: fields[1],
                request_bytes,
                response_bytes,
                success: fields[4],
                empty_request: fields[5] == "1",
            }
        })
        .collect()
}

fn fixture_path(path: &str) -> String {
    let mut concrete: String = path.to_owned();
    let selector: String = "1".repeat(64);
    for name in [
        "validator_id",
        "object_id",
        "request_id",
        "sender",
        "publisher",
        "origin_seed",
        "creator",
        "seed",
    ] {
        concrete = concrete.replace(&format!("{{{name}}}"), &selector);
    }
    assert!(
        !concrete.contains('{'),
        "every native selector has an explicit fixture"
    );
    concrete
}

#[test]
fn certified_literal_transport_inventory_matches_existing_native_bounds() {
    let actual: Vec<RouteContract<'static>> = fixtures();
    assert_eq!(actual.len(), 21);
    assert_eq!(actual, native_contract());
}

#[tokio::test]
async fn certified_literal_transport_inventory_reaches_the_real_router() {
    let app: Router = certified_router();
    for contract in fixtures() {
        let path: String = fixture_path(contract.path);
        let wrong_method: &str = if contract.method == "GET" {
            "POST"
        } else {
            "GET"
        };
        assert_eq!(
            dispatch(&app, wrong_method, &path, Vec::new()).await,
            StatusCode::METHOD_NOT_ALLOWED,
            "opposite method proves actual native mount: {}",
            contract.path,
        );
        let body: Vec<u8> = if contract.method == "POST" && !contract.empty_request {
            vec![0xaa]
        } else {
            Vec::new()
        };
        let status: StatusCode = dispatch(&app, contract.method, &path, body).await;
        assert_ne!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{} {}",
            contract.method,
            contract.path
        );
        if contract.method == "POST" {
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "POST must reach its actual handler: {}",
                contract.path
            );
        }
        // A missing object/publication may legitimately yield handler 404. The
        // opposite-method 405 above distinguishes it from an unmounted route.
    }
    for path in crate::fastvote::CERTIFIED_FASTVOTE_EXCLUDED_MUTATION_PATHS
        .iter()
        .copied()
        .chain(["/v1/unlisted"])
    {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(
                dispatch(&app, method, path, vec![0xaa]).await,
                StatusCode::NOT_FOUND
            );
        }
    }
}
