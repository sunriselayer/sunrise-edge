//! Test-only closed SQLite row image, never a raw connection exposed to runtime.
//! Each read-only SQLite-owned connection/transaction is explicitly finished and
//! dropped before returning owned values. Physical page/WAL equality is not claimed.

use rusqlite::{
    Connection, OpenFlags, Transaction,
    types::{Value, ValueRef},
};
use std::{collections::BTreeMap, path::Path, time::Duration};

const MAX_ROWS: usize = 1_024;
const MAX_CELL_BYTES: usize = 512 * 1024;
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;

const TABLES: [(&str, &str, usize); 12] = [
    (
        "durable_metadata",
        "SELECT id, schema_identity, chain_id, validator_id, domain, writer_fence, mutation_sequence, source_instance_id, namespace_origin, import_binding FROM durable_metadata ORDER BY id",
        10,
    ),
    (
        "durable_import_progress",
        "SELECT id, phase, progress FROM durable_import_progress ORDER BY id",
        3,
    ),
    (
        "durable_outgoing_barrier",
        "SELECT id, barrier FROM durable_outgoing_barrier ORDER BY id",
        2,
    ),
    (
        "durable_successor_serving",
        "SELECT id, serving FROM durable_successor_serving ORDER BY id",
        2,
    ),
    (
        "durable_state",
        "SELECT key, revision, value FROM durable_state ORDER BY key",
        3,
    ),
    (
        "durable_conditional_readiness",
        "SELECT slot, status, record FROM durable_conditional_readiness ORDER BY slot",
        3,
    ),
    (
        "durable_object_heads",
        "SELECT object_id, status, head_revision, object_version, digest_algorithm, digest_bytes, owner_projection, routing_projection FROM durable_object_heads ORDER BY object_id",
        8,
    ),
    (
        "durable_object_versions",
        "SELECT object_id, object_version, digest_algorithm, digest_bytes, schema_version, type_id, created_chain_id, created_protocol_version, created_checkpoint, inline_canonical_bytes, blob_digest_algorithm, blob_digest_bytes FROM durable_object_versions ORDER BY object_id, object_version",
        12,
    ),
    (
        "durable_receipts",
        "SELECT request_id, event_digest_algorithm, event_digest_bytes, canonical_bytes FROM durable_receipts ORDER BY request_id",
        4,
    ),
    (
        "durable_outbox_messages",
        "SELECT request_id, message_index, payload_digest_algorithm, payload_digest_bytes, canonical_payload FROM durable_outbox_messages ORDER BY request_id, message_index",
        5,
    ),
    (
        "durable_outbox_delivery",
        "SELECT request_id, message_count, next_message_index, completed, available_at_unix_millis, active_lease_id, lease_expires_at_unix_millis, attempt_count FROM durable_outbox_delivery ORDER BY request_id",
        8,
    ),
    (
        "durable_outbox_attempts",
        "SELECT lease_id, request_id, message_index, lease_expires_at_unix_millis, status FROM durable_outbox_attempts ORDER BY lease_id",
        5,
    ),
];
const BLOB_TABLES: [(&str, &str, usize); 2] = [
    (
        "blob_metadata",
        "SELECT id, schema_identity FROM blob_metadata ORDER BY id",
        2,
    ),
    (
        "blobs",
        "SELECT digest_algorithm, digest_bytes, content FROM blobs ORDER BY digest_algorithm, digest_bytes",
        3,
    ),
];
const ANCHOR_TABLES: [(&str, &str, usize); 2] = [
    (
        "anchor_head",
        "SELECT id, device, inode, lease_device, lease_inode, sequence, state_root, body_root, pending_state_root, pending_body_root, pending_sequence FROM anchor_head ORDER BY id",
        11,
    ),
    (
        "anchor_bodies",
        "SELECT pending, algorithm, digest, length, content_hash FROM anchor_bodies ORDER BY pending, algorithm, digest",
        5,
    ),
];

type Row = Vec<Value>;
type Tables = BTreeMap<&'static str, Vec<Row>>;

#[derive(Clone, Debug, PartialEq)]
pub struct Image {
    state: Tables,
    blobs: Tables,
}

fn rows(
    transaction: &Transaction<'_>,
    query: &str,
    columns: usize,
    row_limit: usize,
    total_bytes: &mut usize,
) -> Vec<Row> {
    let mut statement: rusqlite::Statement<'_> = transaction.prepare(query).unwrap();
    assert_eq!(statement.column_count(), columns);
    let mut cursor: rusqlite::Rows<'_> = statement.query([]).unwrap();
    let mut output: Vec<Row> = Vec::new();
    while let Some(row) = cursor.next().unwrap() {
        assert!(output.len() < row_limit, "complete SQL image row admission");
        let mut cells: Row = Vec::with_capacity(columns);
        for index in 0..columns {
            let cell: ValueRef<'_> = row.get_ref(index).unwrap();
            let bytes: usize = match cell {
                ValueRef::Null => 0,
                ValueRef::Integer(_) => 8,
                ValueRef::Text(value) | ValueRef::Blob(value) => value.len(),
                ValueRef::Real(_) => panic!("unexpected SQL REAL in durable schema"),
            };
            assert!(
                bytes <= MAX_CELL_BYTES,
                "SQL image cell admission before copy"
            );
            *total_bytes = total_bytes.checked_add(bytes).unwrap();
            assert!(
                *total_bytes <= MAX_IMAGE_BYTES,
                "complete SQL image byte admission"
            );
            cells.push(match cell {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(value) => Value::Integer(value),
                ValueRef::Text(value) => Value::Text(std::str::from_utf8(value).unwrap().into()),
                ValueRef::Blob(value) => Value::Blob(value.to_vec()),
                ValueRef::Real(_) => unreachable!(),
            });
        }
        output.push(cells);
    }
    output
}

fn tables(
    path: &Path,
    inventory: &[(&'static str, &str, usize)],
    total_bytes: &mut usize,
) -> Tables {
    let mut connection: Connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    connection.busy_timeout(Duration::from_secs(5)).unwrap();
    let transaction: Transaction<'_> = connection.transaction().unwrap();
    let names: Vec<Row> = rows(
        &transaction,
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        1,
        inventory.len(),
        total_bytes,
    );
    let actual: Vec<&str> = names
        .iter()
        .map(|row: &Row| match &row[0] {
            Value::Text(name) => name.as_str(),
            other => panic!("non-text schema table name: {other:?}"),
        })
        .collect();
    let mut expected: Vec<&str> = inventory.iter().map(|entry| entry.0).collect();
    expected.sort_unstable();
    assert_eq!(actual, expected, "closed SQL table inventory");
    let mut image: Tables = BTreeMap::new();
    let mut total_rows: usize = 0;
    for &(name, query, columns) in inventory {
        // Projection width alone cannot detect an extra persisted column. The
        // static exact SELECT list also defines the complete schema inventory.
        let selected: &str = query
            .strip_prefix("SELECT ")
            .unwrap()
            .split_once(" FROM ")
            .unwrap()
            .0;
        let expected_columns: Vec<&str> = selected.split(',').map(str::trim).collect();
        assert_eq!(expected_columns.len(), columns);
        let definition: Vec<Row> = rows(
            &transaction,
            &format!("PRAGMA table_info({name})"),
            6,
            columns,
            total_bytes,
        );
        let actual_columns: Vec<&str> = definition
            .iter()
            .map(|row: &Row| match &row[1] {
                Value::Text(column) => column.as_str(),
                other => panic!("non-text schema column name: {other:?}"),
            })
            .collect();
        assert_eq!(
            actual_columns, expected_columns,
            "closed SQL column inventory for {name}"
        );
        let values: Vec<Row> = rows(
            &transaction,
            query,
            columns,
            MAX_ROWS.checked_sub(total_rows).unwrap(),
            total_bytes,
        );
        total_rows = total_rows.checked_add(values.len()).unwrap();
        assert!(image.insert(name, values).is_none());
    }
    transaction.rollback().unwrap();
    assert!(connection.is_autocommit());
    connection.close().unwrap();
    image
}

/// Complete independent local authority rows, read through SQLite-owned
/// connections only. This observation grants no authority or lease ownership.
#[derive(Clone, Debug, PartialEq)]
pub struct AnchorImage {
    tables: Tables,
}

pub fn capture_anchor(path: &Path) -> AnchorImage {
    let mut bytes: usize = 0;
    let image: Tables = tables(path, &ANCHOR_TABLES, &mut bytes);
    assert_eq!(image.len(), 2);
    let head: &Vec<Row> = image.get("anchor_head").unwrap();
    assert_eq!(head.len(), 1);
    assert!(
        head[0][8..11]
            .iter()
            .all(|value: &Value| *value == Value::Null),
        "acknowledged quiescent authority has no Pending"
    );
    AnchorImage { tables: image }
}

pub fn capture(state_path: &Path, blob_path: &Path) -> Image {
    let mut bytes: usize = 0;
    let state: Tables = tables(state_path, &TABLES, &mut bytes);
    let blobs: Tables = tables(blob_path, &BLOB_TABLES, &mut bytes);
    assert_eq!(state.len(), 12);
    assert_eq!(blobs.len(), 2);
    Image { state, blobs }
}

pub fn assert_only_fence_changed(before: &[Image], after: &[Image], from: u64, to: u64) {
    assert_eq!(before.len(), 4);
    assert_eq!(after.len(), 4);
    for (old, actual) in before.iter().zip(after) {
        let mut expected: Image = old.clone();
        let metadata: &mut Vec<Row> = expected.state.get_mut("durable_metadata").unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].len(), 10);
        assert_eq!(metadata[0][5], Value::Blob(from.to_be_bytes().to_vec()));
        metadata[0][5] = Value::Blob(to.to_be_bytes().to_vec());
        assert_eq!(
            &expected, actual,
            "only the authorized writer fence may change"
        );
    }
}

/// A stopped-owner profile enrollment changes only its closed schema identity.
/// Structural user_version is checked separately; every SQL/blob cell here is
/// compared, including mutation sequence, source identity, fences and receipts.
pub fn assert_only_anchor_identity_changed(before: &[Image], after: &[Image]) {
    assert_eq!(before.len(), 4);
    assert_eq!(after.len(), 4);
    for (old, actual) in before.iter().zip(after) {
        let mut expected: Image = old.clone();
        let metadata: &mut Vec<Row> = expected.state.get_mut("durable_metadata").unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].len(), 10);
        assert_eq!(
            metadata[0][1],
            Value::Text("sunrise-edge/sqlite/structured/schema/v6".into())
        );
        metadata[0][1] =
            Value::Text("sunrise-edge/sqlite/structured/schema/v6/independent-anchor/v1".into());
        assert_eq!(
            &expected, actual,
            "only explicit independent-anchor profile identity changes"
        );
    }
}
