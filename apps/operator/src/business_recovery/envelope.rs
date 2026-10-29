//! Closed LOCAL v1 framing. Embedded proof bytes are never re-encoded here.
#![forbid(unsafe_code)]

use super::{RecoveryError, RecoveryLimits};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(super) const MAGIC: &[u8; 12] = b"SE-RECOVERY\0";
pub(super) const COMPLETE: &str = "recovery-complete-v1.bin";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Role {
    pub(super) tag: u8,
    pub(super) link: u16,
}
impl Role {
    pub(super) fn required(links: u16) -> Result<Vec<Self>, RecoveryError> {
        if links > 16 {
            return Err(RecoveryError::Quota);
        }
        let count: usize = 3usize
            .checked_add(
                4usize
                    .checked_mul(usize::from(links))
                    .ok_or(RecoveryError::Quota)?,
            )
            .ok_or(RecoveryError::Quota)?;
        let mut roles: Vec<Self> = Vec::with_capacity(count);
        for tag in 1..=3 {
            roles.push(Self {
                tag,
                link: u16::MAX,
            });
        }
        for tag in 4..=7 {
            for link in 0..links {
                roles.push(Self { tag, link });
            }
        }
        Ok(roles)
    }
    pub(super) fn root(self, base: &Path) -> Result<PathBuf, RecoveryError> {
        match (self.tag, self.link) {
            (1, u16::MAX) => Ok(base.join("genesis")),
            (2, u16::MAX) => Ok(base.join("current/history")),
            (3, u16::MAX) => Ok(base.join("current/cut")),
            (tag @ 4..=7, link @ 0..=15) => {
                let name: &str = match tag {
                    4 => "plan-history",
                    5 => "cut",
                    6 => "manifest-history",
                    7 => "certificate",
                    _ => return Err(RecoveryError::InvalidInput),
                };
                Ok(base.join(format!("predecessors/link-{link:05}/{name}")))
            }
            _ => Err(RecoveryError::InvalidInput),
        }
    }
    pub(super) fn file_limit(self, name: &str) -> Result<usize, RecoveryError> {
        // The defining SDK owners admit their exact original generated names
        // and native per-file ceilings, rather than permissive globs here.
        match self.tag {
            1 if name == "genesis.bin" => Ok(node_core::MAX_GENESIS_MANIFEST_BYTES),
            2 | 4 | 6 => sunrise_edge_client::ordered_history_archive::relative_file_limit(name)
                .ok_or(RecoveryError::Inventory),
            3 | 5 => sunrise_edge_client::business_cut_archive::relative_file_limit(name)
                .ok_or(RecoveryError::Inventory),
            7 if name == "certificate.bin" => Ok(
                sunrise_edge_client::successor_artifacts::MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES,
            ),
            _ => Err(RecoveryError::Inventory),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) role: Role,
    pub(super) name: String,
    pub(super) length: u64,
    pub(super) hash: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Manifest {
    pub(super) links: u16,
    pub(super) entries: Vec<Entry>,
    pub(super) bodies: u64,
    pub(super) control: u64,
    pub(super) plaintext: u64,
    pub(super) record: Vec<u8>,
    pub(super) hash: [u8; 32],
}

impl Manifest {
    pub(super) fn encode(
        links: u16,
        entries: Vec<Entry>,
        limits: &RecoveryLimits,
    ) -> Result<Self, RecoveryError> {
        let Layout {
            roles,
            bodies,
            control,
            plaintext,
            payload_length,
        } = validate(links, &entries, limits)?;
        let mut record: Vec<u8> =
            Vec::with_capacity(payload_length.checked_add(5).ok_or(RecoveryError::Quota)?);
        record.push(1);
        record.extend_from_slice(
            &u32::try_from(payload_length)
                .map_err(|_| RecoveryError::Quota)?
                .to_be_bytes(),
        );
        record.extend_from_slice(&links.to_be_bytes());
        record.extend_from_slice(
            &u16::try_from(roles.len())
                .map_err(|_| RecoveryError::Quota)?
                .to_be_bytes(),
        );
        record.extend_from_slice(
            &u32::try_from(entries.len())
                .map_err(|_| RecoveryError::Quota)?
                .to_be_bytes(),
        );
        record.extend_from_slice(&bodies.to_be_bytes());
        for (role, count) in roles {
            record.push(role.tag);
            record.extend_from_slice(&role.link.to_be_bytes());
            record.extend_from_slice(&count.to_be_bytes());
        }
        for entry in &entries {
            record.push(entry.role.tag);
            record.extend_from_slice(&entry.role.link.to_be_bytes());
            record.extend_from_slice(
                &u16::try_from(entry.name.len())
                    .map_err(|_| RecoveryError::Quota)?
                    .to_be_bytes(),
            );
            record.extend_from_slice(entry.name.as_bytes());
            record.extend_from_slice(&entry.length.to_be_bytes());
            record.extend_from_slice(&entry.hash);
        }
        if record.len() != payload_length + 5 {
            return Err(RecoveryError::Inventory);
        }
        let hash: [u8; 32] = Sha256::digest(&record).into();
        Ok(Self {
            links,
            entries,
            bodies,
            control,
            plaintext,
            record,
            hash,
        })
    }

    pub(super) fn read<R: Read>(
        reader: &mut R,
        expected_links: u16,
        limits: &RecoveryLimits,
    ) -> Result<Self, RecoveryError> {
        let mut prefix: [u8; 14] = [0; 14];
        exact(reader, &mut prefix)?;
        if &prefix[..12] != MAGIC || prefix[12..] != 1u16.to_be_bytes() {
            return Err(RecoveryError::Inventory);
        }
        let mut header: [u8; 5] = [0; 5];
        exact(reader, &mut header)?;
        let length: usize = usize::try_from(u32::from_be_bytes(
            header[1..5]
                .try_into()
                .map_err(|_| RecoveryError::Inventory)?,
        ))
        .map_err(|_| RecoveryError::Quota)?;
        if header[0] != 1
            || length < 16
            || u64::try_from(length).map_err(|_| RecoveryError::Quota)? > limits.control_bytes
        {
            return Err(RecoveryError::Quota);
        }
        // Read the fixed claims on the stack. Exact K/P admission precedes
        // allocating even the bounded Manifest payload, not only file bodies.
        let mut fixed: [u8; 16] = [0; 16];
        exact(reader, &mut fixed)?;
        let mut claims: Cursor<'_> = Cursor {
            bytes: &fixed,
            position: 0,
        };
        let links: u16 = claims.u16()?;
        if links != expected_links || links > 16 {
            return Err(RecoveryError::InvalidInput);
        }
        let required: Vec<Role> = Role::required(links)?;
        let count: usize = usize::from(claims.u16()?);
        let files: usize = usize::try_from(claims.u32()?).map_err(|_| RecoveryError::Quota)?;
        let claimed_bodies: u64 = claims.u64()?;
        if count != required.len()
            || files == 0
            || files > limits.files
            || claimed_bodies > limits.plaintext_bytes
        {
            return Err(RecoveryError::Quota);
        }
        // A minimal framing check precedes both count-driven vectors.
        let minimum: usize = 16usize
            .checked_add(7usize.checked_mul(count).ok_or(RecoveryError::Quota)?)
            .and_then(|value| value.checked_add(46usize.checked_mul(files)?))
            .ok_or(RecoveryError::Quota)?;
        if minimum > length {
            return Err(RecoveryError::Inventory);
        }
        let claimed_control: u64 = 68u64
            .checked_add(u64::try_from(length).map_err(|_| RecoveryError::Quota)?)
            .and_then(|value| value.checked_add(17u64.checked_mul(u64::try_from(files).ok()?)?))
            .ok_or(RecoveryError::Quota)?;
        let claimed_plaintext: u64 = claimed_control
            .checked_add(claimed_bodies)
            .ok_or(RecoveryError::Quota)?;
        if claimed_control > limits.control_bytes || claimed_plaintext > limits.plaintext_bytes {
            return Err(RecoveryError::Quota);
        }
        let mut payload: Vec<u8> = vec![0; length];
        payload[..16].copy_from_slice(&fixed);
        exact(reader, &mut payload[16..])?;
        let mut cursor: Cursor<'_> = Cursor {
            bytes: &payload,
            position: 16,
        };
        let mut descriptors: Vec<(Role, u32)> = Vec::with_capacity(count);
        let mut sum: u64 = 0;
        for expected in required {
            let role: Role = Role {
                tag: cursor.byte()?,
                link: cursor.u16()?,
            };
            let count: u32 = cursor.u32()?;
            if role != expected || count == 0 {
                return Err(RecoveryError::Inventory);
            }
            sum = sum
                .checked_add(u64::from(count))
                .ok_or(RecoveryError::Quota)?;
            if sum > u64::try_from(files).map_err(|_| RecoveryError::Quota)? {
                return Err(RecoveryError::Inventory);
            }
            descriptors.push((role, count));
        }
        if sum != u64::try_from(files).map_err(|_| RecoveryError::Quota)? {
            return Err(RecoveryError::Inventory);
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(files);
        for _ in 0..files {
            let role: Role = Role {
                tag: cursor.byte()?,
                link: cursor.u16()?,
            };
            let name_length: usize = usize::from(cursor.u16()?);
            if !(1..=251).contains(&name_length) {
                return Err(RecoveryError::Quota);
            }
            let name: &str = std::str::from_utf8(cursor.take(name_length)?)
                .map_err(|_| RecoveryError::Inventory)?;
            role.file_limit(name)?; // Admission before allocating its String.
            let entry: Entry = Entry {
                role,
                name: name.to_owned(),
                length: cursor.u64()?,
                hash: cursor
                    .take(32)?
                    .try_into()
                    .map_err(|_| RecoveryError::Inventory)?,
            };
            entries.push(entry);
        }
        if cursor.position != length {
            return Err(RecoveryError::Inventory);
        }
        let Layout {
            roles: actual_descriptors,
            bodies,
            control,
            plaintext,
            payload_length: actual_length,
        } = validate(links, &entries, limits)?;
        if descriptors != actual_descriptors || bodies != claimed_bodies || actual_length != length
        {
            return Err(RecoveryError::Inventory);
        }
        let mut record: Vec<u8> = Vec::with_capacity(length + 5);
        record.extend_from_slice(&header);
        record.extend_from_slice(&payload);
        let hash: [u8; 32] = Sha256::digest(&record).into(); // EXACT original Manifest record.
        Ok(Self {
            links,
            entries,
            bodies,
            control,
            plaintext,
            record,
            hash,
        })
    }

    pub(super) fn footer(&self) -> Result<[u8; 49], RecoveryError> {
        let mut record: [u8; 49] = [0; 49];
        record[0] = 3;
        record[1..5].copy_from_slice(&44u32.to_be_bytes());
        record[5..9].copy_from_slice(
            &u32::try_from(self.entries.len())
                .map_err(|_| RecoveryError::Quota)?
                .to_be_bytes(),
        );
        record[9..17].copy_from_slice(&self.bodies.to_be_bytes());
        record[17..49].copy_from_slice(&self.hash);
        Ok(record)
    }
    pub(super) fn write_prefix<W: Write>(&self, output: &mut W) -> Result<(), RecoveryError> {
        output
            .write_all(MAGIC)
            .map_err(|_| RecoveryError::Transport)?;
        output
            .write_all(&1u16.to_be_bytes())
            .map_err(|_| RecoveryError::Transport)?;
        output
            .write_all(&self.record)
            .map_err(|_| RecoveryError::Transport)
    }
}

struct Layout {
    roles: Vec<(Role, u32)>,
    bodies: u64,
    control: u64,
    plaintext: u64,
    payload_length: usize,
}

fn validate(
    links: u16,
    entries: &[Entry],
    limits: &RecoveryLimits,
) -> Result<Layout, RecoveryError> {
    if entries.is_empty() || entries.len() > limits.files {
        return Err(RecoveryError::Quota);
    }
    let roles: Vec<Role> = Role::required(links)?;
    let mut counts: Vec<(Role, u32)> = roles.into_iter().map(|role: Role| (role, 0)).collect();
    let mut previous: Option<&Entry> = None;
    let mut body: u64 = 0;
    let mut payload: u64 = 16u64
        .checked_add(
            7u64.checked_mul(u64::try_from(counts.len()).map_err(|_| RecoveryError::Quota)?)
                .ok_or(RecoveryError::Quota)?,
        )
        .ok_or(RecoveryError::Quota)?;
    for entry in entries {
        let native: usize = entry.role.file_limit(&entry.name)?;
        if !(1..=251).contains(&entry.name.len())
            || entry.length == 0
            || entry.length > limits.file_bytes
            || entry.length > u64::try_from(native).map_err(|_| RecoveryError::Quota)?
        {
            return Err(RecoveryError::Quota);
        }
        if let Some(previous) = previous
            && (previous.role, previous.name.as_bytes()) >= (entry.role, entry.name.as_bytes())
        {
            return Err(RecoveryError::Inventory);
        }
        previous = Some(entry);
        let (_, count): &mut (Role, u32) = counts
            .iter_mut()
            .find(|(role, _)| *role == entry.role)
            .ok_or(RecoveryError::Inventory)?;
        *count = count.checked_add(1).ok_or(RecoveryError::Quota)?;
        if matches!(entry.role.tag, 1 | 7) && *count != 1 {
            return Err(RecoveryError::Inventory);
        }
        body = body.checked_add(entry.length).ok_or(RecoveryError::Quota)?;
        payload = payload
            .checked_add(45)
            .and_then(|value| value.checked_add(u64::try_from(entry.name.len()).ok()?))
            .ok_or(RecoveryError::Quota)?;
    }
    if counts.iter().any(|(_, count)| *count == 0) {
        return Err(RecoveryError::Inventory);
    }
    let control: u64 = 68u64
        .checked_add(payload)
        .and_then(|value| value.checked_add(17u64.checked_mul(u64::try_from(entries.len()).ok()?)?))
        .ok_or(RecoveryError::Quota)?;
    let plaintext: u64 = control.checked_add(body).ok_or(RecoveryError::Quota)?;
    if control > limits.control_bytes || plaintext > limits.plaintext_bytes {
        return Err(RecoveryError::Quota);
    }
    Ok(Layout {
        roles: counts,
        bodies: body,
        control,
        plaintext,
        payload_length: usize::try_from(payload).map_err(|_| RecoveryError::Quota)?,
    })
}

pub(super) fn file_header(index: usize, entry: &Entry) -> Result<[u8; 17], RecoveryError> {
    let mut header: [u8; 17] = [0; 17];
    header[0] = 2;
    let payload: u32 = u32::try_from(entry.length.checked_add(12).ok_or(RecoveryError::Quota)?)
        .map_err(|_| RecoveryError::Quota)?;
    header[1..5].copy_from_slice(&payload.to_be_bytes());
    header[5..9].copy_from_slice(
        &u32::try_from(index)
            .map_err(|_| RecoveryError::Quota)?
            .to_be_bytes(),
    );
    header[9..17].copy_from_slice(&entry.length.to_be_bytes());
    Ok(header)
}
pub(super) fn exact<R: Read>(reader: &mut R, bytes: &mut [u8]) -> Result<(), RecoveryError> {
    reader
        .read_exact(bytes)
        .map_err(|_| RecoveryError::Transport)
}

/// Writes only incomplete private bytes. Authentication/physical EOF/proofs
/// and publication remain mandatory separate steps in the open owner.
pub(super) fn receive<R: Read>(
    reader: &mut R,
    stage: &mut super::files::PrivateStage,
    links: u16,
    limits: &RecoveryLimits,
) -> Result<(Manifest, [u8; 49]), RecoveryError> {
    let manifest: Manifest = Manifest::read(reader, links, limits)?;
    for (index, entry) in manifest.entries.iter().enumerate() {
        let mut header: [u8; 17] = [0; 17];
        exact(reader, &mut header)?;
        if header != file_header(index, entry)? {
            return Err(RecoveryError::Inventory);
        }
        stage.receive(reader, entry)?;
    }
    let mut received: [u8; 49] = [0; 49];
    exact(reader, &mut received)?;
    let footer: [u8; 49] = manifest.footer()?;
    if received != footer {
        return Err(RecoveryError::Inventory);
    }
    Ok((manifest, footer))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], RecoveryError> {
        let end: usize = self
            .position
            .checked_add(count)
            .ok_or(RecoveryError::Quota)?;
        let bytes: &'a [u8] = self
            .bytes
            .get(self.position..end)
            .ok_or(RecoveryError::Inventory)?;
        self.position = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, RecoveryError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, RecoveryError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| RecoveryError::Inventory)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, RecoveryError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| RecoveryError::Inventory)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, RecoveryError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| RecoveryError::Inventory)?,
        ))
    }
}
