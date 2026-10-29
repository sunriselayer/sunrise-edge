#![forbid(unsafe_code)]

//! A bounded deterministic mutation campaign, with no external fuzz runtime.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalFrame, CanonicalStruct, decode_canonical_frame_bounded,
};

const SEEDS: [u64; 4] = [
    0x243f_6a88_85a3_08d3,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
];
const FRAMES_PER_SEED: usize = 64;
const MUTATIONS_PER_FRAME: usize = 16;
const MAX_FIELDS: usize = 8;
const MAX_GENERATED_PAYLOAD: usize = 64;
const MAX_INPUT_BYTES: usize = 1024;
const HEADER_BYTES: usize = 10;
const FIELD_HEADER_BYTES: usize = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FieldModel {
    id: u16,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FrameModel {
    type_id: u16,
    version: u16,
    fields: Vec<FieldModel>,
}

struct SeededBytes {
    state: u64,
}

impl SeededBytes {
    // Test input scheduling only; this generator has no cryptographic role.
    fn next(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn below(&mut self, bound: usize) -> usize {
        assert!(bound > 0 && bound <= MAX_INPUT_BYTES);
        usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[4]
    }

    fn word(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }
}

fn model(rng: &mut SeededBytes, case: usize) -> FrameModel {
    let count: usize = case % (MAX_FIELDS + 1);
    let mut fields: Vec<FieldModel> = Vec::with_capacity(count);
    let mut id: u16 = u16::try_from(rng.below(1024)).unwrap();
    for index in 0..count {
        id = id
            .checked_add(u16::try_from(1 + rng.below(31)).unwrap())
            .unwrap();
        if index + 1 == count && case.is_multiple_of(8) {
            id = u16::MAX;
        }
        let length: usize = match (case + index) % 4 {
            0 => 0,
            1 => 1,
            2 => MAX_GENERATED_PAYLOAD,
            _ => rng.below(MAX_GENERATED_PAYLOAD + 1),
        };
        let bytes: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
        fields.push(FieldModel { id, bytes });
    }
    let type_id: u16 = match case % 4 {
        0 => 0,
        1 => 1,
        2 => u16::MAX,
        _ => rng.word(),
    };
    FrameModel {
        type_id,
        version: rng.word(),
        fields,
    }
}

// Independent simple wire writer: it neither calls the production encoder nor
// sorts fields. Fixed malformed controls deliberately supply bad field order.
fn wire(model: &FrameModel) -> Vec<u8> {
    assert!(model.fields.len() <= MAX_FIELDS);
    let mut output: Vec<u8> = b"SNRE".to_vec();
    output.extend_from_slice(&model.type_id.to_le_bytes());
    output.extend_from_slice(&model.version.to_le_bytes());
    output.extend_from_slice(&u16::try_from(model.fields.len()).unwrap().to_le_bytes());
    for field in &model.fields {
        assert!(field.bytes.len() <= MAX_INPUT_BYTES);
        output.extend_from_slice(&field.id.to_le_bytes());
        output.extend_from_slice(&u32::try_from(field.bytes.len()).unwrap().to_le_bytes());
        output.extend_from_slice(&field.bytes);
    }
    assert!(output.len() <= MAX_INPUT_BYTES);
    output
}

// Independent bounded format oracle. The local count is checked before any
// field-index allocation, including a mutated u16::MAX count in a tiny input.
fn reference(input: &[u8]) -> Option<FrameModel> {
    if input.len() > MAX_INPUT_BYTES || input.get(..4)? != b"SNRE" {
        return None;
    }
    let type_id: u16 = u16::from_le_bytes(input.get(4..6)?.try_into().ok()?);
    let version: u16 = u16::from_le_bytes(input.get(6..8)?.try_into().ok()?);
    let count: usize = usize::from(u16::from_le_bytes(input.get(8..10)?.try_into().ok()?));
    if count > MAX_FIELDS {
        return None;
    }
    let mut fields: Vec<FieldModel> = Vec::new();
    let mut offset: usize = HEADER_BYTES;
    let mut previous: Option<u16> = None;
    for _ in 0..count {
        let header_end: usize = offset.checked_add(FIELD_HEADER_BYTES)?;
        let header: &[u8] = input.get(offset..header_end)?;
        let id: u16 = u16::from_le_bytes(header.get(..2)?.try_into().ok()?);
        if previous.is_some_and(|last| id <= last) {
            return None;
        }
        let length: usize =
            usize::try_from(u32::from_le_bytes(header.get(2..6)?.try_into().ok()?)).ok()?;
        let end: usize = header_end.checked_add(length)?;
        let bytes: Vec<u8> = input.get(header_end..end)?.to_vec();
        fields.push(FieldModel { id, bytes });
        previous = Some(id);
        offset = end;
    }
    if offset != input.len() {
        return None;
    }
    Some(FrameModel {
        type_id,
        version,
        fields,
    })
}

fn check_case(input: &[u8], label: &str) -> Option<CanonicalDecodingError> {
    assert!(input.len() <= MAX_INPUT_BYTES, "{label}");
    let expected: Option<FrameModel> = reference(input);
    let decoded: Result<CanonicalFrame<'_>, CanonicalDecodingError> =
        decode_canonical_frame_bounded(input, MAX_FIELDS);
    match (expected, decoded) {
        (Some(expected), Ok(frame)) => {
            assert_eq!(frame.type_id(), expected.type_id, "{label}");
            assert_eq!(frame.version(), expected.version, "{label}");
            assert_eq!(frame.field_count(), expected.fields.len(), "{label}");
            let mut encoder: CanonicalStruct =
                CanonicalStruct::new(expected.type_id, expected.version);
            for field in expected.fields {
                assert_eq!(
                    frame.required_field(field.id).unwrap(),
                    field.bytes.as_slice(),
                    "{label}"
                );
                encoder.field_bytes(field.id, field.bytes).unwrap();
            }
            assert_eq!(encoder.finish().unwrap(), input, "{label}");
            None
        }
        (None, Err(error)) => Some(error),
        (Some(expected), Err(error)) => {
            panic!("reference accepted but decoder refused {label}: {expected:?}: {error}");
        }
        (None, Ok(frame)) => panic!("decoder accepted malformed {label}: {frame:?}"),
    }
}

fn mutate(model: &FrameModel, original: &[u8], rng: &mut SeededBytes, kind: usize) -> Vec<u8> {
    let mut input: Vec<u8> = original.to_vec();
    let mut starts: Vec<usize> = Vec::with_capacity(model.fields.len());
    let mut offset: usize = HEADER_BYTES;
    for field in &model.fields {
        starts.push(offset);
        offset += FIELD_HEADER_BYTES + field.bytes.len();
    }
    match kind {
        0 => {
            let at: usize = rng.below(input.len());
            input[at] ^= 1_u8 << rng.below(8);
        }
        1 => input[0] ^= 0x80,
        2 => input[4..6].copy_from_slice(&rng.word().to_le_bytes()),
        3 => input[6..8].copy_from_slice(&rng.word().to_le_bytes()),
        4 => input[8..10].copy_from_slice(&u16::try_from(MAX_FIELDS + 1).unwrap().to_le_bytes()),
        5 => input.truncate(rng.below(input.len())),
        6 => input.push(rng.byte()),
        7 | 11 => {
            if let Some(start) = starts.first() {
                let length: u32 = if kind == 7 {
                    u32::MAX
                } else {
                    u32::try_from(rng.below(MAX_INPUT_BYTES)).unwrap()
                };
                input[*start + 2..*start + FIELD_HEADER_BYTES]
                    .copy_from_slice(&length.to_le_bytes());
            } else {
                input[8..10].copy_from_slice(&1_u16.to_le_bytes());
            }
        }
        8 => input[8..10]
            .copy_from_slice(&u16::try_from(model.fields.len() + 1).unwrap().to_le_bytes()),
        9 => {
            if let Some(start) = starts.first() {
                input[*start..*start + 2].copy_from_slice(&rng.word().to_le_bytes());
            } else {
                input.push(0);
            }
        }
        10 if starts.len() >= 2 => {
            let second: usize = starts[1];
            let end: usize = second + FIELD_HEADER_BYTES + model.fields[1].bytes.len();
            input = original[..HEADER_BYTES].to_vec();
            input.extend_from_slice(&original[second..end]);
            input.extend_from_slice(&original[HEADER_BYTES..second]);
            input.extend_from_slice(&original[end..]);
        }
        10 => input[0] ^= 1,
        12 => {
            if let Some(index) = model
                .fields
                .iter()
                .position(|field| !field.bytes.is_empty())
            {
                input[starts[index] + FIELD_HEADER_BYTES] ^= 0xff;
            } else {
                input[4] ^= 1;
            }
        }
        13 => {
            let at: usize = starts.last().copied().unwrap_or(9);
            input.remove(at);
        }
        14 => input.insert(starts.first().copied().unwrap_or(HEADER_BYTES), rng.byte()),
        15 => {
            let last: u16 = model.fields.last().map_or(0, |field| field.id);
            if model.fields.len() < MAX_FIELDS && last < u16::MAX {
                let mut extended: FrameModel = model.clone();
                extended.fields.push(FieldModel {
                    id: last.checked_add(1).unwrap(),
                    bytes: vec![rng.byte()],
                });
                input = wire(&extended);
            } else {
                input[6] ^= 1;
            }
        }
        _ => panic!("closed mutation operator"),
    }
    assert!(input.len() <= MAX_INPUT_BYTES);
    input
}

fn fixed_rejections() -> [(&'static str, Vec<u8>, Option<usize>); 12] {
    let empty: Vec<u8> = wire(&FrameModel {
        type_id: 0x7a01,
        version: 1,
        fields: Vec::new(),
    });
    let mut bad_magic: Vec<u8> = empty.clone();
    bad_magic[0] ^= 1;
    let mut count_nine: Vec<u8> = empty.clone();
    count_nine[8..10].copy_from_slice(&9_u16.to_le_bytes());
    let mut count_max: Vec<u8> = empty.clone();
    count_max[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut missing_header: Vec<u8> = empty.clone();
    missing_header[8..10].copy_from_slice(&1_u16.to_le_bytes());
    let mut missing_payload: Vec<u8> = missing_header.clone();
    missing_payload.extend_from_slice(&[1, 0, 1, 0, 0, 0]);
    let mut huge_length: Vec<u8> = missing_header.clone();
    huge_length.extend_from_slice(&1_u16.to_le_bytes());
    huge_length.extend_from_slice(&u32::MAX.to_le_bytes());
    let pair = |first: u16, second: u16| -> Vec<u8> {
        wire(&FrameModel {
            type_id: 0x7a01,
            version: 1,
            fields: vec![
                FieldModel {
                    id: first,
                    bytes: Vec::new(),
                },
                FieldModel {
                    id: second,
                    bytes: Vec::new(),
                },
            ],
        })
    };
    let mut trailing_byte: Vec<u8> = empty.clone();
    trailing_byte.push(0);
    let mut undeclared_field: Vec<u8> = empty.clone();
    undeclared_field.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
    [
        ("empty", Vec::new(), None),
        ("short-header", empty[..9].to_vec(), None),
        ("wrong-magic", bad_magic, None),
        ("field-count-nine", count_nine, Some(9)),
        (
            "field-count-u16-max",
            count_max,
            Some(usize::from(u16::MAX)),
        ),
        ("missing-field-header", missing_header, None),
        ("missing-field-payload", missing_payload, None),
        ("u32-max-field-length", huge_length, None),
        ("duplicate-field", pair(1, 1), None),
        ("descending-fields", pair(2, 1), None),
        ("trailing-byte", trailing_byte, None),
        ("undeclared-field", undeclared_field, None),
    ]
}

#[test]
fn bounded_seeded_frame_mutation_campaign() {
    let mut mutations: usize = 0;
    let mut accepted: usize = 0;
    let mut refused: usize = 0;
    for seed in SEEDS {
        let mut rng: SeededBytes = SeededBytes { state: seed };
        for case in 0..FRAMES_PER_SEED {
            let expected: FrameModel = model(&mut rng, case);
            let original: Vec<u8> = wire(&expected);
            assert_eq!(reference(&original), Some(expected.clone()));
            let label: String = format!("seed={seed:016x} case={case} valid");
            assert!(check_case(&original, &label).is_none());
            for kind in 0..MUTATIONS_PER_FRAME {
                let input: Vec<u8> = mutate(&expected, &original, &mut rng, kind);
                let label: String = format!("seed={seed:016x} case={case} mutation={kind}");
                if check_case(&input, &label).is_none() {
                    accepted += 1;
                } else {
                    refused += 1;
                }
                mutations += 1;
            }
        }
    }
    assert_eq!(
        mutations,
        SEEDS.len() * FRAMES_PER_SEED * MUTATIONS_PER_FRAME
    );
    assert_eq!(accepted + refused, 4096);
    assert!(accepted > 0 && refused > 0);
    for (label, input, count) in fixed_rejections() {
        let error: CanonicalDecodingError =
            check_case(&input, label).expect("fixed malformed control");
        if let Some(actual) = count {
            assert_eq!(
                error,
                CanonicalDecodingError::FieldCountExceeded {
                    maximum: MAX_FIELDS,
                    actual
                }
            );
        }
    }
}
