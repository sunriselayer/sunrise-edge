# Bounded deterministic canonical frame mutation campaign

Run the ordinary, nonignored integration test with:

```sh
cargo test --locked --offline -p canonical-encoding --test bounded_seeded_mutations -- --test-threads=1
```

The existing whole-workspace test owners discover this test without new workflow flags,
dependencies or an external fuzz runtime. A test pass qualifies this
fixed campaign only; it does not establish exhaustive or coverage-guided fuzz
coverage, an independent security audit or whole M7 completion.

The four fixed `u64` seeds are `243f6a8885a308d3`, `13198a2e03707344`,
`a4093822299f31d0` and `082efa98ec4e6c89`. A wrapping test-only byte scheduler
generates 64 frames per seed: 256 valid originals and 16 mutations of each,
for 4,096 mutation cases. Twelve named malformed controls give 4,364 total
decoder inputs. No case or iteration count depends on an environment variable.

Every input is at most 1,024 bytes and is decoded with the existing local
eight-field limit before the production parser allocates its field index.
Generated fields have 0..64 payload bytes, with empty, one-byte and maximum
payloads selected explicitly. Frames exercise 0..8 fields, ascending identifiers,
the maximum field identifier, and varied type/version words. The generated
wire envelope is at most 570 bytes; byte insertion and append mutations remain
inside the explicit 1,024-byte campaign cap. At most 4,468,736 input bytes are
submitted across the whole fixed campaign, without retaining a growing corpus.

An independent simple writer emits literal `SNRE` and little-endian framing
without using the production encoder or sorting fields. A separate bounded
format oracle compares acceptance, type, version, field count and every field
payload with the production decoder. Every accepted input must re-encode to
exactly its original bytes through `CanonicalStruct`, including accepted
type/version and payload mutations. A parser panic fails the ordinary test.

Mutation operators cover magic, type/version words, declared field counts,
field identifiers and order, field lengths including `u32::MAX`, truncation,
appended/inserted/deleted bytes, payload bit changes and a correctly framed
additional field. Fixed malformed cases must refuse; tiny inputs declaring
nine or 65,535 fields must specifically report `FieldCountExceeded` with the
eight-field maximum. The campaign tests generic canonical framing, without
claiming that arbitrary type/version words satisfy a protocol-specific schema.
