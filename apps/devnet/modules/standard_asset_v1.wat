(module
  ;; Canonical Standard Asset module version 1. `transfer`, `split`, `merge`,
  ;; bounded `mint`, and whole-coin `burn` are the initial active surface.
  ;; `mint` reads and mutates a supply-bounded TreasuryCap<A>: it checked-adds
  ;; the requested amount into the cap's
  ;; total_supply, rejects the call if that would exceed max_supply, and
  ;; commits the mutated cap atomically with the one created recipient
  ;; Coin<A>. `burn` checked-subtracts a whole consumed coin's amount from
  ;; the same cap and commits the mutated cap atomically with the coin's
  ;; Consume. Node-core remains asset-generic and validates the committed
  ;; typed signature, recipient, type source, id, and atomicity.
  (import "env" "get_object_count"     (func $get_object_count     (result i32)))
  (import "env" "get_object_data_len"  (func $get_object_data_len  (param i32) (result i32)))
  (import "env" "read_object_data"     (func $read_object_data     (param i32 i32 i32 i32) (result i32)))
  (import "env" "write_object_data"    (func $write_object_data    (param i32 i32 i32) (result i32)))
  (import "env" "consume_object"       (func $consume_object       (param i32) (result i32)))
  (import "env" "create_object"        (func $create_object        (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "env" "get_object_type_hash" (func $get_object_type_hash (param i32 i32) (result i32)))
  (import "env" "get_args_len"         (func $get_args_len         (result i32)))
  (import "env" "read_args"            (func $read_args            (param i32 i32 i32) (result i32)))
  (import "env" "abort"                (func $abort                (param i32 i32)))

  (memory (export "memory") 1)
  (data (i32.const 0) "invalid standard asset operation")

  ;; StandardAssetCoinV1 is the fixed 78-byte canonical form: the u64 amount
  ;; begins at offset 70. Split and mint args are 62 bytes; amount begins at
  ;; 16 and recipient Address at 30. StandardAssetTreasuryCapV1 is the fixed
  ;; 92-byte canonical form: header(10) + asset_id field(54) + total_supply
  ;; field(14) + max_supply field(14); total_supply begins at offset 70 and
  ;; max_supply at offset 84. Its header/asset_id prefix (bytes 0..64) is
  ;; byte-identical in shape to the frozen MintCapabilityV1, so mint reuses
  ;; the same in-place conversion technique as the discarded development
  ;; mint fixture.
  (func $fail
    (call $abort (i32.const 0) (i32.const 32))
    unreachable)

  (func $copy_78 (param $source i32) (param $target i32) (local $i i32)
    (local.set $i (i32.const 0))
    (block $done
      (loop $copy
        (br_if $done (i32.ge_u (local.get $i) (i32.const 78)))
        (i32.store8
          (i32.add (local.get $target) (local.get $i))
          (i32.load8_u (i32.add (local.get $source) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $copy))))

  (func $copy_64 (param $source i32) (param $target i32) (local $i i32)
    (local.set $i (i32.const 0))
    (block $done
      (loop $copy
        (br_if $done (i32.ge_u (local.get $i) (i32.const 64)))
        (i32.store8
          (i32.add (local.get $target) (local.get $i))
          (i32.load8_u (i32.add (local.get $source) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $copy))))

  (func (export "transfer")
    (if (i32.ne (call $get_object_count) (i32.const 2)) (then (call $fail)))
    (if (i32.ne (call $get_args_len) (i32.const 48)) (then (call $fail))))

  ;; sender source Write at index 0, sender fee Write at index 1, hidden
  ;; trusted treasury final Write. Creates exactly one recipient-owned coin.
  (func (export "split") (local $amount i64) (local $source i64) (local $remainder i64)
    (if (i32.ne (call $get_object_count) (i32.const 2)) (then (call $fail)))
    (if (i32.ne (call $get_args_len) (i32.const 62)) (then (call $fail)))
    (if (i32.ne (call $get_object_data_len (i32.const 0)) (i32.const 78)) (then (call $fail)))
    (if (i32.ne (call $read_object_data (i32.const 0) (i32.const 0) (i32.const 128) (i32.const 78)) (i32.const 78)) (then (call $fail)))
    (if (i32.ne (call $read_args (i32.const 0) (i32.const 512) (i32.const 62)) (i32.const 62)) (then (call $fail)))
    (local.set $amount (i64.load offset=16 (i32.const 512)))
    (local.set $source (i64.load offset=70 (i32.const 128)))
    (if (i64.eqz (local.get $amount)) (then (call $fail)))
    (if (i64.le_u (local.get $source) (local.get $amount)) (then (call $fail)))
    (local.set $remainder (i64.sub (local.get $source) (local.get $amount)))
    (call $copy_78 (i32.const 128) (i32.const 256))
    (i64.store offset=70 (i32.const 128) (local.get $remainder))
    (i64.store offset=70 (i32.const 256) (local.get $amount))
    (if (i32.ne (call $get_object_type_hash (i32.const 0) (i32.const 64)) (i32.const 34)) (then (call $fail)))
    (if (i32.ne (call $write_object_data (i32.const 0) (i32.const 128) (i32.const 78)) (i32.const 0)) (then (call $fail)))
    (if (i32.ne
      (call $create_object
        (i32.const 256) (i32.const 78)
        (i32.const 64) (i32.const 1)
        (i32.const 3) (i32.const 542))
      (i32.const 0))
      (then (call $fail))))

  ;; sender primary Write at index 0, sender secondary Consume at index 1,
  ;; sender fee Write at index 2, hidden trusted treasury final Write.
  (func (export "merge") (local $first i64) (local $second i64) (local $sum i64)
    (if (i32.ne (call $get_object_count) (i32.const 3)) (then (call $fail)))
    (if (i32.ne (call $get_args_len) (i32.const 0)) (then (call $fail)))
    (if (i32.ne (call $get_object_data_len (i32.const 0)) (i32.const 78)) (then (call $fail)))
    (if (i32.ne (call $get_object_data_len (i32.const 1)) (i32.const 78)) (then (call $fail)))
    (if (i32.ne (call $read_object_data (i32.const 0) (i32.const 0) (i32.const 128) (i32.const 78)) (i32.const 78)) (then (call $fail)))
    (if (i32.ne (call $read_object_data (i32.const 1) (i32.const 0) (i32.const 256) (i32.const 78)) (i32.const 78)) (then (call $fail)))
    (local.set $first (i64.load offset=70 (i32.const 128)))
    (local.set $second (i64.load offset=70 (i32.const 256)))
    (if (i64.eqz (local.get $first)) (then (call $fail)))
    (if (i64.eqz (local.get $second)) (then (call $fail)))
    (local.set $sum (i64.add (local.get $first) (local.get $second)))
    (if (i64.lt_u (local.get $sum) (local.get $first)) (then (call $fail)))
    (i64.store offset=70 (i32.const 128) (local.get $sum))
    (if (i32.ne (call $write_object_data (i32.const 0) (i32.const 128) (i32.const 78)) (i32.const 0)) (then (call $fail)))
    (if (i32.ne (call $consume_object (i32.const 1)) (i32.const 0)) (then (call $fail))))

  ;; Write TreasuryCap<A> at index 0, sender fee Coin<A> Write at index 1,
  ;; hidden trusted treasury final Write. Checked-adds the requested amount
  ;; into the cap's total_supply, rejecting overflow and any amount that
  ;; would push total_supply above max_supply, then commits the mutated cap
  ;; atomically with the one created recipient Coin<A>. The cap's nested
  ;; AssetId bytes become the created body; the fee coin supplies the exact
  ;; Coin<A> nominal type hash and schema version committed by the creation
  ;; policy.
  (func (export "mint") (local $amount i64) (local $total i64) (local $max i64) (local $new_total i64)
    (if (i32.ne (call $get_object_count) (i32.const 2)) (then (call $fail)))
    (if (i32.ne (call $get_args_len) (i32.const 62)) (then (call $fail)))
    (if (i32.ne (call $get_object_data_len (i32.const 0)) (i32.const 92)) (then (call $fail)))
    (if (i32.ne (call $get_object_data_len (i32.const 1)) (i32.const 78)) (then (call $fail)))
    (if (i32.ne (call $read_object_data (i32.const 0) (i32.const 0) (i32.const 128) (i32.const 92)) (i32.const 92)) (then (call $fail)))
    (if (i32.ne (call $read_args (i32.const 0) (i32.const 512) (i32.const 62)) (i32.const 62)) (then (call $fail)))
    (local.set $amount (i64.load offset=16 (i32.const 512)))
    (if (i64.eqz (local.get $amount)) (then (call $fail)))
    (local.set $total (i64.load offset=70 (i32.const 128)))
    (local.set $max (i64.load offset=84 (i32.const 128)))
    (local.set $new_total (i64.add (local.get $total) (local.get $amount)))
    (if (i64.lt_u (local.get $new_total) (local.get $total)) (then (call $fail)))
    (if (i64.gt_u (local.get $new_total) (local.get $max)) (then (call $fail)))
    (i64.store offset=70 (i32.const 128) (local.get $new_total))
    (if (i32.ne (call $write_object_data (i32.const 0) (i32.const 128) (i32.const 92)) (i32.const 0)) (then (call $fail)))
    (call $copy_64 (i32.const 128) (i32.const 256))
    ;; Convert CanonicalStruct(0x7107,v1){asset_id,total_supply,max_supply}'s
    ;; header/asset_id prefix into CanonicalStruct(0x7102,v1){asset_id,amount}.
    (i32.store16 offset=4 (i32.const 256) (i32.const 28930))
    (i32.store16 offset=8 (i32.const 256) (i32.const 2))
    (i32.store16 offset=64 (i32.const 256) (i32.const 2))
    (i32.store offset=66 (i32.const 256) (i32.const 8))
    (i64.store offset=70 (i32.const 256) (local.get $amount))
    (if (i32.ne (call $get_object_type_hash (i32.const 1) (i32.const 64)) (i32.const 34)) (then (call $fail)))
    (if (i32.ne
      (call $create_object
        (i32.const 256) (i32.const 78)
        (i32.const 64) (i32.const 1)
        (i32.const 3) (i32.const 542))
      (i32.const 0))
      (then (call $fail))))

  ;; Write TreasuryCap<A> at index 0, sender Consume Coin<A> at index 1,
  ;; sender fee Coin<A> Write at index 2, hidden trusted treasury final
  ;; Write. Checked-subtracts the whole consumed coin's amount from the
  ;; cap's total_supply and commits the mutated cap atomically with the
  ;; coin's Consume. Creates nothing.
  (func (export "burn") (local $burned i64) (local $total i64) (local $new_total i64)
    (if (i32.ne (call $get_object_count) (i32.const 3)) (then (call $fail)))
    (if (i32.ne (call $get_args_len) (i32.const 0)) (then (call $fail)))
    (if (i32.ne (call $get_object_data_len (i32.const 0)) (i32.const 92)) (then (call $fail)))
    (if (i32.ne (call $get_object_data_len (i32.const 1)) (i32.const 78)) (then (call $fail)))
    (if (i32.ne (call $read_object_data (i32.const 0) (i32.const 0) (i32.const 128) (i32.const 92)) (i32.const 92)) (then (call $fail)))
    (if (i32.ne (call $read_object_data (i32.const 1) (i32.const 0) (i32.const 256) (i32.const 78)) (i32.const 78)) (then (call $fail)))
    (local.set $burned (i64.load offset=70 (i32.const 256)))
    (if (i64.eqz (local.get $burned)) (then (call $fail)))
    (local.set $total (i64.load offset=70 (i32.const 128)))
    (if (i64.lt_u (local.get $total) (local.get $burned)) (then (call $fail)))
    (local.set $new_total (i64.sub (local.get $total) (local.get $burned)))
    (i64.store offset=70 (i32.const 128) (local.get $new_total))
    (if (i32.ne (call $write_object_data (i32.const 0) (i32.const 128) (i32.const 92)) (i32.const 0)) (then (call $fail)))
    (if (i32.ne (call $consume_object (i32.const 1)) (i32.const 0)) (then (call $fail))))
)
