(module
  ;; Standard Asset v1 protocol-v5 module. `transfer` preserves the v1
  ;; whole-object owner-transition entrypoint. `split` and `merge` own the
  ;; coin-body arithmetic: node-core only verifies committed policy, nominal
  ;; type/owner/id invariants and durable atomicity; it never decodes amounts.
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
  ;; begins at offset 70. Split args are 62 bytes; amount begins at 16 and
  ;; recipient Address at 30. These constants are pinned by Rust vectors.
  (func $fail
    (call $abort (i32.const 0) (i32.const 32))
    unreachable)

  (func $copy_source_to_created (local $i i32)
    (local.set $i (i32.const 0))
    (block $done
      (loop $copy
        (br_if $done (i32.ge_u (local.get $i) (i32.const 78)))
        (i32.store8
          (i32.add (i32.const 256) (local.get $i))
          (i32.load8_u (i32.add (i32.const 128) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $copy))))

  ;; Retained byte-for-byte semantic shape of the v1 entrypoint: policy
  ;; synthesis, not this module, performs the owner-only mutation.
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
    ;; Amount and remainder must both stay nonzero: this is partial split,
    ;; not a duplicate owner-transition spelling or a zero-value coin.
    (if (i64.eqz (local.get $amount)) (then (call $fail)))
    (if (i64.le_u (local.get $source) (local.get $amount)) (then (call $fail)))
    (local.set $remainder (i64.sub (local.get $source) (local.get $amount)))
    (call $copy_source_to_created)
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
)
