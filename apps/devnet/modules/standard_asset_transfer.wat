(module
  ;; Standard Asset v1 whole-coin transfer: a validation-only entrypoint.
  ;;
  ;; This module performs no state transition. It exists only to assert the
  ;; exact engine-visible shape a real invocation must have: exactly two
  ;; engine-visible objects (the transferred `Coin<A>` at index 0 and the
  ;; distinct fee-payer `Coin<A>` at index 1; the fee treasury is a third
  ;; declared access but is hidden from this module's execution inputs by
  ;; node-core before this entrypoint ever runs) and the exact
  ;; `StandardAssetTransferArgsV1` frame length. The owner-only mutation of
  ;; index 0 is synthesized and independently re-verified by node-core's
  ;; committed owner-transition policy, never by this module; the fee
  ;; debit/credit is composed by trusted node composition. Every other
  ;; check (typed schema/asset-identity agreement between the two Write
  ;; params, sender ownership, recipient admissibility) is enforced by
  ;; node-core before and after this call, never here.
  (import "env" "get_object_count" (func $get_object_count (result i32)))
  (import "env" "get_args_len"     (func $get_args_len     (result i32)))
  (import "env" "abort"            (func $abort            (param i32 i32)))

  (memory (export "memory") 1)

  (data (i32.const 0) "invalid standard asset transfer arguments")

  (func $fail
    (call $abort (i32.const 0) (i32.const 41))
    unreachable)

  (func (export "transfer")
    (if
      (i32.ne (call $get_object_count) (i32.const 2))
      (then (call $fail)))
    (if
      (i32.ne (call $get_args_len) (i32.const 48))
      (then (call $fail)))))
