# reduce_queue — a witness that makes an unequal pair equal

Two XDP programs that count packets per RX queue in a hash map:

| | `orig.bpf.c` | `opt.bpf.c` |
|---|---|---|
| queue id variable | `u32` | `u16` (`(__u16)ctx->rx_queue_index`) |
| map key type | `u32` | `u16` |
| behaviour | `queue_packets[queue_id] += 1` | `queue_packets[queue_id] += 1` |

The optimization narrows a 32-bit variable (and the map key) to 16 bits. That
is only sound if the RX queue index never exceeds 65535.

## Under plain semantic checking: NOT equivalent

```
python3 verify_mixed_entries.py orig.bpf.o opt.bpf.o \
    count_by_queue count_by_queue queue_packets:hash
```

```
[!] BTF MISMATCH: map 'queue_packets' key_size differs: C=4 vs Rust=2
equivalent: False
result_type: error
```

The checker cannot even compare a `map<u32,_>` against a `map<u16,_>`.

## Under the transformation witness: equivalent

```
python3 verify_mixed_entries.py orig.bpf.o opt.bpf.o \
    count_by_queue count_by_queue --witness witness.json
```

```
[+] map_correspondence 'queue_packets': C key 32b ↔ Rust key 16b via truncate(k, 16); value equal
    map_correspondence 'queue_packets': key domain restricted by assume k <= 65535
[SUCCESS] Programs are EQUIVALENT.
```

`witness.json` says:

- **assumption** `rx_queue_index <= 65535` — the 32-bit input range is narrowed
  to `0 .. 2^16-1`.
- **binding** `queue_packets`: `map_correspondence` with
  `optimized_key = truncate(k, 16)` and `assume: k <= 65535` — the original
  entry at key `k` corresponds to the optimized entry at `k & 0xffff`, and the
  key domain is the assumed range so the narrowing is lossless.

## The range assumption is load-bearing

Drop the `assume` from the `map_correspondence` (and the top-level assumption)
and the same witness reports:

```
[!] MISMATCH DETECTED! Programs are NOT equivalent.
      Map 'queue_packets' at key=0xffff0000: ... EXTRA_KEY: Rust created an entry that C did not.
```

`rx_queue_index = 0xffff0000` collides with queue `0` in the 16-bit map — the
optimization is wrong without the bound.

## Rebuilding the objects

```
CLANG=clang-14 ./build.sh
```
