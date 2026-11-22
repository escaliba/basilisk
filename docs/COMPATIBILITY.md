# Roblox compatibility

Basilisk's virtualized output runs on Roblox, with one behavioral exception documented below. The
standalone `luau` CLI (used as the conformance oracle in tests) does not dispatch `__namecall`, so
Roblox-specific metamethod behavior is verified by hand in Studio using the fixtures under
`tests/roblox/`.

## The `__namecall` exception

`obj:method()` compiles to "index the method, then call it", which fires `__index`, not
`__namecall`. Virtualized output therefore resolves method calls through `__index`:

- Method-call syntax and self-passing are preserved. `obj:m(x)` still passes `obj` as the first
  argument, so OOP through `__index` works correctly.
- `__index`, `__newindex`, arithmetic metamethods, length, comparison, and concat all behave
  exactly as native, because the VM applies native Luau operators to native values.
- `__namecall` is never invoked by virtualized output. This is inherent to virtualization and is
  not a bug. Reaching `__namecall` would require a
  `NO_VIRTUALIZE`-style escape that leaves the affected function as plain Luau (a planned macro).

## Test fixtures

`tests/roblox/src/*.luau` are the original scripts. Their virtualized counterparts under
`tests/roblox/virtualized/` are generated output and are not tracked in Git (regenerate them after
any VM or compiler change):

```sh
cargo build -p cli
./target/debug/basilisk tests/roblox/src/metamethods.luau tests/roblox/virtualized/metamethods.luau
./target/debug/basilisk tests/roblox/src/namecall.luau     tests/roblox/virtualized/namecall.luau
```

## Studio procedure

For each script, paste `src/<name>.luau` into a `Script`, run it once and note the Output, then run
the virtualized version in a fresh `Script` and compare.

### `metamethods`: identical output expected

```
index-table   true   hi from obj
index-func    computed:anything   computed:other
newindex      50
method-chain  12
```

A difference here is a real VM bug; please report it.

### `namecall`: divergence expected on Roblox

```
original     namecall-result   via-namecall   1   2     (Roblox fires __namecall)
virtualized  namecall-result   via-index      1   2     (virtualization fires __index)
```

Under the standalone `luau` CLI both print `via-index`, because that runtime never dispatches
`__namecall`.
