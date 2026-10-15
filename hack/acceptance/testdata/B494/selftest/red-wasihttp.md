# Self-test fixture

Prose before the table is ignored.

## Spike questions (fixture)

| # | question (abbreviated) | answer | evidence sha256 | reason/notes |
|---|---|---|---|---|
| (a) | libwasmtime.a features (WASI, WASI_HTTP) and its provenance digest | FAIL | a6765e1389313ea459e5dbe3d199b51aca28bb38ff1355a2f8b15966b983493d | conf.h lacks WASMTIME_FEATURE_WASI_HTTP |
| (b) | WASI p1 hello: exit code and stdout in the crilog file | PASS | ce8d2130c09002cfb1c62105aaa462459c7a88fb263ab14af4ff1f4d961bed3f | observed |
| (c) | wasi:http incoming-handler on a post-sandbox pod-IP listener | PASS | 63d50dd6da37eb9c9d5e3fcbeec7bf9a8f95731636aa2e7acbc81fc687bd98b2 | observed |
| (d) | Cranelift under Seatbelt, ad-hoc and -o runtime signed | PASS | 0dbed0335e2decfd0647ad2cc5562b979a1201fa894c3468b9f8aa1162b6ccff | observed |
| (e) | footprint (compile+load peak, steady), cold start, binary size | PASS | 9478c3072f4fa8e761a7fb9845cafce7b3345cb0158cde6589e79b14620fba80 | observed |
| (f) | StoreLimits above the pod limit: the sampler OOMKills first | PASS | ffacba1c3a5974b4d8bb9edc1096b3f18c4e64a787a5a600292beb1b9b740c06 | observed |
| (g) | a wasi/wasm32 OCI image through the existing Puller | N/A | a3bff59c718f9c48ffc5dfc56d08157db2c99e8f9260f7e35eaa13bf431ab635 | no platform row exists yet |
| (h) | SIGTERM within the grace period; traps with Go handlers installed | PASS | 2942b21dbc5c0b4b69d74c28ab44c9c84dc4d0ed12631a0ec0905e7a8480a873 | observed |
| (i) | WasiConfig p1 sock_accept listener preopen | FAIL | 9ddd7027e4b0d57becd2905e837842b51e71fce66e51ee12deb4a7717752c53d | no listener preopen |
| (j) | the engine in-process under -race on darwin/arm64 | PASS | aff4cff9452450185aeae14d805aaccbfef2a23bc352e863a5a9d1b900b851ad | observed |
| (k) | raw cosign signature fetch per transport; payload digest; format | PASS | ca19f66137f0206ab219e1540fe94e623d45a3019ae96a54bbe8dd2d8d6ea28c | observed |
| (l) | offline stdlib verification and its distinct error classes | PASS | c4c6093e78241439980a06706a46d1b8055daa13176f1a0a2fd6b5b01463116a | observed |

## Next section

| unrelated | table |
|---|---|
| x | y |
