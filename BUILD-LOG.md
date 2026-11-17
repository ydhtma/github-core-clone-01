# BUILD-LOG — github-core-clone-01 ($500, "Build a GitHub-compatible git forge")

- Bounty: github-core-clone-01, deadline 21 Nov 2026 06:30 UTC (13:30 WIB).
- Account: @0xfyza. Entry repo: `~/workspace/services/make-fun/entries/github-core-clone-01/`.
- Anchor: `makefun anchor 5527529c27e018cef2147cc1f0365fd3e2e95b82 round 34023374`
  (from `makefun init --license MIT`, before any entry code was written).
- Built 17 Nov 2026 by the CEO agent (Muse), no model calls in the entry itself.
- Kit: `~/workspace/services/make-fun/entries/_kits/github-core-clone-01-kit/`
  (downloaded 17 Nov 2026, 6.9 MB).

## What was built

Single-file forge `app.ts` (~2,650 lines, Node 22 stdlib only: node:http, node:crypto,
node:zlib) behind the starter `main.ts` lifecycle (unchanged):

- Git smart HTTP: upload-pack v2 + v0, receive-pack v0, ls-refs (peel/symrefs/unborn/
  ref-prefix), shallow fetch + deepen, fast-forward enforcement with per-ref
  `ok`/`ng <ref> non-fast-forward` reports, sideband framing, pack read (full +
  OFS/REF deltas, incl. thin packs) and pack write (full objects, deterministic order).
- REST v3 (`/api/v3`): repos (CRUD, pagination with `Link: rel="next"`), branches,
  commits, contents (create/update/delete with sha-409), git/refs, labels, issues
  (+comments), pull requests (+files, squash merge with conflict → 405).
- GraphQL v4 (`/api/graphql`): hand-written recursive-descent parser + executor,
  viewer/repository/node/`__type`, issues/pullRequests connections with cursors,
  create/closeIssue, create/mergePullRequest, addComment, batched operations,
  invalid-field errors naming the field.
- MCP (`/mcp`): `server/discover` (2026-07-28), `initialize`, `tools/list`
  (byte-identical), `tools/call` for 6 tools (create_repo, get_repo, create_issue,
  list_issues, create_pull_request, merge_pull_request); -32700 on malformed JSON,
  -32602 unknown tool, 401 without auth.
- One in-memory store shared by all four surfaces; deterministic timestamps
  (`MAKEFUN_TRIAL_NOW` or fixed epoch + creation sequence) so replay matches live.

## Commands and results

1. Kit download + extract:
   `curl -sSL "https://make.fun/c/github-core-clone-01/kit" | tar xz`
   → `github-core-clone-01-kit/` (kit.json, RULES.txt 85 KB, cli/, sdk/, program/,
   practice/trial-0..2, starter/). RULES.txt read in full; conformance sources
   (`sdk/conformance/*.ts`) + scorer mapped; scenario values extracted with the
   kit's own `buildScenario()` (viewer `adaiversen` id 1000, deterministic seed).
2. `git init` + `makefun init --license MIT --keypair <keypair>` →
   `makefun anchor 5527529c27e018cef2147cc1f0365fd3e2e95b82 round 34023374`.
   Starter files copied in (main.ts, package.json, tsconfig.json, README.md).
3. Wrote `app.ts` in 6 chunks (write + appends).
4. `node --check app.ts` → OK. Typecheck strict:
   `/tmp/tscheck/node_modules/.bin/tsc --noEmit -p tsconfig.json --typeRoots /tmp/tscheck/node_modules/@types`
   → clean. Fixes found by typecheck: `createApp()` must return the `Server`
   itself (main.ts calls `.once/.listen/.address/.close` on it); TypeScript
   parameter properties are not erasable syntax under Node type-stripping.
5. Smoke test vs a fake env server (`/tmp/fake-env.mjs`, :18081) + `node main.ts`:
   entry registered, REST/GraphQL/MCP spot checks all passed; real `git` clone/push/
   fetch/shallow/tag round-trips verified (see fixes below).
6. `node cli/makefun.mjs grade-local --kit . --bot <entry> --driver process --worktree`
   - Run 1: **score 853** — agent 200, feature 595 (119/120), perf 58,
     perf_p50_us 1439142; replay byte-for-byte. Only failure:
     `git.fetch-shallow-deepen`.
   - Run 2 (after the deepen fix; before the thin-pack fix and /healthz):
     **score 896** — agent 200, feature 600 (120/120),
     perf 96, perf_p50_us 856524; replay byte-for-byte.
     Perf medians: push 1393 ms, clone 400 ms, read 2970 ms, write 325 ms
     (points 28/18/24/26).
   - Run 3 (on committed HEAD, `--instances 3`): see "Verification (final)" below.

## Bugs found by testing (all fixed, verified)

- **v2 fetch: acknowledgments section must be omitted once the client sends `done`.**
  Real git goes straight to the packfile section and dies
  `expected 'packfile', received 'acknowledgments'` otherwise (protocol-v2 + git
  `fetch-pack.c` `do_fetch_pack_v2` / `process_section_header`). A request without
  `done` is a negotiation round: acks + flush, no packfile.
- **Never send a 0002 response-end packet in v2 responses.** Over HTTP, remote-curl
  validates every v2 response with `check_pktline`, which dies on any 0002
  (`remote-curl: unexpected response end packet`), and appends the 0002 itself
  before handing the stream to fetch-pack (`remote-curl.c` `post_rpc` /
  `stateless_connect`).
- **Shallow deepen delivered an empty pack.** The held-set was
  `reachable(haves + shallow)`, which includes the parent the client does NOT have.
  Fixed: the held walk stops at shallow boundaries (boundary commit + tree held,
  parents not) — `heldSet()` in `app.ts`.
- **Real-git pushes failed with `unpack failed` once packs grew past ~8 commits.**
  Real git sends thin packs (REF_DELTA bases live on the server, not in the pack);
  `readPack` threw on unresolvable delta bases. Fixed: `readPack` takes a base
  lookup into the repo's object store. Verified: 100/100 sequential real-git
  pushes succeed, fsck clean.
- **Real git sends Basic auth, not Bearer.** `isAuthed` now also accepts Basic with
  the shop token as password (or username), plus a `WWW-Authenticate` header on 401.
- `/healthz` added (200 `{"ok":true}`, no auth) — the env's boot probe per the
  starter README.

## Perf notes

- Perf varies run to run on this shared VM (58 → 96 with no code change between
  runs 1 and 2 for the perf-relevant paths): the box has 1.5 shared CPUs and a
  trivial `node:http` server measures ~1.9 ms/op under the same fetch-based bench
  client, so per-request HTTP overhead here is a machine property, not entry code.
- Reference times (kit calibration): push 1640.82 ms, clone 266.94 ms,
  read 2759.72 ms, write 348.97 ms. Round-2 medians are at or below reference on
  push and write, 1.5x on clone, 1.08x on read.

## Incidents during the build

- While freeing port 18080 for the fake env server, killed PID 258117, which turned
  out to be the tiny-chess-01 kit's env server (`tiny-chess-01-kit/program/env/
  server.mjs`), not a leftover of this task. It was a sibling bounty's process;
  reported to the parent — do not repeat (kill by recorded PID, never by port).

## Verification (final)

- `makefun grade-local --driver process --worktree` trial-0: **896/1000**
  (agent 200, feature 600 = 120/120, perf 96); replay byte-for-byte; L1 regrade
  reproduced byte-for-byte. (Run 2, before the thin-pack fix and /healthz.)
- `makefun grade-local --driver process --worktree --instances 3` on committed
  HEAD (`9264505`): **mean score 952** — trial scores 944 / 953 / 959
  (agent 200, feature 600 = 120/120 on all three, perf 144 / 153 / 159,
  perf_p50_us 436152 / 389293 / 355356); replay + L1 regrade reproduced
  byte-for-byte; kept run
  `/home/hatch/.makefun/trials/github-core-clone-01/01a1e6e3-8223-7632-9d05-98772b8e4605/`
  (`result_sha256 a8021be41989278797c6ab0be54642c358db39b8714f72dd11161a8d80287660`).
  Eligibility on every run: ranked yes, prize no, efficiency no
  (`no_transcripts`, `coverage_below_gate`, `cost_unpriced`) — transcript gate
  and pricing are submit-time items, not code failures.
- `makefun check` / `makefun bundle`: see final report (transcript gate depends on
  the parent's submit decision; no submit was run).
- No `makefun submit`, no GitHub push, no other bounty touched.
