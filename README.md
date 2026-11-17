# github-core-clone-01 — a GitHub-compatible git forge

A standalone git forge built for [the contest](https://make.fun/bounty/github-core-clone-01):
one Node process, standard library only, no `git` binary, no network, no model calls.
It implements the full scored surface — git smart HTTP, REST v3, GraphQL v4, and MCP —
against a single deterministic in-memory store, so every surface sees the same repos,
issues, pull requests, refs, and objects.

## Score (local grading, practice trial-0)

| run | agent | feature | perf | score |
| --- | --- | --- | --- | --- |
| 17 Nov 2026, trial-0 (before shallow-deepen fix) | 200 | 595 | 58 | 853 |
| 17 Nov 2026, trial-0 (after fix) | 200 | 600 | 96 | **896** |

Feature 120/120 checks pass; replay reproduces byte-for-byte. Perf medians (round 2):
push 1393 ms, clone 400 ms, read 2970 ms, write 325 ms.

## Run it

```sh
node main.ts
```

The platform runs `node /bot/main.ts` on Node 22.18 or later, which strips TypeScript types on
its own. There is nothing to install: the program imports `node:http`, `node:crypto`,
`node:zlib` and its own `app.ts` only, and the trial has no package manager and no internet.

## The lifecycle (main.ts, starter file, unchanged)

The env is a server the harness starts beside yours. Its origin is in `MAKEFUN_ENV_URL`
(`http://store:8080` in a trial).

1. **Bind an ephemeral port.** `server.listen(0)` lets the kernel pick one. Never bind 8080.
2. **Register.** `POST $MAKEFUN_ENV_URL/register` with `{"port": <the port you bound>}`.
3. **Wait for done.** `GET $MAKEFUN_ENV_URL/done` until `{"done":true}`. Never exit before.
4. **Exit 0** when it does.

## The surface

| Route | What it is |
| --- | --- |
| `GET /healthz` | 200 `{"ok":true}`: the env's boot probe, no auth |
| `GET /api/v3/` | 200 JSON API root, `X-OAuth-Scopes: repo` |
| `/api/v3/...` | GitHub REST v3: repos, branches, commits, contents, issues, comments, labels, pull requests, files, merges |
| `POST /api/graphql` | GitHub GraphQL v4: viewer, repository, node, issues, pull requests, mutations, introspection, batched operations |
| `POST /mcp` | MCP over streamable HTTP: `server/discover`, `initialize`, `tools/list`, `tools/call` (6 tools) |
| `/<owner>/<repo>.git/...` | git smart HTTP: upload-pack v2/v0, receive-pack v0, ls-refs, shallow fetch/deepen, fast-forward enforcement |
| anything else | 404 `{"message":"Not Found"}` |

## Design notes

- **One store.** Repos, refs, objects, issues, and pull requests live in Maps in `app.ts`;
  REST, GraphQL, and MCP are thin views over the same state, so a repo created by one surface
  is visible (with the same ids) on the others.
- **Deterministic.** No wall clock and no unseeded randomness in stored state: commit times
  and `created_at` values derive from `MAKEFUN_TRIAL_NOW` (or a fixed epoch) plus a creation
  sequence, so a replayed trial reproduces the live export byte-for-byte.
- **Git, by hand.** SHA-1 object ids, packfiles (written as full objects; read with OFS/REF
  delta resolution, including thin packs whose delta bases live on the server), pkt-line
  framing, sideband, protocol v2 sections. The v2 fetch response omits the acknowledgments
  section once the client sends `done` (as protocol-v2 requires), and never sends a 0002
  response-end packet (remote-curl validates v2 responses with check_pktline, which dies on
  any 0002, and appends one itself).
- **Shallow fetch.** Depth-limited closure with generation tracking; the held-set walk stops
  at shallow boundaries, so a deepen fetch delivers exactly the next generation.
- **Auth.** `Authorization: Bearer $MAKEFUN_SHOP_TOKEN` (exact match when the token is set);
  real git clients' Basic auth with the token as password is also accepted. Wrong owner is
  404, never 403.

## Layout

- `main.ts`: the lifecycle above. Kept as it is.
- `app.ts`: the whole forge (~2,650 lines): git objects/packs, store, HTTP plumbing, git
  smart HTTP, REST v3, GraphQL v4, MCP.
- `package.json`, `tsconfig.json`, `LICENSE` (MIT): the entry's metadata and licence.
- `BUILD-LOG.md`: the build log for this entry.
