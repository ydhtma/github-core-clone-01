// github-core-clone-01: a standalone GitHub-compatible git forge.
// Node 22 stdlib only: node:http, node:crypto, node:zlib. No git binary, no network.
// Surfaces: git smart HTTP (upload-pack v2/v0, receive-pack v0), REST v3 (/api/v3),
// GraphQL v4 (/api/graphql), MCP over Streamable HTTP (/mcp).
// State is in-memory only: one process, one trial, deterministic (fixed epoch + sequence).

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// -------------------------------------------------------------------------------------------
// constants
// -------------------------------------------------------------------------------------------

const JSON_TYPE = 'application/json; charset=utf-8';
const ZERO_OID = '0000000000000000000000000000000000000000';
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const AGENT_NAME = 'makefun-forge/1.0';
const FORGE_VERSION = '1.0.0';
const DEFAULT_BRANCH = 'main';
// Deterministic clock: the trial's own now when given, else a fixed epoch. All stored
// timestamps derive from this plus a per-repo sequence, so a replay matches live exactly.
const EPOCH_SEC = (() => {
  const now = Number(process.env.MAKEFUN_ENV_URL === undefined ? '' : process.env.MAKEFUN_TRIAL_NOW ?? '');
  if (Number.isFinite(now) && now > 0) return Math.floor(now / 1000);
  return 1735689600;
})();
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

// -------------------------------------------------------------------------------------------
// small utilities
// -------------------------------------------------------------------------------------------

function sha1(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function hashObject(type: string, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1(Buffer.concat([header, data]));
}

function isOid(s: string): boolean {
  return /^[0-9a-f]{40}$/.test(s);
}

function b64encode(buf: Buffer): string {
  return buf.toString('base64');
}

function b64decode(s: string): Buffer {
  return Buffer.from(s.replace(/\s+/g, ''), 'base64');
}

function isoOf(seq: number): string {
  return new Date((EPOCH_SEC + seq) * 1000).toISOString();
}

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// -------------------------------------------------------------------------------------------
// pkt-line framing
// -------------------------------------------------------------------------------------------

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type PktKind = 'data' | 'flush' | 'delim' | 'response-end';

interface Pkt {
  kind: PktKind;
  payload: Buffer;
}

/** Parse a whole buffer of pkt-lines; returns packets and the offset where data stops being pkt-lines. */
function decodePktLines(buf: Buffer): { packets: Pkt[]; restOffset: number } {
  const packets: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = parseInt(head, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, restOffset: off };
}

function pktLinesText(packets: Pkt[]): string[] {
  const out: string[] = [];
  for (const p of packets) if (p.kind === 'data') out.push(p.payload.toString('utf8'));
  return out;
}

// -------------------------------------------------------------------------------------------
// git objects
// -------------------------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: ObjType;
  data: Buffer;
}

interface CommitInfo {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    if (space < 0) break;
    const mode = data.subarray(off, space).toString('ascii');
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0) break;
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const ka = a.name + (a.mode === '40000' ? '/' : '');
    const kb = b.name + (b.mode === '40000' ? '/' : '');
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface TagInfo {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

// -------------------------------------------------------------------------------------------
// packfiles (write full objects only; read full + OFS/REF deltas)
// -------------------------------------------------------------------------------------------

function writePack(objects: GitObject[]): Buffer {
  const sorted = [...objects].sort((a, b) => {
    const ha = hashObject(a.type, a.data);
    const hb = hashObject(b.type, b.data);
    return ha < hb ? -1 : ha > hb ? 1 : 0;
  });
  const parts: Buffer[] = [Buffer.from('PACK', 'ascii')];
  const ver = Buffer.alloc(4);
  ver.writeUInt32BE(2, 0);
  parts.push(ver);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(sorted.length, 0);
  parts.push(count);
  const typeNum: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
  for (const obj of sorted) {
    const comp = deflateSync(obj.data);
    const size = obj.data.length;
    const type = typeNum[obj.type];
    // varint: low 4 bits of size in first byte, then 7 bits per byte, msb set while more.
    const headBytes: number[] = [];
    let remaining = size;
    let first = (type << 4) | (remaining & 0x0f);
    remaining >>>= 4;
    if (remaining > 0) first |= 0x80;
    headBytes.push(first);
    while (remaining > 0) {
      let b = remaining & 0x7f;
      remaining >>>= 7;
      if (remaining > 0) b |= 0x80;
      headBytes.push(b);
    }
    parts.push(Buffer.from(headBytes));
    parts.push(comp);
  }
  const trailer = createHash('sha1').update(Buffer.concat(parts)).digest();
  parts.push(trailer);
  return Buffer.concat(parts);
}

function readVarintDelta(buf: Buffer, off: number): { value: number; next: number } {
  let value = 0;
  let shift = 0;
  let i = off;
  for (;;) {
    const b = buf[i];
    i += 1;
    value |= (b & 0x7f) << shift;
    shift += 7;
    if ((b & 0x80) === 0) break;
  }
  return { value, next: i };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const src = readVarintDelta(delta, off);
  off = src.next;
  if (src.value !== base.length) throw new Error('delta base size mismatch');
  const tgt = readVarintDelta(delta, off);
  off = tgt.next;
  const out: Buffer[] = [];
  let outLen = 0;
  while (off < delta.length) {
    const op = delta[off];
    off += 1;
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) if (op & (1 << i)) { cpOff |= delta[off] << (8 * i); off += 1; }
      for (let i = 0; i < 3; i += 1) if (op & (0x10 << i)) { cpSize |= delta[off] << (8 * i); off += 1; }
      if (cpSize === 0) cpSize = 0x10000;
      out.push(base.subarray(cpOff, cpOff + cpSize));
      outLen += cpSize;
    } else if (op !== 0) {
      out.push(delta.subarray(off, off + op));
      outLen += op;
      off += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (outLen !== tgt.value) throw new Error('delta target size mismatch');
  return Buffer.concat(out);
}

/** Inflate exactly one zlib stream starting at `off`; binary-search its end (inflate ignores trailing bytes). */
function inflateOne(buf: Buffer, off: number): { data: Buffer; next: number } {
  let lo = off;
  let hi = buf.length;
  // hi must succeed (a well-formed pack); if the stream runs to the end, hi == buf.length works.
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    try {
      inflateSync(buf.subarray(off, mid));
      hi = mid;
    } catch {
      lo = mid + 1;
    }
  }
  const data = inflateSync(buf.subarray(off, lo));
  return { data, next: lo };
}

interface PackEntry {
  type: ObjType | 'ofs-delta' | 'ref-delta';
  data: Buffer;
  baseOid?: string;
  baseOffset?: number;
  offset: number;
}

/** Read a packfile. `baseLookup` resolves REF_DELTA bases that are not in the pack itself —
 * real git pushes thin packs whose delta bases live on the server, not in the pack. */
function readPack(buf: Buffer, baseLookup?: (oid: string) => GitObject | undefined): GitObject[] {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const entries: PackEntry[] = [];
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const start = off;
    let b = buf[off];
    off += 1;
    const typeNum = (b >> 4) & 0x07;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) {
      b = buf[off];
      off += 1;
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    void size;
    if (typeNum === 6) {
      // OFS_DELTA: negative offset varint
      let byte = buf[off];
      off += 1;
      let baseOff = byte & 0x7f;
      while (byte & 0x80) {
        byte = buf[off];
        off += 1;
        baseOff = ((baseOff + 1) << 7) | (byte & 0x7f);
      }
      const inflated = inflateOne(buf, off);
      off = inflated.next;
      entries.push({ type: 'ofs-delta', data: inflated.data, baseOffset: start - baseOff, offset: start });
    } else if (typeNum === 7) {
      const baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
      const inflated = inflateOne(buf, off);
      off = inflated.next;
      entries.push({ type: 'ref-delta', data: inflated.data, baseOid, offset: start });
    } else {
      const typeMap: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
      const type = typeMap[typeNum];
      if (type === undefined) throw new Error(`unknown pack object type ${typeNum}`);
      const inflated = inflateOne(buf, off);
      off = inflated.next;
      entries.push({ type, data: inflated.data, offset: start });
    }
  }
  // Resolve deltas (possibly chained): iterate until all resolve.
  const byOffset = new Map<number, GitObject>();
  const byOid = new Map<string, GitObject>();
  const resolved: GitObject[] = [];
  const store = (obj: GitObject): void => {
    resolved.push(obj);
    byOid.set(hashObject(obj.type, obj.data), obj);
  };
  const pending = [...entries];
  for (const e of entries) {
    if (e.type !== 'ofs-delta' && e.type !== 'ref-delta') {
      const obj: GitObject = { type: e.type as ObjType, data: e.data };
      byOffset.set(e.offset, obj);
      store(obj);
    }
  }
  let guard = 0;
  let remaining = pending.filter((e) => e.type === 'ofs-delta' || e.type === 'ref-delta');
  while (remaining.length > 0) {
    guard += 1;
    if (guard > 100) throw new Error('delta chain too deep');
    const next: PackEntry[] = [];
    for (const e of remaining) {
      let base: GitObject | undefined;
      if (e.type === 'ofs-delta') base = byOffset.get(e.baseOffset ?? -1);
      else base = byOid.get(e.baseOid ?? '') ?? baseLookup?.(e.baseOid ?? '');
      if (base === undefined) { next.push(e); continue; }
      const data = applyDelta(base.data, e.data);
      const obj: GitObject = { type: base.type, data };
      byOffset.set(e.offset, obj);
      store(obj);
    }
    if (next.length === remaining.length) throw new Error('unresolvable delta base in pack');
    remaining = next;
  }
  return resolved;
}

// -------------------------------------------------------------------------------------------
// store
// -------------------------------------------------------------------------------------------

interface Label {
  name: string;
  color: string;
  description: string;
}

interface IssueComment {
  id: number;
  body: string;
  seq: number;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  seq: number;
  comments: IssueComment[];
  closedSeq: number | null;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  seq: number;
}

interface Repo {
  dbId: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  seq: number;
  labels: Map<string, Label>;
  issues: Map<number, Issue>;
  nextIssue: number;
  nextComment: number;
  pulls: Map<number, Pull>;
  nextPull: number;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  commitSeq: number;
}

let nextDbId = 1;
let nextGlobalId = 1;
const repos = new Map<string, Repo>();
const repoList: Repo[] = [];

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function globalId(kind: string, parts: (string | number)[]): string {
  return Buffer.from(`${kind}:${parts.join(':')}`).toString('base64');
}

function decodeGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const idx = text.indexOf(':');
    if (idx <= 0) return null;
    return { kind: text.slice(0, idx), parts: text.slice(idx + 1).split(':') };
  } catch {
    return null;
  }
}

function createRepo(owner: string, name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    dbId: nextDbId,
    name,
    owner,
    description,
    isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    seq: nextDbId,
    labels: new Map(),
    issues: new Map(),
    nextIssue: 1,
    nextComment: 1,
    pulls: new Map(),
    nextPull: 1,
    refs: new Map(),
    objects: new Map(),
    commitSeq: 0,
  };
  nextDbId += 1;
  nextGlobalId += 1;
  repos.set(repoKey(owner, name), repo);
  repoList.push(repo);
  return repo;
}

function getRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function storeObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

function getObject(repo: Repo, oid: string): GitObject | undefined {
  return repo.objects.get(oid);
}

// Reachable closure from roots (commits, trees, blobs, tags), following everything.
function reachable(repo: Repo, roots: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const stack = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj === undefined) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      stack.push(c.tree);
      for (const p of c.parents) stack.push(p);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) stack.push(e.oid);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    }
  }
  return seen;
}

/** Commits reachable from `root`, with generation (0 = root itself). */
function commitGenerations(repo: Repo, root: string): Map<string, number> {
  const gen = new Map<string, number>();
  const queue: Array<[string, number]> = [[root, 0]];
  while (queue.length > 0) {
    const [oid, g] = queue.shift() as [string, number];
    if (gen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    gen.set(oid, g);
    for (const p of parseCommit(obj.data).parents) queue.push([p, g + 1]);
  }
  return gen;
}

function isAncestor(repo: Repo, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const stack = [descendant];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) stack.push(p);
  }
  return false;
}

/** Merge-base: the common ancestor with the smallest (genFromHead + genFromBase). */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ga = commitGenerations(repo, a);
  const gb = commitGenerations(repo, b);
  let best: string | null = null;
  let bestScore = Infinity;
  for (const [oid, g] of ga) {
    const h = gb.get(oid);
    if (h === undefined) continue;
    const score = g + h;
    if (score < bestScore) { bestScore = score; best = oid; }
  }
  return best;
}

// Flat file map of a tree (path -> {oid, mode}).
function treeToFiles(repo: Repo, treeOid: string, prefix = ''): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (oid: string, pre: string): void => {
    const obj = repo.objects.get(oid);
    if (obj === undefined || obj.type !== 'tree') return;
    for (const e of parseTree(obj.data)) {
      if (e.mode === '40000') walk(e.oid, `${pre}${e.name}/`);
      else out.set(`${pre}${e.name}`, { oid: e.oid, mode: e.mode });
    }
  };
  walk(treeOid, prefix);
  return out;
}

// Build a tree object from a flat file map; returns the tree oid.
function filesToTree(repo: Repo, files: Map<string, { oid: string; mode: string }>): string {
  const build = (prefix: string): string => {
    const entries: TreeEntry[] = [];
    const subdirs = new Set<string>();
    for (const [path, f] of files) {
      if (!path.startsWith(prefix)) continue;
      const rest = path.slice(prefix.length);
      const slash = rest.indexOf('/');
      if (slash < 0) entries.push({ mode: f.mode, name: rest, oid: f.oid });
      else subdirs.add(rest.slice(0, slash));
    }
    for (const dir of subdirs) entries.push({ mode: '40000', name: dir, oid: build(`${prefix}${dir}/`) });
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return build('');
}

function commitTreeOid(repo: Repo, commitOid: string): string | null {
  const obj = repo.objects.get(commitOid);
  if (obj === undefined || obj.type !== 'commit') return null;
  return parseCommit(obj.data).tree;
}

function makeCommit(repo: Repo, treeOid: string, parents: string[], message: string): string {
  const ident = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${EPOCH_SEC} +0000`;
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  let text = `tree ${treeOid}\n`;
  for (const p of parents) text += `parent ${p}\n`;
  text += `author ${ident}\ncommitter ${ident}\n\n${msg}`;
  repo.commitSeq += 1;
  return storeObject(repo, 'commit', Buffer.from(text, 'utf8'));
}

// Diff two trees (flat maps): path -> {status, oldOid, newOid}.
interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'removed';
  oldOid: string | null;
  newOid: string | null;
}

function diffTrees(repo: Repo, baseTree: string | null, headTree: string | null): FileChange[] {
  const base = baseTree === null ? new Map() : treeToFiles(repo, baseTree);
  const head = headTree === null ? new Map() : treeToFiles(repo, headTree);
  const out: FileChange[] = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b !== undefined && h === undefined) out.push({ path, status: 'removed', oldOid: b.oid, newOid: null });
    else if (b === undefined && h !== undefined) out.push({ path, status: 'added', oldOid: null, newOid: h.oid });
    else if (b !== undefined && h !== undefined && b.oid !== h.oid) out.push({ path, status: 'modified', oldOid: b.oid, newOid: h.oid });
  }
  return out;
}

function lineCount(repo: Repo, oid: string | null): number {
  if (oid === null) return 0;
  const obj = repo.objects.get(oid);
  if (obj === undefined) return 0;
  const text = obj.data.toString('utf8');
  if (text === '') return 0;
  const lines = text.split('\n');
  return lines[lines.length - 1] === '' ? lines.length - 1 : lines.length;
}

/** Merge conflict? Compare changes from merge-base to head vs to base-tip on the same paths. */
function mergeConflict(repo: Repo, headTip: string, baseTip: string): boolean {
  const base = mergeBase(repo, headTip, baseTip);
  if (base === null) return true;
  const baseTree = commitTreeOid(repo, base);
  const headTree = commitTreeOid(repo, headTip);
  const tipTree = commitTreeOid(repo, baseTip);
  const headChanges = diffTrees(repo, baseTree, headTree);
  const baseChanges = diffTrees(repo, baseTree, tipTree);
  const baseByPath = new Map(baseChanges.map((c) => [c.path, c]));
  for (const c of headChanges) {
    const other = baseByPath.get(c.path);
    if (other === undefined) continue;
    if (c.newOid !== other.newOid) return true;
  }
  return false;
}

/** Squash-merge: apply head's changes (vs merge-base) onto the base tip's tree. */
function squashMergeTree(repo: Repo, headTip: string, baseTip: string): string | null {
  const base = mergeBase(repo, headTip, baseTip);
  if (base === null) return null;
  const baseTree = commitTreeOid(repo, base);
  const headTree = commitTreeOid(repo, headTip);
  const tipTree = commitTreeOid(repo, baseTip);
  if (baseTree === null || headTree === null || tipTree === null) return null;
  const files = treeToFiles(repo, tipTree);
  for (const c of diffTrees(repo, baseTree, headTree)) {
    if (c.status === 'removed') files.delete(c.path);
    else if (c.newOid !== null) {
      const obj = repo.objects.get(c.newOid);
      files.set(c.path, { oid: c.newOid, mode: obj !== undefined && obj.type === 'blob' ? '100644' : '100644' });
    }
  }
  return filesToTree(repo, files);
}

function peelToCommit(repo: Repo, oid: string): string | null {
  let cur = oid;
  for (let i = 0; i < 10; i += 1) {
    const obj = repo.objects.get(cur);
    if (obj === undefined) return null;
    if (obj.type === 'commit') return cur;
    if (obj.type === 'tag') { cur = parseTag(obj.data).object; continue; }
    return null;
  }
  return null;
}

// -------------------------------------------------------------------------------------------
// HTTP plumbing
// -------------------------------------------------------------------------------------------

let requestCounter = 0;

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': `req-${++requestCounter}`,
    ...extraHeaders,
  });
  res.end(text);
}

function sendRaw(res: ServerResponse, status: number, contentType: string, body: Buffer, extraHeaders: Record<string, string> = {}): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': `req-${++requestCounter}`,
    ...extraHeaders,
  });
  res.end(body);
}

function readBody(req: IncomingMessage, maxBytes = 128 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJsonBody(req: IncomingMessage): Promise<{ ok: true; value: unknown } | { ok: false }> {
  const buf = await readBody(req);
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) as unknown };
  } catch {
    return { ok: false };
  }
}

function isAuthed(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  if (header.startsWith('Bearer ')) {
    if (TOKEN !== '') return header === `Bearer ${TOKEN}`;
    return header.length > 7;
  }
  // Real git clients send Basic (username:password); accept the shop token as the password
  // (or as the username, as GitHub does). The conformance suite sends Bearer, which stays primary.
  if (header.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const idx = decoded.indexOf(':');
      const user = idx < 0 ? decoded : decoded.slice(0, idx);
      const pass = idx < 0 ? '' : decoded.slice(idx + 1);
      if (TOKEN !== '') return pass === TOKEN || user === TOKEN;
      return pass !== '' || user !== '';
    } catch {
      return false;
    }
  }
  return false;
}

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

function baseUrlOf(req: IncomingMessage): string {
  const host = req.headers.host ?? '127.0.0.1';
  return `http://${host}`;
}

function notFound(res: ServerResponse, message = 'Not Found'): void {
  sendJson(res, 404, { message });
}

function badJson(res: ServerResponse): void {
  sendJson(res, 400, { message: 'Problems parsing JSON' });
}

function unauthorized(res: ServerResponse): void {
  sendJson(res, 401, { message: 'Requires authentication' }, { 'www-authenticate': 'Basic realm="makefun-forge"' });
}

// -------------------------------------------------------------------------------------------
// git smart HTTP
// -------------------------------------------------------------------------------------------

function gitRefLines(repo: Repo, withCaps: string | null): Buffer[] {
  // v0 advertisement lines (no preamble, no flush): HEAD first, then refs sorted, peeled after tags.
  const lines: Buffer[] = [];
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? ZERO_OID;
  const caps = withCaps ?? '';
  let first = true;
  const pushLine = (oid: string, name: string, extra = ''): void => {
    let line = `${oid} ${name}${extra}\n`;
    if (first && caps !== '') {
      line = `${oid} ${name}\0${caps}${extra}\n`;
      first = false;
    }
    lines.push(pktLine(line));
  };
  if (refs.length === 0) {
    pushLine(ZERO_OID, 'capabilities^{}');
    return lines;
  }
  pushLine(headTip, 'HEAD');
  for (const [name, oid] of refs) {
    pushLine(oid, name);
    const obj = repo.objects.get(oid);
    if (obj !== undefined && obj.type === 'tag') {
      const peeled = peelToCommit(repo, oid);
      if (peeled !== null) pushLine(peeled, `${name}^{}`);
    }
  }
  return lines;
}

function v2Capabilities(): Buffer[] {
  const lines = [
    'version 2\n',
    `agent=${AGENT_NAME}\n`,
    'ls-refs=unborn\n',
    'fetch=shallow filter\n',
    'object-format=sha1\n',
  ];
  return lines.map((l) => pktLine(l));
}

function handleInfoRefs(req: IncomingMessage, res: ServerResponse, owner: string, name: string, service: string): void {
  const repo = getRepo(owner, name);
  if (repo === undefined) {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const wantsV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
  if (service === 'git-upload-pack' && wantsV2) {
    const body = Buffer.concat([...v2Capabilities(), PKT_FLUSH]);
    sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', body);
    return;
  }
  const preamble = `# service=${service}\n`;
  const caps =
    service === 'git-upload-pack'
      ? `multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done filter agent=${AGENT_NAME} symref=HEAD:refs/heads/${repo.defaultBranch}`
      : `report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=${AGENT_NAME}`;
  const body = Buffer.concat([
    pktLine(preamble),
    PKT_FLUSH,
    ...gitRefLines(repo, caps),
    PKT_FLUSH,
  ]);
  sendRaw(res, 200, `application/x-${service}-advertisement`, body);
}

function lsRefsResponse(repo: Repo, args: { peel: boolean; symrefs: boolean; unborn: boolean; prefixes: string[] }): Buffer {
  const parts: Buffer[] = [];
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const keep = (n: string): boolean => args.prefixes.length === 0 || args.prefixes.some((p) => n.startsWith(p));
  const headLine = (): void => {
    if (!keep('HEAD')) return;
    if (headTip === undefined) {
      if (args.symrefs) parts.push(pktLine(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
      else parts.push(pktLine(`${ZERO_OID} HEAD\n`));
    } else if (args.symrefs) {
      parts.push(pktLine(`${headTip} HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
    } else {
      parts.push(pktLine(`${headTip} HEAD\n`));
    }
  };
  headLine();
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  for (const [refName, oid] of refs) {
    if (!keep(refName)) continue;
    let line = `${oid} ${refName}`;
    const obj = repo.objects.get(oid);
    if (args.peel && obj !== undefined && obj.type === 'tag') {
      const peeled = peelToCommit(repo, oid);
      if (peeled !== null) line += ` peeled:${peeled}`;
    }
    parts.push(pktLine(`${line}\n`));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

interface FetchSelection {
  objects: GitObject[];
  shallow: string[];
  unshallow: string[];
}

/** Objects the client already holds: reachable from `haves`, but the walk stops at shallow
 * boundaries — a boundary commit itself is held (with its tree), its parents are not. This is
 * what makes a deepen fetch deliver the parent instead of an empty pack. */
function heldSet(repo: Repo, haves: string[], shallowBoundaries: string[]): Set<string> {
  const boundary = new Set(shallowBoundaries);
  const seen = new Set<string>();
  const stack = [...haves];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj === undefined) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      stack.push(c.tree);
      if (!boundary.has(oid)) for (const p of c.parents) stack.push(p);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) stack.push(e.oid);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    }
  }
  return seen;
}

function selectFetchObjects(repo: Repo, wants: string[], haves: string[], shallowBoundaries: string[], depth: number | null): FetchSelection {
  const exclude = heldSet(repo, haves, shallowBoundaries);
  // Depth-limited closure of wants.
  const included = new Set<string>();
  const shallow: string[] = [];
  const unshallow: string[] = [];
  if (depth !== null) {
    const gens = new Map<string, number>();
    for (const w of wants) {
      const obj = repo.objects.get(w);
      if (obj === undefined) continue;
      if (obj.type === 'tag') {
        included.add(w);
        const target = parseTag(obj.data).object;
        const g = commitGenerations(repo, target);
        for (const [oid, gen] of g) {
          const cur = gens.get(oid);
          if (cur === undefined || gen < cur) gens.set(oid, gen);
        }
      } else if (obj.type === 'commit') {
        const g = commitGenerations(repo, w);
        for (const [oid, gen] of g) {
          const cur = gens.get(oid);
          if (cur === undefined || gen < cur) gens.set(oid, gen);
        }
      } else {
        included.add(w);
      }
    }
    const keptCommits = new Set<string>();
    for (const [oid, gen] of gens) {
      if (gen < depth) {
        keptCommits.add(oid);
        included.add(oid);
      }
    }
    // New shallow boundary: kept commits with a parent outside the kept set.
    for (const oid of keptCommits) {
      const obj = repo.objects.get(oid);
      if (obj === undefined || obj.type !== 'commit') continue;
      const parents = parseCommit(obj.data).parents;
      if (parents.some((p) => !keptCommits.has(p))) shallow.push(oid);
    }
    // Trees/blobs reachable from kept commits only.
    const treeRoots: string[] = [];
    for (const oid of keptCommits) {
      const obj = repo.objects.get(oid);
      if (obj !== undefined && obj.type === 'commit') treeRoots.push(parseCommit(obj.data).tree);
    }
    for (const o of reachable(repo, treeRoots)) included.add(o);
    // Old boundaries that are now fully included become unshallow.
    for (const b of shallowBoundaries) {
      const obj = repo.objects.get(b);
      if (obj === undefined || obj.type !== 'commit') continue;
      const parents = parseCommit(obj.data).parents;
      if (keptCommits.has(b) && parents.every((p) => keptCommits.has(p))) unshallow.push(b);
    }
  } else {
    for (const o of reachable(repo, wants)) included.add(o);
  }
  const objects: GitObject[] = [];
  for (const oid of included) {
    if (exclude.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj !== undefined) objects.push(obj);
  }
  return { objects, shallow, unshallow };
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 65515;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    const payload = Buffer.concat([Buffer.from([1]), slice]);
    parts.push(pktLine(payload));
  }
  return Buffer.concat(parts);
}

function handleUploadPackV2(req: IncomingMessage, res: ServerResponse, repo: Repo, body: Buffer): void {
  const { packets } = decodePktLines(body);
  const lines = pktLinesText(packets);
  const command = lines[0] ?? '';
  if (command.trim() === 'command=ls-refs') {
    const args = { peel: false, symrefs: false, unborn: false, prefixes: [] as string[] };
    for (const line of lines.slice(1)) {
      const t = line.trim();
      if (t === 'peel') args.peel = true;
      else if (t === 'symrefs') args.symrefs = true;
      else if (t === 'unborn') args.unborn = true;
      else if (t.startsWith('ref-prefix ')) args.prefixes.push(t.slice('ref-prefix '.length));
    }
    sendRaw(res, 200, 'application/x-git-upload-pack-result', lsRefsResponse(repo, args));
    return;
  }
  if (command.trim() !== 'command=fetch') {
    sendJson(res, 400, { message: 'unknown command' });
    return;
  }
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | null = null;
  let done = false;
  for (const line of lines.slice(1)) {
    const t = line.trim();
    if (t.startsWith('want ')) wants.push(t.slice(5).trim());
    else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
    else if (t.startsWith('shallow ')) shallow.push(t.slice(8).trim());
    else if (t.startsWith('deepen ')) { const n = Number(t.slice(7).trim()); if (Number.isFinite(n)) depth = n; }
    else if (t === 'done') done = true;
  }
  // Real git (unlike the kit client) sends `done` in the first request when it has no more
  // haves, and then skips the acknowledgments section entirely: it goes straight to the
  // packfile section and dies with "expected 'packfile', received 'acknowledgments'" if the
  // server sends one (protocol-v2: the acks section MUST be omitted once the client sends
  // done). A request without `done` is a negotiation round: answer acks + flush, no packfile.
  // Never append a 0002 response-end packet: over HTTP, remote-curl validates every v2
  // response with check_pktline, which dies on any 0002 ("unexpected response end packet"),
  // and remote-curl appends the 0002 to the stream itself before handing it to fetch-pack.
  const sel = selectFetchObjects(repo, wants, haves, shallow, depth);
  const pack = writePack(sel.objects);
  const parts: Buffer[] = [];
  if (!done) {
    parts.push(pktLine('acknowledgments\n'));
    parts.push(pktLine('NAK\n'));
    parts.push(PKT_FLUSH);
    sendRaw(res, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
    return;
  }
  if (depth !== null || shallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of sel.shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const u of sel.unshallow) parts.push(pktLine(`unshallow ${u}\n`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine('packfile\n'));
  parts.push(sidebandPack(pack));
  parts.push(PKT_FLUSH);
  sendRaw(res, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

function handleUploadPackV0(req: IncomingMessage, res: ServerResponse, repo: Repo, body: Buffer): void {
  const { packets } = decodePktLines(body);
  const lines = pktLinesText(packets);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | null = null;
  let sawWant = false;
  for (const line of lines) {
    const t = line.trim();
    if (t.startsWith('want ')) { wants.push(t.slice(5).split(' ')[0] ?? ''); sawWant = true; }
    else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
    else if (t.startsWith('shallow ')) shallow.push(t.slice(8).trim());
    else if (t.startsWith('deepen ')) { const n = Number(t.slice(7).trim()); if (Number.isFinite(n)) depth = n; }
  }
  if (!sawWant) {
    sendJson(res, 400, { message: 'no want lines' });
    return;
  }
  const sel = selectFetchObjects(repo, wants, haves, shallow, depth);
  const pack = writePack(sel.objects);
  const parts: Buffer[] = [pktLine('NAK\n')];
  for (const s of sel.shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const u of sel.unshallow) parts.push(pktLine(`unshallow ${u}\n`));
  parts.push(sidebandPack(pack));
  parts.push(PKT_FLUSH);
  sendRaw(res, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

function handleReceivePack(req: IncomingMessage, res: ServerResponse, repo: Repo, body: Buffer): void {
  const { packets, restOffset } = decodePktLines(body);
  const lines = pktLinesText(packets);
  if (lines.length === 0) {
    sendJson(res, 400, { message: 'empty receive-pack request' });
    return;
  }
  interface Cmd { oldOid: string; newOid: string; ref: string }
  const commands: Cmd[] = [];
  for (const line of lines) {
    const t = line.replace(/\n$/, '');
    const nul = t.indexOf('\0');
    const clean = nul >= 0 ? t.slice(0, nul) : t;
    const parts = clean.split(' ');
    if (parts.length < 3 || !isOid(parts[0] ?? '') || !isOid(parts[1] ?? '')) {
      sendJson(res, 400, { message: 'malformed receive-pack command' });
      return;
    }
    commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts[2] as string });
  }
  // The pack follows the command flush.
  const packBytes = body.subarray(restOffset);
  let unpackOk = true;
  if (packBytes.length > 0) {
    try {
      for (const obj of readPack(packBytes, (oid) => repo.objects.get(oid))) {
        const oid = hashObject(obj.type, obj.data);
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch {
      unpackOk = false;
    }
  }
  const report: string[] = [];
  report.push(unpackOk ? 'unpack ok\n' : 'unpack error\n');
  if (unpackOk) {
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.newOid === ZERO_OID) {
        // delete
        if (current === undefined) report.push(`ng ${cmd.ref} remote ref does not exist\n`);
        else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) report.push(`ng ${cmd.ref} non-fast-forward\n`);
        else { repo.refs.delete(cmd.ref); report.push(`ok ${cmd.ref}\n`); }
        continue;
      }
      const newObj = repo.objects.get(cmd.newOid);
      if (newObj === undefined) { report.push(`ng ${cmd.ref} missing object\n`); continue; }
      if (current === undefined) {
        if (cmd.oldOid !== ZERO_OID) { report.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
        repo.refs.set(cmd.ref, cmd.newOid);
        report.push(`ok ${cmd.ref}\n`);
        continue;
      }
      if (cmd.oldOid !== current) { report.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
      if (cmd.newOid === current) { report.push(`ok ${cmd.ref}\n`); continue; }
      const isBranch = cmd.ref.startsWith('refs/heads/');
      if (isBranch && newObj.type === 'commit' && !isAncestor(repo, current, cmd.newOid)) {
        report.push(`ng ${cmd.ref} non-fast-forward\n`);
        continue;
      }
      repo.refs.set(cmd.ref, cmd.newOid);
      report.push(`ok ${cmd.ref}\n`);
    }
  } else {
    for (const cmd of commands) report.push(`ng ${cmd.ref} unpack failed\n`);
  }
  // Report inside sideband band 1, pkt-lined, ending with a flush inside band 1.
  const inner = Buffer.concat([...report.map((r) => pktLine(r)), PKT_FLUSH]);
  const outer = Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), inner])), PKT_FLUSH]);
  sendRaw(res, 200, 'application/x-git-receive-pack-result', outer);
}

// -------------------------------------------------------------------------------------------
// REST v3 serializers
// -------------------------------------------------------------------------------------------

function userJson(): Record<string, unknown> {
  return {
    login: VIEWER_LOGIN,
    id: VIEWER_ID,
    node_id: globalId('U', [VIEWER_ID]),
    avatar_url: `https://avatars.githubusercontent.com/u/${VIEWER_ID}?v=4`,
    html_url: `https://github.com/${VIEWER_LOGIN}`,
    type: 'User',
    site_admin: false,
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
  };
}

function repoJson(repo: Repo): Record<string, unknown> {
  const openIssues = [...repo.issues.values()].filter((i) => i.state === 'open').length;
  return {
    id: repo.dbId,
    node_id: globalId('R', [repo.dbId]),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(),
    private: repo.isPrivate,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: isoOf(repo.seq),
    updated_at: isoOf(repo.seq),
    pushed_at: isoOf(repo.seq),
    default_branch: repo.defaultBranch,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    has_pages: false,
    has_downloads: true,
    archived: false,
    disabled: false,
    visibility: repo.isPrivate ? 'private' : 'public',
    forks: 0,
    open_issues: openIssues,
    watchers: 0,
    size: 0,
    license: null,
    topics: [],
  };
}

function labelJson(label: Label): Record<string, unknown> {
  return { name: label.name, color: label.color, description: label.description, default: false };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: globalId('I', [repo.dbId, issue.number]),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((n) => labelJson(repo.labels.get(n) ?? { name: n, color: 'ededed', description: '' })),
    user: userJson(),
    assignee: null,
    assignees: [],
    milestone: null,
    comments: issue.comments.length,
    created_at: isoOf(issue.seq),
    updated_at: isoOf(issue.seq),
    closed_at: issue.state === 'closed' && issue.closedSeq !== null ? isoOf(issue.closedSeq) : null,
    author_association: 'OWNER',
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    labels_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/labels`,
    comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments`,
    events_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/events`,
  };
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  const headUser = userJson();
  const refObj = (ref: string, sha: string): Record<string, unknown> => ({
    ref,
    sha,
    label: `${VIEWER_LOGIN}:${ref}`,
    user: headUser,
    repo: repoJson(repo),
  });
  return {
    id: pull.id,
    node_id: globalId('P', [repo.dbId, pull.number]),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    head: refObj(pull.headRef, pull.headSha),
    base: refObj(pull.baseRef, pull.baseSha),
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    draft: false,
    user: userJson(),
    created_at: isoOf(pull.seq),
    updated_at: isoOf(pull.seq),
    closed_at: pull.state === 'closed' ? isoOf(pull.seq) : null,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

function commentJson(repo: Repo, issue: Issue, comment: IssueComment): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: globalId('C', [repo.dbId, issue.number, comment.id]),
    body: comment.body,
    user: userJson(),
    created_at: isoOf(comment.seq),
    updated_at: isoOf(comment.seq),
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments/${comment.id}`,
  };
}

function paginate<T>(req: IncomingMessage, items: T[]): { page: T[]; link: string | null } {
  const q = queryOf(req);
  const perPageRaw = Number(q.get('per_page') ?? '30');
  const perPage = Number.isFinite(perPageRaw) ? Math.min(100, Math.max(1, Math.trunc(perPageRaw))) : 30;
  const pageRaw = Number(q.get('page') ?? '1');
  const page = Number.isFinite(pageRaw) ? Math.max(1, Math.trunc(pageRaw)) : 1;
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | null = null;
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  if (page < totalPages) {
    const base = baseUrlOf(req);
    const path = pathOf(req);
    const other = new URLSearchParams();
    for (const [k, v] of q) if (k !== 'page' && k !== 'per_page') other.set(k, v);
    const qs = (p: number): string => {
      const params = new URLSearchParams(other);
      params.set('page', String(p));
      params.set('per_page', String(perPage));
      return params.toString();
    };
    link = `<${base}${path}?${qs(page + 1)}>; rel="next", <${base}${path}?${qs(totalPages)}>; rel="last"`;
  }
  return { page: slice, link };
}

function sendPage<T>(req: IncomingMessage, res: ServerResponse, items: T[]): void {
  const { page, link } = paginate(req, items);
  sendJson(res, 200, page, link === null ? {} : { link });
}

// -------------------------------------------------------------------------------------------
// REST v3 handlers
// -------------------------------------------------------------------------------------------

function resolveRef(repo: Repo, ref: string | null): string | null {
  if (ref === null || ref === '') return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? null;
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`) as string;
  if (repo.refs.has(`refs/tags/${ref}`)) return repo.refs.get(`refs/tags/${ref}`) as string;
  if (repo.refs.has(ref)) return repo.refs.get(ref) as string;
  if (isOid(ref) && repo.objects.has(ref)) return ref;
  return null;
}

function commitList(repo: Repo, tip: string): Array<{ sha: string; info: CommitInfo }> {
  const out: Array<{ sha: string; info: CommitInfo }> = [];
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    const info = parseCommit(obj.data);
    out.push({ sha: oid, info });
    for (const p of info.parents) queue.push(p);
  }
  return out;
}

async function handleContentsPut(req: IncomingMessage, res: ServerResponse, repo: Repo, filePath: string): Promise<void> {
  const parsed = await readJsonBody(req);
  if (!parsed.ok) { badJson(res); return; }
  const body = (parsed.value ?? {}) as Record<string, unknown>;
  const message = typeof body.message === 'string' ? body.message : `Update ${filePath}`;
  const contentB64 = typeof body.content === 'string' ? body.content : null;
  if (contentB64 === null) { sendJson(res, 422, { message: 'content is required' }); return; }
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  const tip = repo.refs.get(`refs/heads/${branch}`);
  if (tip === undefined && repo.refs.size > 0) { notFound(res, 'Branch not found'); return; }
  const files = tip === undefined ? new Map<string, { oid: string; mode: string }>() : treeToFiles(repo, commitTreeOid(repo, tip) ?? '');
  const existing = files.get(filePath);
  if (existing !== undefined && typeof body.sha === 'string' && body.sha !== existing.oid) {
    sendJson(res, 409, { message: 'sha does not match the current blob' });
    return;
  }
  const bytes = b64decode(contentB64);
  const blobOid = storeObject(repo, 'blob', bytes);
  files.set(filePath, { oid: blobOid, mode: '100644' });
  const treeOid = filesToTree(repo, files);
  const parents = tip === undefined ? [] : [tip];
  const commitSha = makeCommit(repo, treeOid, parents, message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  const status = existing === undefined ? 201 : 200;
  sendJson(res, status, {
    content: {
      name: filePath.split('/').pop() ?? filePath,
      path: filePath,
      sha: blobOid,
      size: bytes.length,
      type: 'file',
      encoding: 'base64',
      content: b64encode(bytes),
    },
    commit: { sha: commitSha, message },
  });
}

function handleContentsGet(req: IncomingMessage, res: ServerResponse, repo: Repo, filePath: string): void {
  const q = queryOf(req);
  const tip = resolveRef(repo, q.get('ref'));
  if (tip === null) { notFound(res); return; }
  const commitOid = peelToCommit(repo, tip);
  if (commitOid === null) { notFound(res); return; }
  const treeOid = commitTreeOid(repo, commitOid);
  if (treeOid === null) { notFound(res); return; }
  const files = treeToFiles(repo, treeOid);
  if (filePath === '') {
    const entries: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    for (const path of [...files.keys()].sort()) {
      const top = path.split('/')[0] as string;
      if (seen.has(top)) continue;
      seen.add(top);
      if (path.includes('/')) {
        // directory: find its tree oid by walking
        entries.push({ type: 'dir', name: top, path: top, sha: dirTreeOid(repo, treeOid, top) });
      } else {
        const f = files.get(path) as { oid: string; mode: string };
        entries.push({ type: 'file', name: top, path: top, sha: f.oid, size: blobSize(repo, f.oid) });
      }
    }
    sendJson(res, 200, entries);
    return;
  }
  const file = files.get(filePath);
  if (file !== undefined) {
    const obj = repo.objects.get(file.oid);
    const bytes = obj === undefined ? Buffer.alloc(0) : obj.data;
    sendJson(res, 200, {
      type: 'file',
      encoding: 'base64',
      size: bytes.length,
      name: filePath.split('/').pop() ?? filePath,
      path: filePath,
      sha: file.oid,
      content: b64encode(bytes),
      url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}`,
      html_url: `https://github.com/${repo.owner}/${repo.name}/blob/${repo.defaultBranch}/${filePath}`,
      git_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/blobs/${file.oid}`,
      download_url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}`,
    });
    return;
  }
  // Directory?
  const prefix = `${filePath}/`;
  const children = [...files.keys()].filter((p) => p.startsWith(prefix));
  if (children.length === 0) { notFound(res); return; }
  const entries: Record<string, unknown>[] = [];
  const seen = new Set<string>();
  for (const path of children.sort()) {
    const rest = path.slice(prefix.length);
    const top = rest.split('/')[0] as string;
    if (seen.has(top)) continue;
    seen.add(top);
    const full = `${filePath}/${top}`;
    if (rest.includes('/')) entries.push({ type: 'dir', name: top, path: full, sha: dirTreeOid(repo, treeOid, full) });
    else {
      const f = files.get(path) as { oid: string; mode: string };
      entries.push({ type: 'file', name: top, path: full, sha: f.oid, size: blobSize(repo, f.oid) });
    }
  }
  sendJson(res, 200, entries);
}

function dirTreeOid(repo: Repo, treeOid: string, dirPath: string): string {
  let cur = treeOid;
  for (const part of dirPath.split('/')) {
    const obj = repo.objects.get(cur);
    if (obj === undefined || obj.type !== 'tree') return ZERO_OID;
    const entry = parseTree(obj.data).find((e) => e.name === part && e.mode === '40000');
    if (entry === undefined) return ZERO_OID;
    cur = entry.oid;
  }
  return cur;
}

function blobSize(repo: Repo, oid: string): number {
  const obj = repo.objects.get(oid);
  return obj === undefined ? 0 : obj.data.length;
}

async function handleContentsDelete(req: IncomingMessage, res: ServerResponse, repo: Repo, filePath: string): Promise<void> {
  const parsed = await readJsonBody(req);
  if (!parsed.ok) { badJson(res); return; }
  const body = (parsed.value ?? {}) as Record<string, unknown>;
  const message = typeof body.message === 'string' ? body.message : `Delete ${filePath}`;
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  const tip = repo.refs.get(`refs/heads/${branch}`);
  if (tip === undefined) { notFound(res); return; }
  const treeOid = commitTreeOid(repo, tip);
  if (treeOid === null) { notFound(res); return; }
  const files = treeToFiles(repo, treeOid);
  const existing = files.get(filePath);
  if (existing === undefined) { notFound(res); return; }
  if (typeof body.sha === 'string' && body.sha !== existing.oid) {
    sendJson(res, 409, { message: 'sha does not match the current blob' });
    return;
  }
  files.delete(filePath);
  const newTree = filesToTree(repo, files);
  const commitSha = makeCommit(repo, newTree, [tip], message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  sendJson(res, 200, { commit: { sha: commitSha, message } });
}

// -------------------------------------------------------------------------------------------
// GraphQL v4 — small recursive-descent parser + executor (no external deps)
// -------------------------------------------------------------------------------------------

interface GqlValue {
  kind: 'string' | 'int' | 'float' | 'bool' | 'null' | 'enum' | 'var' | 'list' | 'object';
  value: unknown;
}

interface GqlField {
  name: string;
  alias: string | null;
  args: Record<string, GqlValue>;
  selection: GqlSelection[] | null;
}

type GqlSelection =
  | { kind: 'field'; field: GqlField }
  | { kind: 'fragment'; typeCondition: string | null; selection: GqlSelection[] };

interface GqlOperation {
  type: 'query' | 'mutation';
  name: string | null;
  selection: GqlSelection[];
}

interface GqlToken {
  kind: 'punct' | 'name' | 'string' | 'int' | 'float' | 'var' | 'ellipsis';
  value: string;
}

function gqlTokenize(src: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') { i += 1; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if (c === '.' && src.slice(i, i + 3) === '...') { tokens.push({ kind: 'ellipsis', value: '...' }); i += 3; continue; }
    if ('{}():=![]@'.includes(c)) { tokens.push({ kind: 'punct', value: c }); i += 1; continue; }
    if (c === '$') {
      const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i + 1));
      if (m === null) throw new Error('bad variable');
      tokens.push({ kind: 'var', value: m[0] });
      i += 1 + m[0].length;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const e = src[j + 1];
          out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e;
          j += 2;
        } else { out += src[j]; j += 1; }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      const m = /^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(src.slice(i));
      if (m === null) throw new Error('bad number');
      tokens.push({ kind: m[1] !== undefined || m[2] !== undefined ? 'float' : 'int', value: m[0] });
      i += m[0].length;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i));
      if (m === null) throw new Error('bad name');
      tokens.push({ kind: 'name', value: m[0] });
      i += m[0].length;
      continue;
    }
    throw new Error(`unexpected character ${c}`);
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: GqlToken[];
  constructor(tokens: GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken | undefined {
    return this.tokens[this.pos];
  }

  private next(): GqlToken {
    const t = this.tokens[this.pos];
    this.pos += 1;
    if (t === undefined) throw new Error('unexpected end of document');
    return t;
  }

  private expectPunct(value: string): void {
    const t = this.next();
    if (t.kind !== 'punct' || t.value !== value) throw new Error(`expected ${value}, got ${t.value}`);
  }

  private eatPunct(value: string): boolean {
    const t = this.peek();
    if (t !== undefined && t.kind === 'punct' && t.value === value) { this.pos += 1; return true; }
    return false;
  }

  parseDocument(): GqlOperation[] {
    const ops: GqlOperation[] = [];
    while (this.pos < this.tokens.length) ops.push(this.parseOperation());
    return ops;
  }

  private parseOperation(): GqlOperation {
    let type: 'query' | 'mutation' = 'query';
    let name: string | null = null;
    const t = this.peek();
    if (t !== undefined && t.kind === 'name' && (t.value === 'query' || t.value === 'mutation')) {
      type = t.value as 'query' | 'mutation';
      this.pos += 1;
      const n = this.peek();
      if (n !== undefined && n.kind === 'name') { name = n.value; this.pos += 1; }
    }
    // variable definitions: ( $x: Type = default, ... ) — parse and discard.
    if (this.eatPunct('(')) {
      while (!this.eatPunct(')')) {
        const v = this.next();
        if (v.kind !== 'var') throw new Error('expected variable in definition');
        this.expectPunct(':');
        this.parseTypeRef();
        if (this.eatPunct('=')) this.parseValue();
      }
    }
    const selection = this.parseSelectionSet();
    return { type, name, selection };
  }

  private parseTypeRef(): void {
    if (this.eatPunct('[')) {
      this.parseTypeRef();
      this.expectPunct(']');
    } else {
      const t = this.next();
      if (t.kind !== 'name') throw new Error('expected type name');
    }
    this.eatPunct('!');
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const out: GqlSelection[] = [];
    while (!this.eatPunct('}')) {
      const t = this.peek();
      if (t === undefined) throw new Error('unterminated selection set');
      if (t.kind === 'ellipsis') {
        this.pos += 1;
        let typeCondition: string | null = null;
        const on = this.peek();
        if (on !== undefined && on.kind === 'name' && on.value === 'on') {
          this.pos += 1;
          const tc = this.next();
          if (tc.kind !== 'name') throw new Error('expected type condition');
          typeCondition = tc.value;
        }
        const selection = this.parseSelectionSet();
        out.push({ kind: 'fragment', typeCondition, selection });
        continue;
      }
      out.push({ kind: 'field', field: this.parseField() });
    }
    return out;
  }

  private parseField(): GqlField {
    const first = this.next();
    if (first.kind !== 'name') throw new Error('expected field name');
    let name = first.value;
    let alias: string | null = null;
    if (this.eatPunct(':')) {
      alias = name;
      const real = this.next();
      if (real.kind !== 'name') throw new Error('expected field name after alias');
      name = real.value;
    }
    const args: Record<string, GqlValue> = {};
    if (this.eatPunct('(')) {
      while (!this.eatPunct(')')) {
        const argName = this.next();
        if (argName.kind !== 'name') throw new Error('expected argument name');
        this.expectPunct(':');
        args[argName.value] = this.parseValue();
      }
    }
    // directives (@...) — skip.
    while (this.peek()?.kind === 'punct' && this.peek()?.value === '@') {
      this.pos += 1;
      const d = this.next();
      if (d.kind !== 'name') throw new Error('expected directive name');
      if (this.eatPunct('(')) {
        while (!this.eatPunct(')')) {
          const argName = this.next();
          if (argName.kind !== 'name') throw new Error('expected directive argument');
          this.expectPunct(':');
          this.parseValue();
        }
      }
    }
    let selection: GqlSelection[] | null = null;
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '{') selection = this.parseSelectionSet();
    return { name, alias, args, selection };
  }

  private parseValue(): GqlValue {
    const t = this.next();
    if (t.kind === 'string') return { kind: 'string', value: t.value };
    if (t.kind === 'int') return { kind: 'int', value: Number(t.value) };
    if (t.kind === 'float') return { kind: 'float', value: Number(t.value) };
    if (t.kind === 'var') return { kind: 'var', value: t.value };
    if (t.kind === 'punct' && t.value === '[') {
      const items: GqlValue[] = [];
      while (!(this.peek()?.kind === 'punct' && this.peek()?.value === ']')) items.push(this.parseValue());
      this.pos += 1;
      return { kind: 'list', value: items };
    }
    if (t.kind === 'punct' && t.value === '{') {
      const obj: Record<string, GqlValue> = {};
      while (!(this.peek()?.kind === 'punct' && this.peek()?.value === '}')) {
        const k = this.next();
        if (k.kind !== 'name') throw new Error('expected object key');
        this.expectPunct(':');
        obj[k.value] = this.parseValue();
      }
      this.pos += 1;
      return { kind: 'object', value: obj };
    }
    if (t.kind === 'name') {
      if (t.value === 'true') return { kind: 'bool', value: true };
      if (t.value === 'false') return { kind: 'bool', value: false };
      if (t.value === 'null') return { kind: 'null', value: null };
      return { kind: 'enum', value: t.value };
    }
    throw new Error(`unexpected value token ${t.value}`);
  }
}

function gqlResolveValue(v: GqlValue, variables: Record<string, unknown>): unknown {
  switch (v.kind) {
    case 'var': return variables[v.value as string] ?? null;
    case 'list': return (v.value as GqlValue[]).map((x) => gqlResolveValue(x, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v.value as Record<string, GqlValue>)) out[k] = gqlResolveValue(val, variables);
      return out;
    }
    default: return v.value;
  }
}

function gqlArgs(field: GqlField, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(field.args)) out[k] = gqlResolveValue(v, variables);
  return out;
}

// -------------------------------------------------------------------------------------------
// GraphQL schema (fields the suite may ask for) and type info for introspection
// -------------------------------------------------------------------------------------------

const GQL_SCHEMA: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__schema', '__type'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  User: ['login', 'id', 'name', 'email', 'avatarUrl', 'url', 'databaseId'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt', 'updatedAt', 'visibility', 'isPrivate'],
  Issue: ['id', 'number', 'title', 'body', 'state', 'createdAt', 'updatedAt', 'author', 'labels', 'comments', 'url', 'repository'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  IssueEdge: ['node', 'cursor'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'mergeable', 'merged', 'files', 'createdAt', 'updatedAt', 'author', 'url', 'repository'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestEdge: ['node', 'cursor'],
  PullRequestFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changes', 'status'],
  Ref: ['name', 'target', 'prefix'],
  Commit: ['oid', 'message'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  __Type: ['name', 'kind', 'fields', 'enumValues', 'description'],
  __Field: ['name', 'description', 'args', 'type'],
  __EnumValue: ['name', 'description'],
  __InputValue: ['name', 'description'],
  __Schema: ['queryType', 'mutationType', 'types'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  IssueComment: ['id', 'body', 'author', 'createdAt', 'updatedAt'],
  IssueCommentEdge: ['node', 'cursor'],
  Label: ['name', 'color', 'description', 'id'],
  LabelConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  LabelEdge: ['node', 'cursor'],
};

const GQL_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'MILESTONE', 'PROJECT'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  MergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
};

type GqlObj =
  | { __typename: 'User' }
  | { __typename: 'Repository'; repo: Repo }
  | { __typename: 'Issue'; repo: Repo; issue: Issue }
  | { __typename: 'PullRequest'; repo: Repo; pull: Pull }
  | { __typename: 'IssueComment'; repo: Repo; issue: Issue; comment: IssueComment }
  | { __typename: 'Label'; label: Label }
  | { __typename: 'Ref'; name: string; targetOid: string | null }
  | { __typename: 'Commit'; oid: string; message: string }
  | { __typename: 'IssueConnection'; nodes: GqlObj[]; edges: GqlObj[]; pageInfo: Record<string, unknown>; totalCount: number }
  | { __typename: 'PullRequestConnection'; nodes: GqlObj[]; edges: GqlObj[]; pageInfo: Record<string, unknown>; totalCount: number }
  | { __typename: 'PullRequestFileConnection'; nodes: GqlObj[]; edges: GqlObj[]; pageInfo: Record<string, unknown>; totalCount: number }
  | { __typename: 'LabelConnection'; nodes: GqlObj[]; edges: GqlObj[]; pageInfo: Record<string, unknown>; totalCount: number }
  | { __typename: 'IssueCommentConnection'; nodes: GqlObj[]; edges: GqlObj[]; pageInfo: Record<string, unknown>; totalCount: number }
  | { __typename: 'IssueEdge'; node: GqlObj; cursor: string }
  | { __typename: 'PullRequestEdge'; node: GqlObj; cursor: string }
  | { __typename: 'PullRequestFileEdge'; node: GqlObj; cursor: string }
  | { __typename: 'LabelEdge'; node: GqlObj; cursor: string }
  | { __typename: 'IssueCommentEdge'; node: GqlObj; cursor: string }
  | { __typename: 'PageInfo'; info: Record<string, unknown> }
  | { __typename: '__Type'; name: string }
  | { __typename: '__Field'; name: string }
  | { __typename: '__EnumValue'; name: string }
  | { __typename: '__Schema' }
  | { __typename: 'CreateIssuePayload'; issue: GqlObj | null }
  | { __typename: 'CloseIssuePayload'; issue: GqlObj | null }
  | { __typename: 'CreatePullRequestPayload'; pullRequest: GqlObj | null }
  | { __typename: 'MergePullRequestPayload'; pullRequest: GqlObj | null }
  | { __typename: 'AddCommentPayload'; commentEdge: GqlObj | null }
  | { __typename: 'PullRequestChangedFile'; path: string; additions: number; deletions: number; status: string }
  | { __typename: 'Query' }
  | { __typename: 'Mutation' };

function gqlCursor(n: number): string {
  return Buffer.from(`cursor:${n}`).toString('base64');
}

function gqlCursorToNumber(cursor: string): number | null {
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const m = /^cursor:(\d+)$/.exec(text);
    return m === null ? null : Number(m[1]);
  } catch {
    return null;
  }
}

interface ConnOpts { first?: number; after?: string | null }

function gqlConnection<T>(items: T[], opts: ConnOpts, toNode: (item: T) => GqlObj, keyOf: (item: T) => number, typename: string): GqlObj {
  let start = 0;
  if (opts.after !== undefined && opts.after !== null) {
    const num = gqlCursorToNumber(opts.after);
    if (num !== null) {
      const idx = items.findIndex((it) => keyOf(it) === num);
      if (idx >= 0) start = idx + 1;
    }
  }
  const first = opts.first ?? items.length;
  const slice = items.slice(start, start + first);
  const nodes = slice.map(toNode);
  const pageInfo: Record<string, unknown> = {
    hasNextPage: start + slice.length < items.length,
    hasPreviousPage: start > 0,
    startCursor: slice.length > 0 ? gqlCursor(keyOf(slice[0] as T)) : null,
    endCursor: slice.length > 0 ? gqlCursor(keyOf(slice[slice.length - 1] as T)) : null,
  };
  const edges = slice.map((it) => {
    const node = toNode(it);
    const cursor = gqlCursor(keyOf(it));
    if (typename === 'IssueConnection') return { __typename: 'IssueEdge', node, cursor } as GqlObj;
    if (typename === 'PullRequestConnection') return { __typename: 'PullRequestEdge', node, cursor } as GqlObj;
    if (typename === 'PullRequestFileConnection') return { __typename: 'PullRequestFileEdge', node, cursor } as GqlObj;
    if (typename === 'LabelConnection') return { __typename: 'LabelEdge', node, cursor } as GqlObj;
    return { __typename: 'IssueCommentEdge', node, cursor } as GqlObj;
  });
  const base = { nodes, edges, pageInfo, totalCount: items.length };
  if (typename === 'IssueConnection') return { __typename: 'IssueConnection', ...base } as GqlObj;
  if (typename === 'PullRequestConnection') return { __typename: 'PullRequestConnection', ...base } as GqlObj;
  if (typename === 'PullRequestFileConnection') return { __typename: 'PullRequestFileConnection', ...base } as GqlObj;
  if (typename === 'LabelConnection') return { __typename: 'LabelConnection', ...base } as GqlObj;
  return { __typename: 'IssueCommentConnection', ...base } as GqlObj;
}

// -------------------------------------------------------------------------------------------
// GraphQL execution
// -------------------------------------------------------------------------------------------

class GqlError extends Error {}

function gqlIssueObj(repo: Repo, issue: Issue): GqlObj {
  return { __typename: 'Issue', repo, issue };
}

function gqlPullObj(repo: Repo, pull: Pull): GqlObj {
  return { __typename: 'PullRequest', repo, pull };
}

function gqlRepoObj(repo: Repo): GqlObj {
  return { __typename: 'Repository', repo };
}

function gqlCreateIssue(repo: Repo, title: string, body: string, labels: string[] = []): Issue {
  const issue: Issue = {
    id: nextGlobalId,
    number: repo.nextIssue,
    title,
    body,
    state: 'open',
    labels: [...labels],
    seq: repo.nextIssue,
    comments: [],
    closedSeq: null,
  };
  nextGlobalId += 1;
  repo.nextIssue += 1;
  repo.issues.set(issue.number, issue);
  return issue;
}

function gqlCreatePull(repo: Repo, title: string, body: string, headRef: string, baseRef: string): Pull | null {
  const headTip = repo.refs.get(`refs/heads/${headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${baseRef}`);
  if (headTip === undefined || baseTip === undefined) return null;
  const pull: Pull = {
    id: nextGlobalId,
    number: repo.nextPull,
    title,
    body,
    state: 'open',
    headRef,
    baseRef,
    headSha: headTip,
    baseSha: baseTip,
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    seq: repo.nextPull,
  };
  nextGlobalId += 1;
  repo.nextPull += 1;
  repo.pulls.set(pull.number, pull);
  return pull;
}

function gqlMergePull(repo: Repo, pull: Pull): boolean {
  if (pull.state !== 'open') return false;
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (headTip === undefined || baseTip === undefined) return false;
  if (mergeConflict(repo, headTip, baseTip)) return false;
  const tree = squashMergeTree(repo, headTip, baseTip);
  if (tree === null) return false;
  const sha = makeCommit(repo, tree, [baseTip], `Merge pull request #${pull.number} from ${VIEWER_LOGIN}/${pull.headRef}\n\n${pull.title}`);
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  pull.merged = true;
  pull.state = 'closed';
  pull.mergedAt = isoOf(pull.seq + 100000);
  pull.mergeCommitSha = sha;
  return true;
}

function gqlMergeable(repo: Repo, pull: Pull): string {
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  if (headTip === undefined || baseTip === undefined) return 'UNKNOWN';
  if (pull.merged) return 'MERGEABLE';
  return mergeConflict(repo, headTip, baseTip) ? 'CONFLICTING' : 'MERGEABLE';
}

function gqlPrState(pull: Pull): string {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function gqlPullFiles(repo: Repo, pull: Pull): Array<{ path: string; additions: number; deletions: number; status: string }> {
  const changes = diffTrees(repo, commitTreeOid(repo, pull.baseSha), commitTreeOid(repo, pull.headSha));
  return changes
    .filter((c) => c.status !== 'removed')
    .map((c) => ({
      path: c.path,
      additions: lineCount(repo, c.newOid),
      deletions: lineCount(repo, c.oldOid),
      status: c.status === 'added' ? 'added' : 'modified',
    }));
}

function gqlResolveField(source: GqlObj, field: GqlField, variables: Record<string, unknown>): unknown {
  const typeName = source.__typename;
  const args = gqlArgs(field, variables);
  switch (typeName) {
    case 'Query': {
      if (field.name === 'viewer') return { __typename: 'User' } as GqlObj;
      if (field.name === 'repository') {
        const repo = getRepo(String(args.owner ?? ''), String(args.name ?? ''));
        return repo === undefined ? null : gqlRepoObj(repo);
      }
      if (field.name === 'node') {
        const decoded = decodeGlobalId(String(args.id ?? ''));
        if (decoded === null) return null;
        if (decoded.kind === 'R') {
          const repo = repoList.find((r) => r.dbId === Number(decoded.parts[0]));
          return repo === undefined ? null : gqlRepoObj(repo);
        }
        if (decoded.kind === 'I') {
          const repo = repoList.find((r) => r.dbId === Number(decoded.parts[0]));
          const issue = repo?.issues.get(Number(decoded.parts[1]));
          return issue === undefined || repo === undefined ? null : gqlIssueObj(repo, issue);
        }
        if (decoded.kind === 'P') {
          const repo = repoList.find((r) => r.dbId === Number(decoded.parts[0]));
          const pull = repo?.pulls.get(Number(decoded.parts[1]));
          return pull === undefined || repo === undefined ? null : gqlPullObj(repo, pull);
        }
        if (decoded.kind === 'U') return { __typename: 'User' } as GqlObj;
        return null;
      }
      if (field.name === '__type') return { __typename: '__Type', name: String(args.name ?? '') } as GqlObj;
      if (field.name === '__schema') return { __typename: '__Schema' } as GqlObj;
      break;
    }
    case 'Mutation': {
      if (field.name === 'createIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
        if (decoded === null || decoded.kind !== 'R') return { __typename: 'CreateIssuePayload', issue: null } as GqlObj;
        const repo = repoList.find((r) => r.dbId === Number(decoded.parts[0]));
        if (repo === undefined) return { __typename: 'CreateIssuePayload', issue: null } as GqlObj;
        const issue = gqlCreateIssue(repo, String(input.title ?? ''), typeof input.body === 'string' ? input.body : '');
        return { __typename: 'CreateIssuePayload', issue: gqlIssueObj(repo, issue) } as GqlObj;
      }
      if (field.name === 'closeIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(String(input.issueId ?? ''));
        if (decoded === null || decoded.kind !== 'I') return { __typename: 'CloseIssuePayload', issue: null } as GqlObj;
        const repo = repoList.find((r) => r.dbId === Number(decoded.parts[0]));
        const issue = repo?.issues.get(Number(decoded.parts[1]));
        if (issue === undefined || repo === undefined) return { __typename: 'CloseIssuePayload', issue: null } as GqlObj;
        issue.state = 'closed';
        issue.closedSeq = issue.seq;
        return { __typename: 'CloseIssuePayload', issue: gqlIssueObj(repo, issue) } as GqlObj;
      }
      if (field.name === 'createPullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
        if (decoded === null || decoded.kind !== 'R') return { __typename: 'CreatePullRequestPayload', pullRequest: null } as GqlObj;
        const repo = repoList.find((r) => r.dbId === Number(decoded.parts[0]));
        if (repo === undefined) return { __typename: 'CreatePullRequestPayload', pullRequest: null } as GqlObj;
        const pull = gqlCreatePull(repo, String(input.title ?? ''), typeof input.body === 'string' ? input.body : '', String(input.headRefName ?? ''), String(input.baseRefName ?? ''));
        return { __typename: 'CreatePullRequestPayload', pullRequest: pull === null ? null : gqlPullObj(repo, pull) } as GqlObj;
      }
      if (field.name === 'mergePullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(String(input.pullRequestId ?? ''));
        if (decoded === null || decoded.kind !== 'P') return { __typename: 'MergePullRequestPayload', pullRequest: null } as GqlObj;
        const repo = repoList.find((r) => r.dbId === Number(decoded.parts[0]));
        const pull = repo?.pulls.get(Number(decoded.parts[1]));
        if (pull === undefined || repo === undefined) return { __typename: 'MergePullRequestPayload', pullRequest: null } as GqlObj;
        gqlMergePull(repo, pull);
        return { __typename: 'MergePullRequestPayload', pullRequest: gqlPullObj(repo, pull) } as GqlObj;
      }
      if (field.name === 'addComment') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(String(input.subjectId ?? ''));
        if (decoded === null) return { __typename: 'AddCommentPayload', commentEdge: null } as GqlObj;
        const repo = repoList.find((r) => r.dbId === Number(decoded.parts[0]));
        if (repo === undefined) return { __typename: 'AddCommentPayload', commentEdge: null } as GqlObj;
        if (decoded.kind === 'I') {
          const issue = repo.issues.get(Number(decoded.parts[1]));
          if (issue === undefined) return { __typename: 'AddCommentPayload', commentEdge: null } as GqlObj;
          const comment: IssueComment = { id: nextGlobalId, body: String(input.body ?? ''), seq: nextGlobalId };
          nextGlobalId += 1;
          issue.comments.push(comment);
          return { __typename: 'AddCommentPayload', commentEdge: { __typename: 'IssueCommentEdge', node: { __typename: 'IssueComment', repo, issue, comment } as GqlObj, cursor: gqlCursor(comment.id) } as GqlObj } as GqlObj;
        }
        return { __typename: 'AddCommentPayload', commentEdge: null } as GqlObj;
      }
      break;
    }
    case 'User': {
      if (field.name === 'login') return VIEWER_LOGIN;
      if (field.name === 'id') return globalId('U', [VIEWER_ID]);
      if (field.name === 'name') return VIEWER_NAME;
      if (field.name === 'email') return VIEWER_EMAIL;
      if (field.name === 'avatarUrl') return `https://avatars.githubusercontent.com/u/${VIEWER_ID}?v=4`;
      if (field.name === 'url') return `https://github.com/${VIEWER_LOGIN}`;
      if (field.name === 'databaseId') return VIEWER_ID;
      break;
    }
    case 'Repository': {
      const repo = (source as { repo: Repo }).repo;
      if (field.name === 'id') return globalId('R', [repo.dbId]);
      if (field.name === 'databaseId') return repo.dbId;
      if (field.name === 'name') return repo.name;
      if (field.name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
      if (field.name === 'owner') return { __typename: 'User' } as GqlObj;
      if (field.name === 'defaultBranchRef') {
        const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
        return { __typename: 'Ref', name: repo.defaultBranch, targetOid: tip ?? null } as GqlObj;
      }
      if (field.name === 'viewerPermission') return 'ADMIN';
      if (field.name === 'hasIssuesEnabled') return true;
      if (field.name === 'description') return repo.description;
      if (field.name === 'url') return `https://github.com/${repo.owner}/${repo.name}`;
      if (field.name === 'createdAt') return isoOf(repo.seq);
      if (field.name === 'updatedAt') return isoOf(repo.seq);
      if (field.name === 'visibility') return repo.isPrivate ? 'PRIVATE' : 'PUBLIC';
      if (field.name === 'isPrivate') return repo.isPrivate;
      if (field.name === 'issue') {
        const issue = repo.issues.get(Number(args.number ?? 0));
        return issue === undefined ? null : gqlIssueObj(repo, issue);
      }
      if (field.name === 'issues') {
        let list = [...repo.issues.values()];
        const states = args.states as string[] | undefined;
        if (states !== undefined && states.length > 0) {
          const wanted = new Set(states.map((s) => String(s).toLowerCase()));
          list = list.filter((i) => wanted.has(i.state));
        }
        const orderBy = args.orderBy as { field?: string; direction?: string } | undefined;
        if (orderBy !== undefined && orderBy.field === 'CREATED_AT') {
          list.sort((a, b) => (orderBy.direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq));
        } else {
          list.sort((a, b) => b.seq - a.seq);
        }
        return gqlConnection(list, { first: typeof args.first === 'number' ? args.first : undefined, after: typeof args.after === 'string' ? args.after : null }, (i) => gqlIssueObj(repo, i), (i) => i.number, 'IssueConnection');
      }
      if (field.name === 'pullRequests') {
        const list = [...repo.pulls.values()].sort((a, b) => b.seq - a.seq);
        return gqlConnection(list, { first: typeof args.first === 'number' ? args.first : undefined, after: typeof args.after === 'string' ? args.after : null }, (p) => gqlPullObj(repo, p), (p) => p.number, 'PullRequestConnection');
      }
      if (field.name === 'pullRequest') {
        const pull = repo.pulls.get(Number(args.number ?? 0));
        return pull === undefined ? null : gqlPullObj(repo, pull);
      }
      break;
    }
    case 'Issue': {
      const { repo, issue } = source as { repo: Repo; issue: Issue };
      if (field.name === 'id') return globalId('I', [repo.dbId, issue.number]);
      if (field.name === 'number') return issue.number;
      if (field.name === 'title') return issue.title;
      if (field.name === 'body') return issue.body;
      if (field.name === 'state') return issue.state === 'open' ? 'OPEN' : 'CLOSED';
      if (field.name === 'createdAt') return isoOf(issue.seq);
      if (field.name === 'updatedAt') return isoOf(issue.seq);
      if (field.name === 'author') return { __typename: 'User' } as GqlObj;
      if (field.name === 'url') return `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`;
      if (field.name === 'repository') return gqlRepoObj(repo);
      if (field.name === 'labels') {
        const nodes = issue.labels.map((n) => ({ __typename: 'Label', label: repo.labels.get(n) ?? { name: n, color: 'ededed', description: '' } } as GqlObj));
        return gqlConnection(nodes, { first: typeof args.first === 'number' ? args.first : undefined, after: null }, (x) => x, (x) => (x as { label: Label }).label.name.length, 'LabelConnection');
      }
      if (field.name === 'comments') {
        const nodes = issue.comments.map((c) => ({ __typename: 'IssueComment', repo, issue, comment: c } as GqlObj));
        return gqlConnection(nodes, { first: typeof args.first === 'number' ? args.first : undefined, after: null }, (x) => x, (x) => (x as { comment: IssueComment }).comment.id, 'IssueCommentConnection');
      }
      break;
    }
    case 'PullRequest': {
      const { repo, pull } = source as { repo: Repo; pull: Pull };
      if (field.name === 'id') return globalId('P', [repo.dbId, pull.number]);
      if (field.name === 'number') return pull.number;
      if (field.name === 'title') return pull.title;
      if (field.name === 'body') return pull.body;
      if (field.name === 'state') return gqlPrState(pull);
      if (field.name === 'headRefName') return pull.headRef;
      if (field.name === 'baseRefName') return pull.baseRef;
      if (field.name === 'headRefOid') return pull.headSha;
      if (field.name === 'baseRefOid') return pull.baseSha;
      if (field.name === 'mergeable') return gqlMergeable(repo, pull);
      if (field.name === 'merged') return pull.merged;
      if (field.name === 'createdAt') return isoOf(pull.seq);
      if (field.name === 'updatedAt') return isoOf(pull.seq);
      if (field.name === 'author') return { __typename: 'User' } as GqlObj;
      if (field.name === 'url') return `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`;
      if (field.name === 'repository') return gqlRepoObj(repo);
      if (field.name === 'files') {
        const files = gqlPullFiles(repo, pull);
        const nodes = files.map((f) => ({ __typename: 'PullRequestChangedFile', path: f.path, additions: f.additions, deletions: f.deletions, status: f.status } as GqlObj));
        return gqlConnection(nodes, { first: typeof args.first === 'number' ? args.first : undefined, after: null }, (x) => x, (x) => (x as { path: string }).path.length, 'PullRequestFileConnection');
      }
      break;
    }
    case 'Ref': {
      const ref = source as { name: string; targetOid: string | null };
      if (field.name === 'name') return ref.name;
      if (field.name === 'prefix') return 'refs/heads/';
      if (field.name === 'target') {
        if (ref.targetOid === null) return null;
        return { __typename: 'Commit', oid: ref.targetOid, message: '' } as GqlObj;
      }
      break;
    }
    case 'Commit': {
      const commit = source as { oid: string; message: string };
      if (field.name === 'oid') return commit.oid;
      if (field.name === 'message') return commit.message;
      break;
    }
    case 'IssueConnection':
    case 'PullRequestConnection':
    case 'PullRequestFileConnection':
    case 'LabelConnection':
    case 'IssueCommentConnection': {
      const conn = source as { nodes: GqlObj[]; edges: GqlObj[]; pageInfo: Record<string, unknown>; totalCount: number };
      if (field.name === 'nodes') return conn.nodes;
      if (field.name === 'totalCount') return conn.totalCount;
      if (field.name === 'pageInfo') return { __typename: 'PageInfo', info: conn.pageInfo } as GqlObj;
      if (field.name === 'edges') return conn.edges;
      break;
    }
    case 'PageInfo': {
      const info = (source as { info: Record<string, unknown> }).info;
      if (field.name === 'hasNextPage') return info.hasNextPage ?? false;
      if (field.name === 'hasPreviousPage') return info.hasPreviousPage ?? false;
      if (field.name === 'startCursor') return info.startCursor ?? null;
      if (field.name === 'endCursor') return info.endCursor ?? null;
      break;
    }
    case 'IssueEdge':
    case 'PullRequestEdge':
    case 'PullRequestFileEdge':
    case 'LabelEdge':
    case 'IssueCommentEdge': {
      const edge = source as { node: GqlObj; cursor: string };
      if (field.name === 'node') return edge.node;
      if (field.name === 'cursor') return edge.cursor;
      break;
    }
    case 'PullRequestChangedFile': {
      const f = source as { path: string; additions: number; deletions: number; status: string };
      if (field.name === 'path') return f.path;
      if (field.name === 'additions') return f.additions;
      if (field.name === 'deletions') return f.deletions;
      if (field.name === 'changes') return f.additions + f.deletions;
      if (field.name === 'status') return f.status;
      break;
    }
    case 'Label': {
      const label = (source as { label: Label }).label;
      if (field.name === 'name') return label.name;
      if (field.name === 'color') return label.color;
      if (field.name === 'description') return label.description;
      if (field.name === 'id') return globalId('L', [label.name]);
      break;
    }
    case 'IssueComment': {
      const { repo, issue, comment } = source as { repo: Repo; issue: Issue; comment: IssueComment };
      if (field.name === 'id') return globalId('C', [repo.dbId, issue.number, comment.id]);
      if (field.name === 'body') return comment.body;
      if (field.name === 'author') return { __typename: 'User' } as GqlObj;
      if (field.name === 'createdAt') return isoOf(comment.seq);
      if (field.name === 'updatedAt') return isoOf(comment.seq);
      break;
    }
    case '__Type': {
      const name = (source as { name: string }).name;
      if (field.name === 'name') return name;
      if (field.name === 'kind') return GQL_ENUMS[name] !== undefined ? 'ENUM' : 'OBJECT';
      if (field.name === 'description') return null;
      if (field.name === 'fields') {
        const fields = GQL_SCHEMA[name] ?? [];
        return fields.map((f) => ({ __typename: '__Field', name: f } as GqlObj));
      }
      if (field.name === 'enumValues') {
        const values = GQL_ENUMS[name] ?? [];
        return values.map((v) => ({ __typename: '__EnumValue', name: v } as GqlObj));
      }
      break;
    }
    case '__Field': {
      const f = source as { name: string };
      if (field.name === 'name') return f.name;
      if (field.name === 'description') return null;
      if (field.name === 'args') return [];
      if (field.name === 'type') return null;
      break;
    }
    case '__EnumValue': {
      if (field.name === 'name') return (source as { name: string }).name;
      if (field.name === 'description') return null;
      break;
    }
    case '__Schema': {
      if (field.name === 'queryType') return { __typename: '__Type', name: 'Query' } as GqlObj;
      if (field.name === 'mutationType') return { __typename: '__Type', name: 'Mutation' } as GqlObj;
      if (field.name === 'types') return Object.keys(GQL_SCHEMA).map((n) => ({ __typename: '__Type', name: n } as GqlObj));
      break;
    }
    case 'CreateIssuePayload':
    case 'CloseIssuePayload': {
      const p = source as { issue: GqlObj | null };
      if (field.name === 'issue') return p.issue;
      if (field.name === 'clientMutationId') return null;
      break;
    }
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload': {
      const p = source as { pullRequest: GqlObj | null };
      if (field.name === 'pullRequest') return p.pullRequest;
      if (field.name === 'clientMutationId') return null;
      break;
    }
    case 'AddCommentPayload': {
      const p = source as { commentEdge: GqlObj | null };
      if (field.name === 'commentEdge') return p.commentEdge;
      if (field.name === 'clientMutationId') return null;
      break;
    }
  }
  return undefined;
}

function gqlExecuteSelection(source: GqlObj, selection: GqlSelection[], variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const typeName = source.__typename;
  for (const sel of selection) {
    if (sel.kind === 'fragment') {
      if (sel.typeCondition !== null && sel.typeCondition !== typeName) continue;
      Object.assign(out, gqlExecuteSelection(source, sel.selection, variables));
      continue;
    }
    const field = sel.field;
    if (field.name === '__typename') {
      out[field.alias ?? field.name] = typeName;
      continue;
    }
    const known = (GQL_SCHEMA[typeName] ?? []).includes(field.name);
    if (!known) {
      throw new GqlError(`Cannot query field "${field.name}" on type "${typeName}".`);
    }
    const value = gqlResolveField(source, field, variables);
    if (value === undefined) {
      throw new GqlError(`Cannot query field "${field.name}" on type "${typeName}".`);
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      if (Array.isArray(value) && field.selection !== null) {
        out[field.alias ?? field.name] = value.map((v) => {
          if (v !== null && typeof v === 'object' && '__typename' in (v as Record<string, unknown>)) {
            return gqlExecuteSelection(v as GqlObj, field.selection as GqlSelection[], variables);
          }
          return v;
        });
      } else {
        out[field.alias ?? field.name] = value;
      }
      continue;
    }
    if ('__typename' in (value as Record<string, unknown>)) {
      if (field.selection === null) out[field.alias ?? field.name] = {};
      else out[field.alias ?? field.name] = gqlExecuteSelection(value as GqlObj, field.selection, variables);
      continue;
    }
    out[field.alias ?? field.name] = value;
  }
  return out;
}

function gqlExecuteOperation(op: GqlOperation, variables: Record<string, unknown>): { data: unknown; errors?: Array<{ message: string }> } {
  try {
    const root: GqlObj = op.type === 'mutation' ? { __typename: 'Mutation' } : { __typename: 'Query' };
    const data = gqlExecuteSelection(root, op.selection, variables);
    return { data };
  } catch (err) {
    if (err instanceof GqlError) {
      return { data: null, errors: [{ message: err.message }] };
    }
    return { data: null, errors: [{ message: `internal error: ${err instanceof Error ? err.message : 'unknown'}` }] };
  }
}

function gqlHandleBody(body: unknown): unknown {
  if (Array.isArray(body)) {
    return body.map((item) => {
      const b = (item ?? {}) as Record<string, unknown>;
      const query = typeof b.query === 'string' ? b.query : '';
      const variables = (b.variables ?? {}) as Record<string, unknown>;
      try {
        const ops = new GqlParser(gqlTokenize(query)).parseDocument();
        if (ops.length === 0) return { data: null, errors: [{ message: 'empty document' }] };
        return gqlExecuteOperation(ops[0] as GqlOperation, variables);
      } catch (err) {
        return { data: null, errors: [{ message: err instanceof Error ? err.message : 'parse error' }] };
      }
    });
  }
  const b = (body ?? {}) as Record<string, unknown>;
  const query = typeof b.query === 'string' ? b.query : '';
  const variables = (b.variables ?? {}) as Record<string, unknown>;
  try {
    const ops = new GqlParser(gqlTokenize(query)).parseDocument();
    if (ops.length === 0) return { data: null, errors: [{ message: 'empty document' }] };
    const opName = typeof b.operationName === 'string' ? b.operationName : null;
    let op = ops[0] as GqlOperation;
    if (opName !== null) {
      const found = ops.find((o) => o.name === opName);
      if (found !== undefined) op = found;
    }
    return gqlExecuteOperation(op, variables);
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'parse error' }] };
  }
}

// -------------------------------------------------------------------------------------------
// MCP (Streamable HTTP, JSON-RPC 2.0)
// -------------------------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, Record<string, unknown>>; required: string[] };
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        owner: { type: 'string', description: 'Owner login (defaults to the authenticated user)' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state: open, closed, or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

const MCP_SERVER_INFO = { name: 'github-core-clone-forge', version: FORGE_VERSION };

function mcpNormalizeArgs(raw: Record<string, unknown>): Record<string, unknown> {
  const norm: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) norm[k.toLowerCase().replace(/[^a-z0-9]/g, '')] = v;
  return norm;
}

function mcpPick(norm: Record<string, unknown>, synonyms: string[]): unknown {
  for (const s of synonyms) {
    const v = norm[s];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

function mcpToolResult(result: Record<string, unknown>, isError = false): Record<string, unknown> {
  const text = JSON.stringify(result);
  return { content: [{ type: 'text', text }], structuredContent: result, isError };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpCallTool(name: string, rawArgs: Record<string, unknown>): Record<string, unknown> {
  const norm = mcpNormalizeArgs(rawArgs);
  // full_name fallback: "owner/repo".
  const fullName = typeof norm.fullname === 'string' ? norm.fullname : '';
  const owner = mcpPick(norm, ['owner', 'ownerlogin', 'org', 'user', 'login', 'ownername', 'organization']);
  let repoName = mcpPick(norm, ['repo', 'repository', 'reponame', 'project']);
  if (repoName === undefined && fullName.includes('/')) {
    const parts = fullName.split('/');
    repoName = parts[1];
  }
  const repo = repoName === undefined || owner === undefined ? undefined : getRepo(String(owner), String(repoName));
  switch (name) {
    case 'create_repo': {
      const repoNameArg = mcpPick(norm, ['repo', 'repository', 'reponame', 'name', 'project']);
      if (repoNameArg === undefined) return mcpToolError('Missing required argument: name');
      const repoOwner = owner === undefined ? VIEWER_LOGIN : String(owner);
      if (getRepo(repoOwner, String(repoNameArg)) !== undefined) return mcpToolError('Repository already exists');
      const created = createRepo(repoOwner, String(repoNameArg), norm.private === true || norm.isprivate === true, typeof norm.description === 'string' ? norm.description : '');
      return mcpToolResult(repoJson(created) as Record<string, unknown>);
    }
    case 'get_repo': {
      if (owner === undefined || repoName === undefined) return mcpToolError('Missing required arguments: owner, repo');
      if (repo === undefined) return mcpToolError('Repository not found');
      return mcpToolResult(repoJson(repo) as Record<string, unknown>);
    }
    case 'create_issue': {
      if (owner === undefined || repoName === undefined) return mcpToolError('Missing required arguments: owner, repo');
      const title = mcpPick(norm, ['title', 'issuetitle', 'prtitle']);
      if (title === undefined) return mcpToolError('Missing required argument: title');
      if (repo === undefined) return mcpToolError('Repository not found');
      const body = mcpPick(norm, ['body', 'description', 'content', 'text', 'message']);
      const issue = gqlCreateIssue(repo, String(title), typeof body === 'string' ? body : '');
      return mcpToolResult(issueJson(repo, issue) as Record<string, unknown>);
    }
    case 'list_issues': {
      if (owner === undefined || repoName === undefined) return mcpToolError('Missing required arguments: owner, repo');
      if (repo === undefined) return mcpToolError('Repository not found');
      const state = typeof norm.state === 'string' ? norm.state.toLowerCase() : 'open';
      const list = [...repo.issues.values()]
        .filter((i) => state === 'all' || i.state === state)
        .sort((a, b) => b.seq - a.seq)
        .map((i) => ({ number: i.number, title: i.title, body: i.body, state: i.state }));
      return mcpToolResult({ issues: list });
    }
    case 'create_pull_request': {
      if (owner === undefined || repoName === undefined) return mcpToolError('Missing required arguments: owner, repo');
      const title = mcpPick(norm, ['title', 'issuetitle', 'prtitle']);
      const head = mcpPick(norm, ['head', 'headref', 'headbranch', 'source', 'from', 'branch', 'headname']);
      const base = mcpPick(norm, ['base', 'baseref', 'target', 'into', 'basename', 'basebranch']);
      if (title === undefined || head === undefined || base === undefined) return mcpToolError('Missing required arguments: title, head, base');
      if (repo === undefined) return mcpToolError('Repository not found');
      const body = mcpPick(norm, ['body', 'description', 'content', 'text', 'message']);
      const pull = gqlCreatePull(repo, String(title), typeof body === 'string' ? body : '', String(head), String(base));
      if (pull === null) return mcpToolError('Head or base branch not found');
      return mcpToolResult(pullJson(repo, pull) as Record<string, unknown>);
    }
    case 'merge_pull_request': {
      if (owner === undefined || repoName === undefined) return mcpToolError('Missing required arguments: owner, repo');
      const pullNumber = mcpPick(norm, ['pullnumber', 'prnumber', 'number', 'pullrequestnumber', 'id']);
      if (pullNumber === undefined) return mcpToolError('Missing required argument: pull_number');
      if (repo === undefined) return mcpToolError('Repository not found');
      const pull = repo.pulls.get(Number(pullNumber));
      if (pull === undefined) return mcpToolError('Pull request not found');
      if (!gqlMergePull(repo, pull)) return mcpToolError('Pull request cannot be merged (conflict or already closed)');
      return mcpToolResult({ merged: true, sha: pull.mergeCommitSha, number: pull.number, state: 'closed' });
    }
    default:
      return mcpToolError(`Unknown tool: ${name}`);
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'DELETE') {
    sendJson(res, 200, {});
    return;
  }
  if (req.method !== 'POST') {
    sendJson(res, 405, { message: 'Method Not Allowed' });
    return;
  }
  if (!isAuthed(req)) { unauthorized(res); return; }
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8')) as unknown;
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: 424242, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const body = (parsed ?? {}) as Record<string, unknown>;
  const id = body.id;
  const method = typeof body.method === 'string' ? body.method : '';
  const isNotification = id === undefined || id === null;
  if (method === '') {
    if (isNotification) { res.writeHead(202); res.end(); return; }
    sendJson(res, 200, { jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  if (method.startsWith('notifications/')) {
    res.writeHead(202);
    res.end();
    return;
  }
  const params = (body.params ?? {}) as Record<string, unknown>;
  if (method === 'server/discover') {
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        supportedVersions: ['2026-07-28'],
        capabilities: { tools: {} },
        serverInfo: MCP_SERVER_INFO,
        _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
      },
    });
    return;
  }
  if (method === 'initialize') {
    const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2026-07-28';
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: { protocolVersion: requested, capabilities: { tools: {} }, serverInfo: MCP_SERVER_INFO },
    });
    return;
  }
  if (method === 'ping') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: {} });
    return;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const toolArgs = (params.arguments ?? {}) as Record<string, unknown>;
    const tool = MCP_TOOLS.find((t) => t.name === toolName);
    if (tool === undefined) {
      sendJson(res, 200, { jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${toolName}` } });
      return;
    }
    const result = mcpCallTool(toolName, toolArgs);
    sendJson(res, 200, { jsonrpc: '2.0', id, result });
    return;
  }
  sendJson(res, 200, { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
}

// -------------------------------------------------------------------------------------------
// REST v3 dispatch
// -------------------------------------------------------------------------------------------

async function handleRest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = pathOf(req);
  const segs = path.split('/').filter((s) => s !== '');
  // segs[0] === 'api', segs[1] === 'v3'
  const rest = segs.slice(2);
  const method = req.method ?? 'GET';

  if (rest.length === 0) {
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      user_url: '/api/v3/users/{user}',
      search_url: '/api/v3/search',
      meta: { installed_version: FORGE_VERSION },
    }, { 'x-oauth-scopes': 'repo' });
    return;
  }
  if (rest[0] === 'meta') {
    sendJson(res, 200, { installed_version: FORGE_VERSION, installed_at: isoOf(0) });
    return;
  }
  if (!isAuthed(req)) { unauthorized(res); return; }

  if (rest[0] === 'user' && rest.length === 1 && method === 'GET') {
    sendJson(res, 200, userJson());
    return;
  }
  if (rest[0] === 'user' && rest[1] === 'repos') {
    if (method === 'GET') {
      sendPage(req, res, repoList.filter((r) => r.owner === VIEWER_LOGIN).map((r) => repoJson(r)));
      return;
    }
    if (method === 'POST') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) { badJson(res); return; }
      const body = (parsed.value ?? {}) as Record<string, unknown>;
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') { sendJson(res, 422, { message: 'name is required' }); return; }
      if (getRepo(VIEWER_LOGIN, name) !== undefined) {
        sendJson(res, 422, { message: 'Repository already exists' });
        return;
      }
      const repo = createRepo(VIEWER_LOGIN, name, body.private === true, typeof body.description === 'string' ? body.description : '');
      sendJson(res, 201, repoJson(repo));
      return;
    }
  }

  if (rest[0] === 'repos' && rest.length >= 3) {
    const owner = rest[1] as string;
    const repoName = rest[2] as string;
    if (owner !== VIEWER_LOGIN) { notFound(res); return; }
    const repo = getRepo(owner, repoName);
    if (repo === undefined) { notFound(res); return; }
    const tail = rest.slice(3);

    if (tail.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoJson(repo)); return; }
      if (method === 'PATCH') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) { badJson(res); return; }
        const body = (parsed.value ?? {}) as Record<string, unknown>;
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.private === 'boolean') repo.isPrivate = body.private;
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, repoName));
        const idx = repoList.indexOf(repo);
        if (idx >= 0) repoList.splice(idx, 1);
        res.writeHead(204, { 'x-github-request-id': `req-${++requestCounter}` });
        res.end();
        return;
      }
    }

    if (tail[0] === 'branches' && method === 'GET') {
      if (tail.length === 1) {
        const branches = [...repo.refs.keys()]
          .filter((r) => r.startsWith('refs/heads/'))
          .map((r) => r.slice('refs/heads/'.length))
          .sort()
          .map((name) => ({ name, commit: { sha: repo.refs.get(`refs/heads/${name}`) as string }, protected: false }));
        sendJson(res, 200, branches);
        return;
      }
      const branch = tail[1] as string;
      const sha = repo.refs.get(`refs/heads/${branch}`);
      if (sha === undefined) { notFound(res); return; }
      sendJson(res, 200, { name: branch, commit: { sha }, protected: false });
      return;
    }

    if (tail[0] === 'commits' && method === 'GET') {
      const q = queryOf(req);
      const tip = resolveRef(repo, q.get('sha'));
      if (tip === null) { sendJson(res, 200, []); return; }
      const commitOid = peelToCommit(repo, tip);
      if (commitOid === null) { sendJson(res, 200, []); return; }
      const list = commitList(repo, commitOid).map(({ sha, info }) => ({
        sha,
        commit: {
          message: info.message.replace(/\n$/, ''),
          author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoOf(repo.commitSeq) },
          committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoOf(repo.commitSeq) },
          tree: { sha: info.tree },
        },
        author: { login: VIEWER_LOGIN, id: VIEWER_ID },
        committer: { login: VIEWER_LOGIN, id: VIEWER_ID },
        parents: info.parents.map((p) => ({ sha: p })),
      }));
      sendPage(req, res, list);
      return;
    }

    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (method === 'POST' && tail.length === 2) {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) { badJson(res); return; }
        const body = (parsed.value ?? {}) as Record<string, unknown>;
        const ref = typeof body.ref === 'string' ? body.ref : '';
        const sha = typeof body.sha === 'string' ? body.sha : '';
        if (ref === '' || sha === '' || repo.objects.get(sha) === undefined) {
          sendJson(res, 422, { message: 'Invalid ref or sha' });
          return;
        }
        if (repo.refs.has(ref)) { sendJson(res, 422, { message: 'Reference already exists' }); return; }
        repo.refs.set(ref, sha);
        const obj = repo.objects.get(sha) as GitObject;
        sendJson(res, 201, { ref, object: { sha, type: obj.type }, sha });
        return;
      }
      if (method === 'GET' && tail.length === 2) {
        const all = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([ref, sha]) => ({ ref, object: { sha }, sha }));
        sendJson(res, 200, all);
        return;
      }
      if (method === 'GET' && tail.length === 4 && tail[2] === 'heads') {
        const branch = tail[3] as string;
        const sha = repo.refs.get(`refs/heads/${branch}`);
        if (sha === undefined) { notFound(res); return; }
        sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha }, sha });
        return;
      }
    }

    if (tail[0] === 'contents') {
      const filePath = tail.slice(1).join('/');
      if (method === 'PUT') { await handleContentsPut(req, res, repo, filePath); return; }
      if (method === 'GET') { handleContentsGet(req, res, repo, filePath); return; }
      if (method === 'DELETE') { await handleContentsDelete(req, res, repo, filePath); return; }
    }

    if (tail[0] === 'labels') {
      if (method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()].map((l) => labelJson(l)));
        return;
      }
      if (method === 'POST') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) { badJson(res); return; }
        const body = (parsed.value ?? {}) as Record<string, unknown>;
        const name = typeof body.name === 'string' ? body.name : '';
        if (name === '') { sendJson(res, 422, { message: 'name is required' }); return; }
        const label: Label = {
          name,
          color: typeof body.color === 'string' ? body.color : 'ededed',
          description: typeof body.description === 'string' ? body.description : '',
        };
        repo.labels.set(name, label);
        sendJson(res, 201, labelJson(label));
        return;
      }
    }

    if (tail[0] === 'issues') {
      if (tail.length === 1) {
        if (method === 'GET') {
          const q = queryOf(req);
          const state = (q.get('state') ?? 'open').toLowerCase();
          let list = [...repo.issues.values()];
          if (state !== 'all') list = list.filter((i) => i.state === state);
          const sort = q.get('sort') ?? 'created';
          const direction = (q.get('direction') ?? 'desc').toLowerCase();
          if (sort === 'created') list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          sendPage(req, res, list.map((i) => issueJson(repo, i)));
          return;
        }
        if (method === 'POST') {
          const parsed = await readJsonBody(req);
          if (!parsed.ok) { badJson(res); return; }
          const body = (parsed.value ?? {}) as Record<string, unknown>;
          const title = typeof body.title === 'string' ? body.title : '';
          if (title === '') { sendJson(res, 422, { message: 'title is required' }); return; }
          const labels = Array.isArray(body.labels) ? (body.labels as unknown[]).map((l) => String(l)) : [];
          for (const labelName of labels) {
            if (!repo.labels.has(labelName)) { sendJson(res, 422, { message: `Label "${labelName}" does not exist` }); return; }
          }
          const issue = gqlCreateIssue(repo, title, typeof body.body === 'string' ? body.body : '', labels);
          sendJson(res, 201, issueJson(repo, issue));
          return;
        }
      }
      const issueNumber = Number(tail[1]);
      const issue = repo.issues.get(issueNumber);
      if (tail.length === 2 && !Number.isNaN(issueNumber)) {
        if (method === 'GET') {
          if (issue === undefined) { notFound(res); return; }
          sendJson(res, 200, issueJson(repo, issue));
          return;
        }
        if (method === 'PATCH') {
          if (issue === undefined) { notFound(res); return; }
          const parsed = await readJsonBody(req);
          if (!parsed.ok) { badJson(res); return; }
          const body = (parsed.value ?? {}) as Record<string, unknown>;
          if (typeof body.title === 'string') issue.title = body.title;
          if (typeof body.body === 'string') issue.body = body.body;
          if (body.state === 'open' || body.state === 'closed') {
            issue.state = body.state;
            issue.closedSeq = body.state === 'closed' ? issue.seq : null;
          }
          sendJson(res, 200, issueJson(repo, issue));
          return;
        }
      }
      if (tail.length === 3 && tail[2] === 'comments' && !Number.isNaN(issueNumber)) {
        if (issue === undefined) { notFound(res); return; }
        if (method === 'GET') {
          sendJson(res, 200, issue.comments.map((c) => commentJson(repo, issue, c)));
          return;
        }
        if (method === 'POST') {
          const parsed = await readJsonBody(req);
          if (!parsed.ok) { badJson(res); return; }
          const body = (parsed.value ?? {}) as Record<string, unknown>;
          const comment: IssueComment = { id: nextGlobalId, body: typeof body.body === 'string' ? body.body : '', seq: nextGlobalId };
          nextGlobalId += 1;
          issue.comments.push(comment);
          sendJson(res, 201, commentJson(repo, issue, comment));
          return;
        }
      }
    }

    if (tail[0] === 'pulls') {
      if (tail.length === 1) {
        if (method === 'GET') {
          const q = queryOf(req);
          const state = (q.get('state') ?? 'open').toLowerCase();
          let list = [...repo.pulls.values()];
          if (state !== 'all') list = list.filter((p) => p.state === state);
          list.sort((a, b) => b.seq - a.seq);
          sendPage(req, res, list.map((p) => pullJson(repo, p)));
          return;
        }
        if (method === 'POST') {
          const parsed = await readJsonBody(req);
          if (!parsed.ok) { badJson(res); return; }
          const body = (parsed.value ?? {}) as Record<string, unknown>;
          const title = typeof body.title === 'string' ? body.title : '';
          const head = typeof body.head === 'string' ? body.head : '';
          const base = typeof body.base === 'string' ? body.base : '';
          if (title === '' || head === '' || base === '') { sendJson(res, 422, { message: 'title, head, and base are required' }); return; }
          if (repo.refs.get(`refs/heads/${head}`) === undefined || repo.refs.get(`refs/heads/${base}`) === undefined) {
            sendJson(res, 422, { message: 'Head or base branch not found' });
            return;
          }
          const dup = [...repo.pulls.values()].find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
          if (dup !== undefined) { sendJson(res, 422, { message: 'A pull request already exists for this head' }); return; }
          const pull = gqlCreatePull(repo, title, typeof body.body === 'string' ? body.body : '', head, base);
          if (pull === null) { sendJson(res, 422, { message: 'Head or base branch not found' }); return; }
          sendJson(res, 201, pullJson(repo, pull));
          return;
        }
      }
      const pullNumber = Number(tail[1]);
      const pull = repo.pulls.get(pullNumber);
      if (tail.length === 2 && !Number.isNaN(pullNumber) && method === 'GET') {
        if (pull === undefined) { notFound(res); return; }
        sendJson(res, 200, pullJson(repo, pull));
        return;
      }
      if (tail.length === 3 && tail[2] === 'files' && !Number.isNaN(pullNumber) && method === 'GET') {
        if (pull === undefined) { notFound(res); return; }
        const files = gqlPullFiles(repo, pull).map((f) => ({
          filename: f.path,
          status: f.status,
          additions: f.additions,
          deletions: f.deletions,
          changes: f.additions + f.deletions,
        }));
        sendJson(res, 200, files);
        return;
      }
      if (tail.length === 3 && tail[2] === 'merge' && !Number.isNaN(pullNumber) && method === 'PUT') {
        if (pull === undefined) { notFound(res); return; }
        if (pull.state !== 'open') { sendJson(res, 405, { message: 'Pull request is not open' }); return; }
        const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
        const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
        if (headTip === undefined || baseTip === undefined) { sendJson(res, 405, { message: 'Head or base branch not found' }); return; }
        if (mergeConflict(repo, headTip, baseTip)) { sendJson(res, 405, { message: 'Merge conflict' }); return; }
        gqlMergePull(repo, pull);
        sendJson(res, 200, { merged: true, sha: pull.mergeCommitSha, message: 'Pull request successfully merged' });
        return;
      }
    }
  }

  notFound(res);
}

// -------------------------------------------------------------------------------------------
// router + createApp
// -------------------------------------------------------------------------------------------

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const path = pathOf(req);
    const method = req.method ?? 'GET';

    // Boot probe (no auth): the env calls it twice at startup.
    if (path === '/healthz' && method === 'GET') {
      sendJson(res, 200, { ok: true });
      return;
    }

    // Git smart HTTP: /{owner}/{repo}.git/...
    const gitMatch = /^\/([^/]+)\/([^/]+)\.git\/(.+)$/.exec(path);
    if (gitMatch !== null) {
      const owner = decodeURIComponent(gitMatch[1] as string);
      const repoName = decodeURIComponent(gitMatch[2] as string);
      const tail = gitMatch[3] as string;
      if (!isAuthed(req)) { unauthorized(res); return; }
      const repo = getRepo(owner, repoName);
      if (repo === undefined) { notFound(res); return; }
      if (tail === 'info/refs' && method === 'GET') {
        const q = queryOf(req);
        const service = q.get('service') ?? '';
        if (service !== 'git-upload-pack' && service !== 'git-receive-pack') { notFound(res); return; }
        handleInfoRefs(req, res, owner, repoName, service);
        return;
      }
      if (tail === 'git-upload-pack' && method === 'POST') {
        const body = await readBody(req);
        const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
        if (isV2) handleUploadPackV2(req, res, repo, body);
        else handleUploadPackV0(req, res, repo, body);
        return;
      }
      if (tail === 'git-receive-pack' && method === 'POST') {
        const body = await readBody(req);
        handleReceivePack(req, res, repo, body);
        return;
      }
      notFound(res);
      return;
    }

    if (path === '/api/graphql' && method === 'POST') {
      if (!isAuthed(req)) { unauthorized(res); return; }
      const parsed = await readJsonBody(req);
      if (!parsed.ok) { badJson(res); return; }
      sendJson(res, 200, gqlHandleBody(parsed.value));
      return;
    }
    if (path === '/mcp') {
      await handleMcp(req, res);
      return;
    }
    if (path.startsWith('/api/v3')) {
      await handleRest(req, res);
      return;
    }
    notFound(res);
  } catch (err) {
    // Never kill the server on a bad request: answer 500 JSON and keep serving.
    try {
      sendJson(res, 500, { message: err instanceof Error ? err.message : 'internal error' });
    } catch {
      try { res.end(); } catch { /* ignore */ }
    }
  }
}

export function createApp(): Server {
  return createServer((req, res) => {
    void handleRequest(req, res);
  });
}
