// Typed client for the DANI controller gateway. Same endpoints the dani-ctl CLI uses.
// Write calls carry the operator token (when signed in) — see --console-auth on the controller.
const BASE = (import.meta as { env?: { VITE_DANI_GATEWAY?: string } }).env?.VITE_DANI_GATEWAY ?? "";

const TOKEN_KEY = "dani-operator-token";
export function getToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}
export function setToken(t: string) {
  try {
    if (t) localStorage.setItem(TOKEN_KEY, t);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable (tests) */
  }
}

function headers(json = false): Record<string, string> {
  const h: Record<string, string> = {};
  if (json) h["Content-Type"] = "application/json";
  const tok = getToken();
  if (tok) h["Authorization"] = `Bearer ${tok}`;
  return h;
}

export interface Worker {
  UUID: string;
  Model: string;
  Engine: string;
  Class: string;
  Site: string;
  Health: string;
  Active: number;
  MaxConcurrent: number;
  Queued: number;
  Served: number;
  Trainer: boolean;
  Drained: boolean;
  Loaded?: string[] | null;
  Accel?: string; // detected acceleration backend (cuda|metal|vulkan|cpu) — hwcaps
  // Resource budget — the EFFECTIVE cap the node reports in its heartbeat (governed config store).
  CapMode?: string; // "full" | "polite" | "custom"
  MaxCores?: number; // cores DANI may use, 0 = all/auto
  MemBudgetMB?: number; // model-memory budget in MB, 0 = unbounded/auto
}
export interface Fleet {
  count: number;
  workers: Worker[];
}

export interface ClusterMember {
  id: string;
  addr?: string;
  leader: boolean;
  self: boolean;
}
export interface Cluster {
  count: number;
  leader: string;
  site: string;
  self: string;
  members: ClusterMember[];
}

export interface Node {
  uuid: string;
  roles: string[];
  class: string;
  site: string;
  lifecycle: string;
  tier: number;
  certSerial: string;
  certExpiry: string;
  generation: number;
  live: boolean;
  drained: boolean;
  model?: string;
  engine?: string;
  trainer?: boolean;
  loaded?: string[];
}

export interface PendingJoin {
  reqId: string;
  nodeUuid: string;
  declaredRoles: string[];
  declaredClass: string;
  tier: number;
  expiresAt: string;
}

export interface Deployment {
  model: string;
  node: string;
  state: string;
  at: string;
}
export interface Lineage {
  DatasetID?: string;
  Collection?: string;
  Engineer?: string;
  BaseModelID?: string;
  [k: string]: unknown;
}
export interface Model {
  id: string;
  state: string;
  classification: string;
  base?: string;
  hash?: string;
  engine?: string;
  signatures: string[];
  gate_failed?: string;
  evals?: Record<string, number>;
  lineage?: Lineage | null;
  deployment?: Deployment | null;
  deployments?: Deployment[] | null;
  replicas: number;
}

export interface Job {
  ID: string;
  State: string;
  Candidate: string;
  TrainerUUID: string;
  CkptsDone: number;
  CkptsTotal: number;
  Collection?: string;
  Engineer?: string;
  Err?: string;
  Evals?: Record<string, number>;
}

export interface Collection {
  name: string;
  connector: string;
  chunks: number;
  classification: string;
}
export interface Collections {
  collections: Collection[];
  corpora: string[];
}

// Connectors — live external sources (folder / git / Azure Blob) managed at runtime.
// A def is what the operator writes; a status is the def joined with sync health.
export interface ConnectorDef {
  kind: "folder" | "git" | "azblob" | "sharepoint" | "confluence" | "jdbc";
  collection: string;
  path?: string; // folder
  tenant?: string; // sharepoint: AAD tenant
  clientId?: string; // sharepoint: app registration (Sites.Selected)
  space?: string; // confluence: space key
  email?: string; // confluence: Atlassian account email (Basic auth with the token)
  query?: string; // jdbc: SELECT — first column is the doc id, all columns become the text
  url?: string; // git clone URL / blob container URL / sharepoint site / confluence base (…/wiki)
  ref?: string; // git ref (empty = default branch)
  secret?: string; // token / SAS / jdbc DSN — the server returns "•redacted•" when set
  classMap?: Record<string, string>; // path-prefix -> classification floor
  defaultClass?: string;
  syncEvery?: number; // nanoseconds; 0 = manual only
  static?: boolean; // configured by controller flags — cannot be disconnected here
}
export interface ConnectorStatus {
  def: ConnectorDef;
  docs: number;
  chunks: number;
  lastSync: string; // RFC3339; the zero value "0001-01-01T00:00:00Z" means never
  lastError?: string;
  lastChanged: number; // docs added/updated in the last sync
  lastGone: number; // docs removed in the last sync
  syncing: boolean;
}
export interface ConnectorTestResult {
  ok: boolean;
  files?: number;
  detail?: string;
  error?: string;
}

export interface Principal {
  sub: string;
  display: string;
  roles: string[];
  clearance: string;
}

export interface RagAlias {
  Alias: string;
  BaseModelID: string;
  Collection: string;
}

export interface Integrity {
  ok: boolean;
  records: number;
  signedHeads: number;
  why?: string;
}
export interface AuditEvent {
  seq: number;
  type: string;
  at: string;
  payload?: Record<string, unknown>;
}
export interface AuditView {
  records: number;
  signedHeads: number;
  integrity: Integrity;
  recent: AuditEvent[];
}

// Governed config store — the fleet/site/node override layers behind the resource budget.
export interface ConfigEntry {
  scope: string; // "fleet" | "site" | "node"
  scopeVal: string; // site name or node uuid (empty for fleet)
  key: string;
  value: string;
}
export interface ConfigView {
  version: number;
  entries: ConfigEntry[];
  knownKeys: string[];
}

export interface Whoami {
  authEnabled: boolean;
  sso?: boolean; // OIDC SSO is available — the console offers a redirect login
  sub?: string;
  roles?: string[];
  clearance?: string;
  error?: string;
}

async function get<T>(path: string): Promise<T> {
  const r = await fetch(BASE + path, { headers: headers() });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return (await r.json()) as T;
}

// friendly turns a gateway error into language a non-engineer can act on; the raw
// server reason rides along because operators DO sometimes need it.
function friendly(status: number, serverMsg: string): string {
  if (status === 401) return "Sign in first — click Sign in (top right) and paste your operator token. Your administrator has the tokens (console-operators.json on the controller).";
  if (status === 403) return `Not allowed: ${serverMsg}`;
  if (status === 503) return "The fleet is busy or nothing can serve this request right now — try again in a moment.";
  return serverMsg || `HTTP ${status}`;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(BASE + path, {
    method: "POST",
    headers: headers(true),
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try {
      const j = (await r.json()) as { error?: string };
      if (j.error) msg = j.error;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(friendly(r.status, msg));
  }
  return (await r.json()) as T;
}

// del mirrors post for DELETE endpoints (no body; errors surface via friendly()).
async function del<T>(path: string): Promise<T> {
  const r = await fetch(BASE + path, { method: "DELETE", headers: headers() });
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try {
      const j = (await r.json()) as { error?: string };
      if (j.error) msg = j.error;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(friendly(r.status, msg));
  }
  return (await r.json()) as T;
}

// ChatMsg is one turn in the playground conversation.
export interface ChatMsg {
  role: "user" | "assistant";
  content: string;
  servedBy?: string;
  model?: string;
  citations?: { id: string; score: number; doc?: string; class?: string }[];
}

export const api = {
  // fleet + nodes
  fleet: () => get<Fleet>("/dani/fleet"),
  // control plane: every controller in the Raft cluster (or the single standalone controller)
  cluster: () => get<Cluster>("/dani/cluster"),
  nodes: () => get<{ nodes: Node[]; count: number }>("/dani/nodes").then((r) => r.nodes),
  drain: (node: string, drain: boolean) => post("/dani/nodes/drain", { node, drain }),
  revoke: (node: string) => post<{ note?: string }>("/dani/nodes/revoke", { node }),
  pending: () => get<{ pending: PendingJoin[] }>("/dani/enroll/pending").then((r) => r.pending),
  // governed config store (resource budget etc.): precedence node > site > fleet.
  config: () => get<ConfigView>("/dani/config"),
  setConfig: (scope: string, scopeVal: string, key: string, value: string | number) =>
    post<{ version?: number }>("/dani/config", { scope, scopeVal, key, value: String(value) }),
  clearConfig: (scope: string, scopeVal: string, key: string) =>
    post<{ version?: number }>("/dani/config", { scope, scopeVal, key, delete: true }),
  approve: (id: string) => post("/dani/enroll/approve", { id }),
  reject: (id: string, reason: string) => post("/dani/enroll/reject", { id, reason }),
  // datasets
  collections: () => get<Collections>("/dani/collections"),
  ingest: (collection: string) => post("/dani/ingest", { collection }),
  // connectors: live external sources managed at runtime (folder / git / Azure Blob)
  connectors: () => get<{ connectors: ConnectorStatus[] | null }>("/dani/connectors").then((r) => r.connectors ?? []),
  connectorTest: (def: ConnectorDef) => post<ConnectorTestResult>("/dani/connectors/test", def),
  connectorCreate: (def: ConnectorDef) => post<{ ok: boolean; collection: string }>("/dani/connectors", def),
  connectorDelete: (collection: string) => del<{ ok: boolean }>(`/dani/connectors?collection=${encodeURIComponent(collection)}`),
  upload: (collection: string, docs: string[], classification: string) =>
    post("/dani/ingest", { collection, docs, classification }),
  // identity
  principals: () => get<{ principals: Principal[] }>("/dani/principals").then((r) => r.principals),
  whoami: () => get<Whoami>("/dani/whoami"),
  // training
  jobs: () => get<{ jobs: Job[] }>("/dani/train/jobs").then((r) => r.jobs),
  submitTrain: (engineer: string, base: string, collection: string) =>
    post<{ ID: string }>("/dani/train/submit", { engineer, base, collection, method: "lora" }),
  // models
  models: () => get<{ models: Model[] }>("/dani/models").then((r) => r.models),
  sign: (model: string, role: string) => post("/dani/models/sign", { model, role }),
  deploy: (model: string, opts: { replicas?: number; node?: string }) =>
    post("/dani/models/deploy", { model, ...opts }),
  undeploy: (model: string, node?: string) => post("/dani/models/undeploy", { model, node }),
  aliases: () => get<{ aliases: RagAlias[] | null }>("/dani/rag/alias").then((r) => r.aliases ?? []),
  createAlias: (base: string, collection: string) => post("/dani/rag/alias", { base, collection }),
  // topology overlay: the DANI-coordinated WireGuard mesh
  wgMesh: () => get<{ cidr: string; nodes: { UUID: string; IP: string; PublicKey: string }[] }>("/dani/wg/mesh"),
  // playground: the models the fleet is serving RIGHT NOW (the OpenAI-compatible surface)
  liveModels: () => get<{ data: { id: string; engine?: string }[] }>("/v1/models").then((r) => r.data ?? []),
  // playground chat: send the conversation to the gateway as an attributed user; the response
  // carries the routing proof (which node served it) and RAG citations when an alias is used.
  chat: async (model: string, messages: { role: string; content: string }[], asUser: string): Promise<ChatMsg> => {
    const r = await fetch(BASE + "/v1/chat/completions", {
      method: "POST",
      headers: { ...headers(true), "X-Dani-User": asUser },
      body: JSON.stringify({ model, messages, max_tokens: 160 }),
    });
    const servedBy = r.headers.get("X-Dani-Served-By") ?? undefined;
    if (!r.ok) {
      let msg = `HTTP ${r.status}`;
      try {
        const j = (await r.json()) as { error?: { message?: string } | string };
        msg = typeof j.error === "string" ? j.error : (j.error?.message ?? msg);
      } catch {
        /* non-JSON body */
      }
      throw new Error(friendly(r.status, msg));
    }
    let citations: ChatMsg["citations"];
    try {
      const raw = r.headers.get("X-Dani-Rag-Chunks");
      if (raw) citations = JSON.parse(raw) as ChatMsg["citations"];
    } catch {
      /* citations are optional decoration */
    }
    const j = (await r.json()) as { choices?: { message?: { content?: string } }[]; model?: string };
    return { role: "assistant", content: j.choices?.[0]?.message?.content ?? "(empty reply)", servedBy, model: j.model, citations };
  },
  // liveness probe for the connection banner (healthz returns plain text, not JSON)
  health: async (): Promise<boolean> => {
    const r = await fetch(BASE + "/healthz");
    if (!r.ok) throw new Error(`controller unreachable (HTTP ${r.status})`);
    return true;
  },
  // audit
  audit: (limit = 12, type = "") =>
    get<AuditView>(`/dani/audit?limit=${limit}${type ? `&type=${encodeURIComponent(type)}` : ""}`),
  auditExport: (deployment = "dep-1") =>
    get<unknown>(`/dani/audit/export?deployment=${encodeURIComponent(deployment)}`),
};

export const REVIEWER_ROLES = ["security-officer", "governance-officer", "administrator"] as const;
