import { useState } from "react";
import { api, type Collections, type ConnectorDef, type ConnectorStatus, type ConnectorTestResult } from "../api";
import { usePoll } from "../usePoll";
import { Badge, Button, Card, ConfirmButton, Select, Toast, fieldCls, stateTone } from "./ui";

// Live connector kinds — everything else in /dani/collections is a synthetic demo corpus or upload.
const KIND_LABEL: Record<string, string> = { folder: "folder / shared drive", git: "git repository", azblob: "Azure Blob", sharepoint: "SharePoint site", confluence: "Confluence space", jdbc: "SQL database" };
const CLASSES = ["unrestricted", "internal", "restricted", "secret"];

// Sync cadence options — the server takes nanoseconds; 0 means manual only.
const CADENCES = [
  { value: "0", label: "Manual only" },
  { value: "900000000000", label: "Every 15 min" },
  { value: "3600000000000", label: "Hourly" },
  { value: "21600000000000", label: "Every 6 h" },
  { value: "86400000000000", label: "Daily" },
];

const KIND_TILES: { kind: ConnectorDef["kind"]; icon: string; label: string; desc: string }[] = [
  { kind: "folder", icon: "📁", label: "Folder / shared drive", desc: "a directory on the controller or a mounted SMB/NFS share" },
  { kind: "git", icon: "🌿", label: "Git repository", desc: "shallow-cloned and tracked; citations carry file@commit" },
  { kind: "azblob", icon: "☁", label: "Azure Blob", desc: "a blob container, crawled incrementally" },
  { kind: "sharepoint", icon: "🏢", label: "SharePoint site", desc: "one site's library via Graph (Sites.Selected); the floor covers the whole site" },
  { kind: "confluence", icon: "📘", label: "Confluence space", desc: "one space's pages via Confluence Cloud REST; the floor covers the whole space" },
  { kind: "jdbc", icon: "🗄", label: "SQL database", desc: "a SELECT over PostgreSQL/SQLite; each row becomes a document (first column = id)" },
];

// relTime renders the last-sync moment the way a person says it. The Go zero time means never.
function relTime(rfc: string): string {
  if (!rfc || rfc.startsWith("0001-")) return "never";
  const t = new Date(rfc).getTime();
  if (isNaN(t)) return "never";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

// suggestName derives a collection name from the source: last path segment / repo name
// (without .git), kebab-cased.
function suggestName(kind: ConnectorDef["kind"], path: string, url: string): string {
  const src = (kind === "folder" ? path : url).trim();
  if (!src) return "";
  let last = src.replace(/[/\\]+$/, "").split(/[/\\]/).pop() ?? "";
  if (kind === "git") last = last.replace(/\.git$/i, "");
  return last
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

// ConnectPanel is the inline "+ Connect a source" editor: pick a kind, point at the source,
// set classification floors + cadence, test, connect. No modal — it expands inside the card.
function ConnectPanel({ onDone, onCancel }: { onDone: () => Promise<void>; onCancel: () => void }) {
  const [kind, setKind] = useState<ConnectorDef["kind"]>("folder");
  const [path, setPath] = useState("");
  const [url, setUrl] = useState("");
  const [gitRef, setGitRef] = useState("");
  const [secret, setSecret] = useState("");
  const [tenant, setTenant] = useState("");
  const [clientId, setClientId] = useState("");
  const [space, setSpace] = useState("");
  const [email, setEmail] = useState("");
  const [query, setQuery] = useState("");
  const [collection, setCollection] = useState("");
  const [floors, setFloors] = useState<{ prefix: string; cls: string }[]>([]);
  const [defaultClass, setDefaultClass] = useState("internal");
  const [cadence, setCadence] = useState("0");
  const [test, setTest] = useState<"testing" | ConnectorTestResult | null>(null);
  const [panelErr, setPanelErr] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);

  const suggestion = suggestName(kind, path, url);
  const effName = collection.trim() || suggestion;
  const sourceOk =
    kind === "folder"
      ? path.trim() !== ""
      : kind === "sharepoint"
        ? url.trim() !== "" && tenant.trim() !== "" && clientId.trim() !== "" && secret.trim() !== ""
        : kind === "confluence"
          ? url.trim() !== "" && space.trim() !== "" && email.trim() !== "" && secret.trim() !== ""
          : kind === "jdbc"
            ? secret.trim() !== "" && query.trim() !== ""
            : url.trim() !== "";
  const canConnect = sourceOk && effName !== "" && !connecting;

  const buildDef = (): ConnectorDef => {
    const def: ConnectorDef = { kind, collection: effName, defaultClass };
    if (kind === "folder") def.path = path.trim();
    else if (kind !== "jdbc") def.url = url.trim();
    if (kind === "git" && gitRef.trim()) def.ref = gitRef.trim();
    if (kind !== "folder" && secret) def.secret = secret;
    if (kind === "jdbc") def.query = query.trim();
    if (kind === "sharepoint") {
      def.tenant = tenant.trim();
      def.clientId = clientId.trim();
    }
    if (kind === "confluence") {
      def.space = space.trim();
      def.email = email.trim();
    }
    const cm: Record<string, string> = {};
    for (const f of floors) if (f.prefix.trim()) cm[f.prefix.trim()] = f.cls;
    if (Object.keys(cm).length > 0) def.classMap = cm;
    const ns = Number(cadence);
    if (ns > 0) def.syncEvery = ns;
    return def;
  };

  // Source fields changed — a previous test result no longer speaks for the current def.
  const resetTest = () => setTest(null);

  const runTest = async () => {
    setTest("testing");
    setPanelErr(null);
    try {
      setTest(await api.connectorTest(buildDef()));
    } catch (e) {
      setTest({ ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  };

  const connect = async () => {
    setConnecting(true);
    setPanelErr(null);
    try {
      await api.connectorCreate(buildDef());
      await onDone(); // collapse + refetch — the new row shows "syncing…" then fills
    } catch (e) {
      setPanelErr(e instanceof Error ? e.message : String(e));
    } finally {
      setConnecting(false);
    }
  };

  return (
    <div className="mb-3 space-y-3 rounded-lg border border-emerald-500/20 bg-emerald-500/[0.03] p-3">
      <div className="grid gap-2 sm:grid-cols-3">
        {KIND_TILES.map((t) => (
          <button
            key={t.kind}
            aria-label={`kind-${t.kind}`}
            aria-pressed={kind === t.kind}
            onClick={() => {
              setKind(t.kind);
              resetTest();
            }}
            className={`rounded-lg border px-3 py-2 text-left transition ${
              kind === t.kind
                ? "border-emerald-500/40 bg-emerald-500/[0.07] ring-1 ring-inset ring-emerald-500/40"
                : "border-white/10 bg-white/[0.02] hover:bg-white/[0.05]"
            }`}
          >
            <div className="flex items-center gap-1.5 text-sm font-medium text-slate-100">
              <span aria-hidden>{t.icon}</span> {t.label}
            </div>
            <p className="mt-0.5 text-[11px] leading-snug text-slate-500">{t.desc}</p>
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-end gap-2">
        {kind === "folder" && (
          <label className="flex min-w-[16rem] flex-1 flex-col gap-1 text-xs text-slate-400">
            path
            <input
              aria-label="connector-path"
              className={fieldCls}
              placeholder="/mnt/team-share"
              value={path}
              onChange={(e) => {
                setPath(e.target.value);
                resetTest();
              }}
            />
          </label>
        )}
        {kind === "git" && (
          <>
            <label className="flex min-w-[16rem] flex-1 flex-col gap-1 text-xs text-slate-400">
              clone URL
              <input
                aria-label="connector-url"
                className={fieldCls}
                placeholder="https://github.com/acme/handbook.git"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  resetTest();
                }}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              ref (optional)
              <input
                aria-label="connector-ref"
                className={fieldCls}
                placeholder="default branch"
                value={gitRef}
                onChange={(e) => {
                  setGitRef(e.target.value);
                  resetTest();
                }}
              />
            </label>
            <label
              className="flex flex-col gap-1 text-xs text-slate-400"
              title="for private repos — stored on the controller, never shown again"
            >
              token (optional)
              <input
                aria-label="connector-secret"
                type="password"
                className={fieldCls}
                value={secret}
                onChange={(e) => {
                  setSecret(e.target.value);
                  resetTest();
                }}
              />
            </label>
          </>
        )}
        {kind === "azblob" && (
          <>
            <label className="flex min-w-[16rem] flex-1 flex-col gap-1 text-xs text-slate-400">
              container URL
              <input
                aria-label="connector-url"
                className={fieldCls}
                placeholder="https://acct.blob.core.windows.net/docs"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  resetTest();
                }}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              SAS
              <input
                aria-label="connector-secret"
                type="password"
                className={fieldCls}
                value={secret}
                onChange={(e) => {
                  setSecret(e.target.value);
                  resetTest();
                }}
              />
            </label>
          </>
        )}
        {kind === "sharepoint" && (
          <>
            <label className="flex min-w-[16rem] flex-1 flex-col gap-1 text-xs text-slate-400">
              site URL
              <input
                aria-label="connector-url"
                className={fieldCls}
                placeholder="https://contoso.sharepoint.com/sites/engineering"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  resetTest();
                }}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              tenant ID
              <input
                aria-label="connector-tenant"
                className={fieldCls}
                placeholder="contoso.onmicrosoft.com"
                value={tenant}
                onChange={(e) => {
                  setTenant(e.target.value);
                  resetTest();
                }}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              client ID
              <input
                aria-label="connector-clientid"
                className={fieldCls}
                placeholder="app registration id"
                value={clientId}
                onChange={(e) => {
                  setClientId(e.target.value);
                  resetTest();
                }}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              client secret
              <input
                aria-label="connector-secret"
                type="password"
                className={fieldCls}
                value={secret}
                onChange={(e) => {
                  setSecret(e.target.value);
                  resetTest();
                }}
              />
            </label>
          </>
        )}
        {kind === "confluence" && (
          <>
            <label className="flex min-w-[16rem] flex-1 flex-col gap-1 text-xs text-slate-400">
              base URL
              <input
                aria-label="connector-url"
                className={fieldCls}
                placeholder="https://acme.atlassian.net/wiki"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  resetTest();
                }}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              space key
              <input
                aria-label="connector-space"
                className={fieldCls}
                placeholder="ENG"
                value={space}
                onChange={(e) => {
                  setSpace(e.target.value);
                  resetTest();
                }}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              account email
              <input
                aria-label="connector-email"
                className={fieldCls}
                placeholder="you@acme.com"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  resetTest();
                }}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              API token
              <input
                aria-label="connector-secret"
                type="password"
                className={fieldCls}
                value={secret}
                onChange={(e) => {
                  setSecret(e.target.value);
                  resetTest();
                }}
              />
            </label>
          </>
        )}
        {kind === "jdbc" && (
          <>
            <label className="flex min-w-[16rem] flex-1 flex-col gap-1 text-xs text-slate-400">
              connection string (DSN)
              <input
                aria-label="connector-secret"
                type="password"
                className={fieldCls}
                placeholder="postgres://user:pass@host:5432/db?sslmode=require"
                value={secret}
                onChange={(e) => {
                  setSecret(e.target.value);
                  resetTest();
                }}
              />
            </label>
            <label className="flex min-w-full flex-col gap-1 text-xs text-slate-400">
              SELECT query
              <textarea
                aria-label="connector-query"
                rows={2}
                className={`${fieldCls} font-mono`}
                placeholder="SELECT id, title, body FROM articles WHERE published"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  resetTest();
                }}
              />
            </label>
          </>
        )}
        {kind === "git" && (
          <p className="w-full text-[11px] text-slate-500">token: for private repos — stored on the controller, never shown again</p>
        )}
        {kind === "sharepoint" && (
          <p className="w-full text-[11px] text-slate-500">
            needs an app registration with the Sites.Selected grant for this site; the floor covers the whole library
          </p>
        )}
        {kind === "confluence" && (
          <p className="w-full text-[11px] text-slate-500">
            uses an Atlassian API token (id.atlassian.com → API tokens) with your account email; the floor covers the whole space
          </p>
        )}
        {kind === "jdbc" && (
          <p className="w-full text-[11px] text-slate-500">
            PostgreSQL or SQLite; the first selected column is the document id, every column becomes the text. Use a read-only account. The DSN is stored write-only.
          </p>
        )}
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1 text-xs text-slate-400">
          collection name
          <input
            aria-label="connector-collection"
            className={fieldCls}
            placeholder={suggestion || "team-share"}
            value={collection}
            onChange={(e) => setCollection(e.target.value)}
          />
        </label>
        <Select label="sync cadence" value={cadence} onChange={setCadence} options={CADENCES} />
      </div>

      <div className="space-y-1.5">
        <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Classification floors</span>
        {floors.map((f, i) => (
          <div key={i} className="flex flex-wrap items-center gap-1.5">
            <input
              aria-label={`floor-prefix-${i}`}
              className={`${fieldCls} w-52`}
              placeholder="docs/finance/"
              value={f.prefix}
              onChange={(e) => setFloors(floors.map((x, j) => (j === i ? { ...x, prefix: e.target.value } : x)))}
            />
            <select
              aria-label={`floor-class-${i}`}
              className={fieldCls}
              value={f.cls}
              onChange={(e) => setFloors(floors.map((x, j) => (j === i ? { ...x, cls: e.target.value } : x)))}
            >
              {CLASSES.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
            <Button size="xs" variant="ghost" title="remove this floor" onClick={() => setFloors(floors.filter((_, j) => j !== i))}>
              ×
            </Button>
          </div>
        ))}
        <div className="flex flex-wrap items-end gap-2">
          <Button size="xs" onClick={() => setFloors([...floors, { prefix: "", cls: "internal" }])}>
            + add floor
          </Button>
          <Select
            label="default floor"
            value={defaultClass}
            onChange={setDefaultClass}
            options={CLASSES.map((c) => ({ value: c, label: c }))}
          />
        </div>
        <p className="text-[11px] text-slate-500">
          Floors set the minimum classification by path prefix — content scanning can only raise it.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2 border-t border-white/5 pt-3">
        <Button onClick={() => void runTest()} disabled={!sourceOk || test === "testing"}>
          Test connection
        </Button>
        {test === "testing" && <span className="text-xs text-sky-300">testing…</span>}
        {test && test !== "testing" &&
          (test.ok ? (
            <Badge tone="ok">✓ reachable{test.detail ? ` — ${test.detail}` : test.files != null ? ` — ${test.files} supported files` : ""}</Badge>
          ) : (
            <span title={test.error ?? ""}>
              <Badge tone="bad">✗ {test.error || test.detail || "unreachable"}</Badge>
            </span>
          ))}
        <span className="ml-auto flex items-center gap-2">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!canConnect} onClick={() => void connect()}>
            {connecting ? "connecting…" : "Connect"}
          </Button>
        </span>
      </div>
      {panelErr && <p className="text-xs text-rose-300">{panelErr}</p>}
      <p className="text-[11px] text-slate-500">Connecting a source is recorded in the audit trail.</p>
    </div>
  );
}

// DatasetsView is where training data comes FROM: live connected sources, connector corpora, and
// uploads. A collection must be ingested (crawl -> classify -> chunk -> embed) before anything can
// train on it — the Training tab only offers what exists here.
export function DatasetsView({ goTab }: { goTab?: (t: string) => void }) {
  const { data, error, refresh } = usePoll<Collections>(api.collections);
  const { data: connectors, refresh: refreshConnectors } = usePoll<ConnectorStatus[]>(() => api.connectors().catch(() => []), 5000);
  const [msg, setMsg] = useState<string | null>(null);
  const [connectOpen, setConnectOpen] = useState(false);
  const [name, setName] = useState("");
  const [docs, setDocs] = useState("");
  const [uploadClass, setUploadClass] = useState("internal");

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setMsg("working…");
    try {
      await fn();
      setMsg(ok);
      await Promise.all([refresh(), refreshConnectors()]);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
  };

  // "Chat over this": mint (or reuse) a RAG alias over the collection on a live base model and
  // hand off to the Playground with that alias pre-selected.
  const chatOver = (collection: string) =>
    run(async () => {
      const models = await api.liveModels();
      const base = (models.find((m) => !m.id.includes("-rag-")) ?? models[0])?.id;
      if (!base) throw new Error("no model is serving yet — deploy one first (Models tab)");
      await api.createAlias(base, collection);
      try {
        localStorage.setItem("dn-playground-model", `${base}-rag-${collection}`);
      } catch {
        /* storage unavailable */
      }
      goTab?.("playground");
    }, `chatting over ${collection}`);

  const ingested = new Set((data?.collections ?? []).map((c) => c.name));
  const sources = (data?.corpora ?? []).filter((c) => !ingested.has(c));
  // Collections owned by a live connector are shown in the Connected sources card, not here.
  const others = (data?.collections ?? []).filter((c) => !KIND_LABEL[c.connector]);
  const classByCollection = new Map((data?.collections ?? []).map((c) => [c.name, c.classification]));

  return (
    <div className="space-y-4">
      <Card
        title="Connected sources — live data"
        info="Real external sources the controller is connected to. The files stay where they live: DANI crawls them incrementally (only changed files are re-read), extracts text (txt/md/code, HTML, PDF, DOCX), classifies at ingest by path-prefix floors + content scan, and indexes chunks for RAG and training. Sync now pulls the latest changes; deletions in the source remove their chunks. Sources marked with a lock are configured by controller flags and can only be removed there."
        actions={
          <>
            <Toast msg={msg} />
            <Button variant={connectOpen ? "default" : "primary"} onClick={() => setConnectOpen((v) => !v)}>
              {connectOpen ? "Close" : "+ Connect a source"}
            </Button>
          </>
        }
      >
        {connectOpen && (
          <ConnectPanel
            onCancel={() => setConnectOpen(false)}
            onDone={async () => {
              setConnectOpen(false);
              setMsg("connected — first sync starting…");
              await Promise.all([refresh(), refreshConnectors()]);
            }}
          />
        )}
        {(connectors ?? []).length === 0 && !connectOpen && (
          <p className="text-sm text-slate-400">
            No live sources connected yet — click <span className="text-slate-200">+ Connect a source</span> to point DANI at a folder, a
            git repository, or an Azure Blob container.
          </p>
        )}
        <div className="space-y-2">
          {(connectors ?? []).map((c) => {
            const col = c.def.collection;
            const cls = classByCollection.get(col) ?? c.def.defaultClass ?? "internal";
            return (
              <div key={col} className="flex flex-wrap items-center gap-2 text-sm">
                <Badge tone="ok">{KIND_LABEL[c.def.kind] ?? c.def.kind}</Badge>
                <span className="font-mono text-xs text-slate-200" title={c.def.path || c.def.url || ""}>
                  {col}
                </span>
                <Badge tone={stateTone(cls)}>{cls}</Badge>
                <span className="text-xs text-slate-400">
                  {c.docs} docs · {c.chunks} chunks
                </span>
                {c.syncing ? (
                  <span className="animate-pulse text-xs text-emerald-300">syncing…</span>
                ) : (
                  <span className="text-xs text-slate-500" title={c.lastSync.startsWith("0001-") ? "never synced" : c.lastSync}>
                    {relTime(c.lastSync)}
                  </span>
                )}
                {c.lastError && (
                  <span title={c.lastError}>
                    <Badge tone="warn">sync error</Badge>
                  </span>
                )}
                {(c.lastChanged > 0 || c.lastGone > 0) && (
                  <span className="text-[11px] tabular-nums text-slate-500" title="docs added/updated and removed in the last sync">
                    {c.lastChanged > 0 && <span className="text-emerald-400/90">+{c.lastChanged}</span>}
                    {c.lastChanged > 0 && c.lastGone > 0 && " "}
                    {c.lastGone > 0 && <span className="text-rose-400/90">−{c.lastGone}</span>}
                  </span>
                )}
                <span className="ml-auto flex items-center gap-1">
                  <Button size="xs" variant="primary" onClick={() => run(() => api.ingest(col), `synced ${col}`)} disabled={c.syncing}>
                    ⟳ Sync now
                  </Button>
                  <Button size="xs" onClick={() => void chatOver(col)} title="Create a RAG alias over this source and open the Playground">
                    💬 Chat over this
                  </Button>
                  {c.def.static ? (
                    <span className="px-1 text-sm text-slate-500" title="configured by controller flags" aria-label="static connector">
                      🔒
                    </span>
                  ) : (
                    <ConfirmButton onConfirm={() => run(() => api.connectorDelete(col), `disconnected ${col}`)}>Disconnect</ConfirmButton>
                  )}
                </span>
              </div>
            );
          })}
        </div>
      </Card>

      <Card
        title="Ingested collections"
        info="Datasets that went through the ingest pipeline: crawl → classify-at-ingest (source class raised by content scan) → chunk → embed → index. The classification shown is the dataset's ceiling — an engineer needs at least that clearance to train on it, and models trained on it inherit it."
      >
        {error && <p className="text-sm text-rose-300">{error}</p>}
        {data && others.length === 0 && (
          <p className="text-sm text-slate-400">Nothing ingested yet — ingest a source below to begin.</p>
        )}
        <div className="space-y-1">
          {others.map((c) => (
            <div key={c.name} className="flex flex-wrap items-center gap-2 text-sm">
              <span className="font-mono text-xs text-slate-200">{c.name}</span>
              <Badge tone={stateTone(c.classification)}>{c.classification}</Badge>
              <span className="text-xs text-slate-400">
                {c.chunks} chunks · via {c.connector}
              </span>
            </div>
          ))}
        </div>
      </Card>

      <Card
        title="Available sources"
        info="Synthetic demo corpora plus anything you uploaded. Click ingest to pull one through the pipeline; re-ingesting refreshes it. Live folder / git / Azure-Blob sources connect and sync in Connected sources above."
      >
        {sources.length === 0 && <p className="text-sm text-slate-400">Every known source is ingested.</p>}
        <div className="flex flex-wrap gap-2">
          {sources.map((c) => (
            <Button key={c} variant="primary" onClick={() => run(() => api.ingest(c), `ingested ${c}`)}>
              Ingest {c}
            </Button>
          ))}
          {others.map((c) => (
            <Button key={c.name} onClick={() => run(() => api.ingest(c.name), `re-ingested ${c.name}`)}>
              Re-ingest {c.name}
            </Button>
          ))}
        </div>
      </Card>

      <Card
        title="Upload a dataset"
        info="Pick text files or paste documents (one per line) to register a custom corpus and ingest it immediately. Pick the source classification honestly — the content scan can RAISE it (a document mentioning revenue/risk classifies restricted) but never lower it. The upload is recorded in the audit trail with your operator identity."
      >
        <div className="space-y-2">
          <div className="flex flex-wrap items-end gap-2">
            <label className="flex flex-col text-xs text-slate-400">
              collection name
              <input aria-label="upload-name" className={fieldCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="contracts-2026" />
            </label>
            <label className="flex flex-col text-xs text-slate-400">
              source classification
              <select aria-label="upload-class" className={fieldCls} value={uploadClass} onChange={(e) => setUploadClass(e.target.value)}>
                {CLASSES.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </label>
            <Button
              variant="primary"
              disabled={!name.trim() || !docs.trim()}
              onClick={() =>
                run(async () => {
                  await api.upload(
                    name.trim(),
                    docs.split("\n").map((d) => d.trim()).filter(Boolean),
                    uploadClass,
                  );
                  setName("");
                  setDocs("");
                }, `uploaded + ingested ${name.trim()}`)
              }
            >
              Upload &amp; ingest
            </Button>
          </div>
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            pick text files (each line becomes a document)
            <input
              aria-label="upload-files"
              type="file"
              multiple
              accept=".txt,.md,.csv,text/plain"
              className="text-xs text-slate-400 file:mr-2 file:rounded-md file:border-0 file:bg-white/10 file:px-2 file:py-1 file:text-xs file:text-slate-200 hover:file:bg-white/20"
              onChange={async (e) => {
                const files = Array.from(e.target.files ?? []);
                if (files.length === 0) return;
                const texts = await Promise.all(files.map((f) => f.text()));
                const lines = texts.join("\n").replace(/\r/g, "");
                setDocs((d) => (d.trim() ? d + "\n" + lines : lines));
                if (!name.trim() && files[0]) setName(files[0].name.replace(/\.[^.]+$/, ""));
                e.target.value = "";
              }}
            />
          </label>
          <textarea
            aria-label="upload-docs"
            className={`${fieldCls} h-28 w-full font-mono text-xs`}
            placeholder={"…or paste documents, one per line\nThe renewal clause fixes pricing for 24 months.\nTermination requires 90 days written notice."}
            value={docs}
            onChange={(e) => setDocs(e.target.value)}
          />
        </div>
      </Card>
    </div>
  );
}
