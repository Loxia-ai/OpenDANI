import { useState } from "react";
import { api } from "./api";
import { AuditView } from "./components/AuditView";
import { DatasetsView } from "./components/DatasetsView";
import { FleetView } from "./components/FleetView";
import { ModelsView } from "./components/ModelsView";
import { ApiAccessCard, HelpDrawer } from "./components/HelpBits";
import { NodesView } from "./components/NodesView";
import { PlaygroundView } from "./components/PlaygroundView";
import { TopologyView } from "./components/TopologyView";
import { TrainView } from "./components/TrainView";
import { Badge, Button, Card, PageHeader, fieldCls } from "./components/ui";
import { SessionProvider, useSession } from "./session";
import { usePoll } from "./usePoll";

const TABS = [
  { id: "overview", label: "Overview", blurb: "Is the network healthy? The live fleet and the tamper-evident audit verdict at a glance." },
  { id: "playground", label: "Playground", blurb: "Talk to a model the fleet is serving — the same gateway your applications use, with the routing proof on every answer." },
  { id: "topology", label: "Topology", blurb: "The DANI network as an interactive graph — controller hub, enrolled nodes, live traffic, and the WireGuard overlay. Drag, zoom, and pan." },
  { id: "nodes", label: "Nodes", blurb: "Manage the fleet: approve pending joins, drain nodes for maintenance, revoke compromised ones, and watch certificate renewal status." },
  { id: "datasets", label: "Datasets", blurb: "Where training data comes from: ingest a connector corpus or upload your own. Everything is classified at ingest." },
  { id: "training", label: "Training", blurb: "Fine-tune a model on an ingested dataset. AuthZ runs first; job progress and evals stream live." },
  { id: "registry", label: "Models", blurb: "The governed catalogue: three-signer promotion, distribution across nodes, and RAG aliases." },
  { id: "audit", label: "Audit", blurb: "The tamper-evident history of every governance action, in plain language, exportable for offline verification." },
] as const;
type TabId = (typeof TABS)[number]["id"];

export function App() {
  return (
    <SessionProvider>
      <Shell />
    </SessionProvider>
  );
}

function Shell() {
  const [tab, setTab] = useState<TabId>("overview");
  const [help, setHelp] = useState(false);
  const { error: healthErr } = usePoll(api.health, 5000);
  const active = TABS.find((t) => t.id === tab)!;
  return (
    <div className="min-h-screen bg-transparent text-slate-100">
      <header className="sticky top-0 z-20 border-b border-white/10 bg-black/70 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center gap-3 px-4 py-2.5 sm:px-6">
          <div className="flex shrink-0 items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-500 shadow-[0_0_10px_2px_rgba(118,185,0,0.7)]" aria-hidden />
            <span className="font-display text-lg font-bold tracking-tight text-white">DANI</span>
            <span className="hidden text-xs text-slate-500 sm:inline">control console</span>
          </div>
          <nav className="flex min-w-0 flex-1 gap-1 overflow-x-auto" role="tablist" aria-label="sections">
            {TABS.map((t) => (
              <button
                key={t.id}
                role="tab"
                aria-selected={tab === t.id}
                onClick={() => setTab(t.id)}
                className={`shrink-0 rounded-md px-3 py-1.5 text-sm transition ${
                  tab === t.id
                    ? "bg-emerald-500/15 text-white ring-1 ring-inset ring-emerald-500/30"
                    : "text-slate-400 hover:bg-white/5 hover:text-slate-200"
                }`}
              >
                {t.label}
              </button>
            ))}
          </nav>
          <div className="flex shrink-0 items-center gap-1">
            <button
              aria-label="help"
              title="How DANI works"
              onClick={() => setHelp(true)}
              className="flex h-7 w-7 items-center justify-center rounded-full text-sm text-slate-400 transition hover:bg-white/10 hover:text-white"
            >
              ?
            </button>
            <SessionBox />
          </div>
        </div>
      </header>
      {healthErr && (
        <div role="alert" className="border-b border-rose-500/30 bg-rose-500/10 px-4 py-2 text-center text-sm text-rose-200">
          Can't reach the DANI controller — the data below may be stale. Retrying…
        </div>
      )}
      <HelpDrawer open={help} onClose={() => setHelp(false)} goTab={(t) => setTab(t as TabId)} />

      <main className="mx-auto max-w-7xl space-y-4 px-4 py-6 sm:px-6">
        <PageHeader title={active.label} blurb={active.blurb} />
        {tab === "overview" && (
          <>
            <Stepper go={setTab} />
            <FleetView />
            <ApiAccessCard />
            <AuditView />
          </>
        )}
        {tab === "playground" && <PlaygroundView />}
        {tab === "topology" && <TopologyView />}
        {tab === "nodes" && <NodesView />}
        {tab === "datasets" && <DatasetsView goTab={(t) => setTab(t as TabId)} />}
        {tab === "training" && (
          <>
            <TrainView />
            <ModelsView />
          </>
        )}
        {tab === "registry" && <ModelsView />}
        {tab === "audit" && <AuditView />}
      </main>
    </div>
  );
}

// SessionBox shows who is driving the console. Auth-off (the DEMO default) is stated, not hidden.
function SessionBox() {
  const s = useSession();
  const [editing, setEditing] = useState(false);
  const [tok, setTok] = useState("");
  if (!s.who) return null;
  if (!s.who.authEnabled) {
    return (
      <span className="hidden text-xs text-slate-500 sm:inline" title="Start the controller with --console-auth to require operator sign-in">
        anonymous
      </span>
    );
  }
  if (s.who.sub && !s.who.error) {
    return (
      <span className="flex items-center gap-2 text-xs">
        <Badge tone="ok">{s.who.sub}</Badge>
        <span className="hidden text-slate-400 sm:inline">{(s.who.roles ?? []).filter((r) => r !== "user").join(", ") || "user"}</span>
        <Button variant="ghost" onClick={s.signOut}>
          Sign out
        </Button>
      </span>
    );
  }
  // SSO available: the primary path is a redirect to the IdP; a token stays available for service use
  if (s.who.sso) {
    return editing ? (
      <span className="flex items-center gap-1">
        <input aria-label="operator token" className={`${fieldCls} w-40`} placeholder="service token" type="password" value={tok} onChange={(e) => setTok(e.target.value)} />
        <Button variant="primary" onClick={() => { s.signIn(tok); setTok(""); setEditing(false); }}>Use token</Button>
      </span>
    ) : (
      <span className="flex items-center gap-1">
        <Button variant="primary" onClick={s.ssoLogin}>Sign in with SSO</Button>
        <button className="text-[11px] text-slate-500 hover:text-slate-300" onClick={() => setEditing(true)} title="Use a service token instead of SSO">
          token
        </button>
      </span>
    );
  }
  // token-only auth (no IdP configured)
  return editing ? (
    <span className="flex items-center gap-1" title="Your administrator hands you this token (generated at controller start into console-operators.json). It identifies you and unlocks the actions your roles allow.">
      <input aria-label="operator token" className={`${fieldCls} w-40`} placeholder="paste token — ask your admin" type="password" value={tok} onChange={(e) => setTok(e.target.value)} />
      <Button
        variant="primary"
        onClick={() => {
          s.signIn(tok);
          setTok("");
          setEditing(false);
        }}
      >
        Sign in
      </Button>
    </span>
  ) : (
    <Button variant="primary" onClick={() => setEditing(true)}>
      Sign in
    </Button>
  );
}

// Stepper is the empty-state guide: it reads the live system and points at the NEXT step of the
// dataset → train → sign → serve story, then disappears once a model is serving.
function Stepper({ go }: { go: (t: TabId) => void }) {
  const { data: cols } = usePoll(() => api.collections().catch(() => null), 8000);
  const { data: models } = usePoll(() => api.models().catch(() => []), 8000);
  if (!cols || !models) return null;
  const hasData = (cols.collections ?? []).length > 0;
  const serving = models.some((m) => (m.deployments ?? []).some((d) => d.state === "loaded") || m.deployment?.state === "loaded");
  if (serving) return null;
  const steps: { label: string; done: boolean; tab: TabId }[] = [
    { label: "1 · Ingest a dataset", done: hasData, tab: "datasets" },
    { label: "2 · Train a fine-tune", done: models.length > 0, tab: "training" },
    { label: "3 · Collect 3 signatures", done: models.some((m) => m.state === "available"), tab: "registry" },
    { label: "4 · Serves automatically", done: false, tab: "registry" },
  ];
  const next = steps.find((st) => !st.done);
  return (
    <Card title="Getting started" info="The whole DANI story: classified data in, governed model out. Each step gates the next — nothing trains without an ingested dataset, and nothing serves without three signatures and a passing safety gate.">
      <div className="flex flex-wrap items-center gap-2">
        {steps.map((st) => (
          <button
            key={st.label}
            onClick={() => go(st.tab)}
            className={`rounded-md px-2.5 py-1 text-xs transition ${
              st.done
                ? "bg-emerald-500/10 text-emerald-300"
                : st === next
                  ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/40"
                  : "bg-white/5 text-slate-500"
            }`}
          >
            {st.done ? "✓ " : ""}
            {st.label}
          </button>
        ))}
      </div>
    </Card>
  );
}
