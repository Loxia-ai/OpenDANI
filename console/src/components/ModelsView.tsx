import { useState } from "react";
import { api, REVIEWER_ROLES, type Collections, type Model, type Node, type Principal } from "../api";
import { useSession } from "../session";
import { usePoll } from "../usePoll";
import { Badge, Button, Card, ConfirmButton, Select, stateTone } from "./ui";

// ModelsView is the governed catalogue: lifecycle state, the 3-signer promotion ceremony, and —
// once promoted — WHERE the model serves (replicas, pinning, undeploy) plus RAG aliases over it.
export function ModelsView() {
  const { data, error, refresh } = usePoll(api.models);
  const { data: nodes } = usePoll<Node[]>(() => api.nodes().catch(() => []), 8000);
  const { data: cols } = usePoll<Collections>(api.collections, 10000);
  const { data: principals } = usePoll<Principal[]>(() => api.principals().catch(() => []), 30000);
  const session = useSession();
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const act = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(key);
    setMsg(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const liveWorkers = (nodes ?? []).filter((n) => n.live && !n.trainer && n.lifecycle !== "revoked" && !n.drained);

  return (
    <Card
      title="Model registry — 3-signer promotion"
      info="Every model DANI may serve, with its lifecycle: a training candidate arrives as a DRAFT; each reviewer (Security, Governance, Administrator) adds a cryptographic signature; with all three — and the quality/safety gate passing — it becomes AVAILABLE and auto-deploys. Signing is per-role: with console auth on, you can only sign as the role your identity holds. Expand a model for its lineage (which dataset, whose job), artifact hash, evals, and distribution controls."
      actions={msg && <span className="max-w-[50%] truncate text-xs text-rose-300">{msg}</span>}
    >
      {error && <p className="text-sm text-rose-300">{error}</p>}
      {!error && data && data.length === 0 && <p className="text-sm text-slate-400">No models yet. Train one to begin.</p>}
      <div className="space-y-3">
        {data?.map((m: Model) => {
          const signed = new Set(m.signatures);
          const placements = m.deployments ?? (m.deployment ? [m.deployment] : []);
          const loadedCount = placements.filter((d) => d.state === "loaded").length;
          const underReplicated = m.state === "available" && !!m.lineage && loadedCount < (m.replicas ?? 1);
          const expanded = open === m.id;
          return (
            <div key={m.id} className="rounded-lg border border-white/5 bg-black/20 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  aria-label={`expand ${m.id}`}
                  className="text-xs text-slate-500 hover:text-slate-300"
                  onClick={() => setOpen(expanded ? null : m.id)}
                >
                  {expanded ? "▾" : "▸"}
                </button>
                <span className="font-mono text-sm text-slate-100">{m.id}</span>
                <Badge tone={stateTone(m.state)}>{m.state}</Badge>
                <Badge tone="muted">{m.classification}</Badge>
                {m.gate_failed && <Badge tone="bad">gate: {m.gate_failed}</Badge>}
                {underReplicated && (
                  <span title="pinned replicas exceed the number of nodes currently serving it (§6.17.15)">
                    <Badge tone="warn">under-replicated {loadedCount}/{m.replicas}</Badge>
                  </span>
                )}
                {placements.map((d) => (
                  <Badge key={d.node} tone="info">
                    serving @ {d.node} ({d.state})
                  </Badge>
                ))}
                {m.evals?.safety !== undefined && (
                  <span className="text-xs text-slate-400">safety {m.evals.safety.toFixed(2)}</span>
                )}
              </div>

              {m.state === "draft" && (
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <span className="text-xs text-slate-400">signatures {m.signatures.length}/3:</span>
                  {/* who still needs to act — turns "waiting" into a name to chase */}
                  {(() => {
                    const missing = REVIEWER_ROLES.filter((r) => !signed.has(r));
                    if (missing.length === 0 || !principals?.length) return null;
                    const who = missing
                      .map((r) => {
                        const holders = principals.filter((p) => p.roles.includes(r)).map((p) => p.sub);
                        return holders.length ? `${r} (${holders.join("/")})` : r;
                      })
                      .join(", ");
                    return <span className="w-full text-xs text-slate-500">waiting for: {who}</span>;
                  })()}
                  {REVIEWER_ROLES.map((role) => {
                    const allowed = session.hasRole(role);
                    return (
                      <Button
                        key={role}
                        variant={signed.has(role) ? "default" : "primary"}
                        disabled={signed.has(role) || busy === `${m.id}:${role}` || !allowed}
                        title={allowed ? undefined : `your identity does not hold the ${role} role`}
                        onClick={() => act(`${m.id}:${role}`, () => api.sign(m.id, role))}
                      >
                        {signed.has(role) ? `✓ ${role}` : allowed ? `sign ${role}` : `🔒 ${role}`}
                      </Button>
                    );
                  })}
                </div>
              )}

              {expanded && (
                <div className="mt-3 space-y-3 border-t border-white/5 pt-3 text-sm">
                  <div className="grid grid-cols-1 gap-1 text-xs text-slate-400 sm:grid-cols-2">
                    {m.base && (
                      <span>
                        base: <span className="font-mono text-slate-300">{m.base}</span>
                      </span>
                    )}
                    {m.hash && (
                      <span>
                        artifact: <span className="font-mono text-slate-300">{m.hash}</span>
                      </span>
                    )}
                    {m.engine && <span>engine: {m.engine}</span>}
                    {m.lineage && (
                      <span>
                        lineage: trained on <span className="font-mono text-slate-300">{String(m.lineage.Collection ?? m.lineage.DatasetID ?? "?")}</span>
                        {m.lineage.Engineer ? ` by ${String(m.lineage.Engineer)}` : ""}
                      </span>
                    )}
                    {m.evals &&
                      Object.entries(m.evals).map(([k, v]) => (
                        <span key={k}>
                          eval {k}: {v.toFixed(3)}
                        </span>
                      ))}
                  </div>

                  {m.state === "available" && m.lineage && (
                    <div className="flex flex-wrap items-end gap-2">
                      <span className="text-xs uppercase text-slate-500">distribution</span>
                      <Button
                        disabled={busy === `${m.id}:scale+`}
                        onClick={() => act(`${m.id}:scale+`, () => api.deploy(m.id, { replicas: (m.replicas ?? 1) + 1 }))}
                      >
                        + replica ({m.replicas ?? 1})
                      </Button>
                      <Button
                        disabled={(m.replicas ?? 1) <= 1 || busy === `${m.id}:scale-`}
                        onClick={() => act(`${m.id}:scale-`, () => api.deploy(m.id, { replicas: (m.replicas ?? 1) - 1 }))}
                      >
                        − replica
                      </Button>
                      <PinPicker
                        nodes={liveWorkers.filter((n) => !placements.some((p) => p.node === n.uuid))}
                        onPin={(node) => act(`${m.id}:pin`, () => api.deploy(m.id, { node }))}
                      />
                      {placements.map((d) => (
                        <Button key={d.node} disabled={busy === `${m.id}:un:${d.node}`} onClick={() => act(`${m.id}:un:${d.node}`, () => api.undeploy(m.id, d.node))}>
                          undeploy @ {d.node}
                        </Button>
                      ))}
                      <ConfirmButton onConfirm={() => act(`${m.id}:park`, () => api.undeploy(m.id))}>park (undeploy all)</ConfirmButton>
                    </div>
                  )}

                  {m.state === "available" && (
                    <AliasMaker model={m} collections={cols} onDone={refresh} />
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
      <AliasList />
    </Card>
  );
}

function PinPicker({ nodes, onPin }: { nodes: Node[]; onPin: (node: string) => void }) {
  const [node, setNode] = useState("");
  if (nodes.length === 0) return null;
  return (
    <span className="flex items-end gap-1">
      <Select
        label="pin to node"
        value={node}
        onChange={setNode}
        options={[{ value: "", label: "—" }, ...nodes.map((n) => ({ value: n.uuid, label: n.uuid }))]}
      />
      <Button disabled={!node} onClick={() => node && onPin(node)}>
        Pin
      </Button>
    </span>
  );
}

// AliasMaker registers a RAG-compound alias (<model>-rag-<collection>): the model answers with
// retrieval over the chosen classified collection, citations included.
function AliasMaker({ model, collections, onDone }: { model: Model; collections: Collections | null; onDone: () => void }) {
  const [col, setCol] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const opts = (collections?.collections ?? []).map((c) => ({ value: c.name, label: c.name }));
  if (opts.length === 0) return null;
  const chosen = col || opts[0].value;
  return (
    <div className="flex flex-wrap items-end gap-2">
      <span className="text-xs uppercase text-slate-500">rag</span>
      <Select label="answer with retrieval over" value={chosen} onChange={setCol} options={opts} />
      <Button
        onClick={async () => {
          try {
            await api.createAlias(model.id, chosen);
            setNote(`alias ${model.id}-rag-${chosen} registered`);
            onDone();
          } catch (e) {
            setNote(e instanceof Error ? e.message : String(e));
          }
        }}
      >
        + RAG alias
      </Button>
      {note && <span className="text-xs text-sky-300">{note}</span>}
    </div>
  );
}

function AliasList() {
  const { data: aliases } = usePoll(() => api.aliases().catch(() => []), 10000);
  if (!aliases || aliases.length === 0) return null;
  return (
    <div className="mt-3 border-t border-white/5 pt-2">
      <span className="text-xs uppercase text-slate-500">rag aliases</span>
      <div className="mt-1 flex flex-wrap gap-2">
        {aliases.map((a) => (
          <Badge key={a.Alias} tone="info">
            {a.Alias}
          </Badge>
        ))}
      </div>
    </div>
  );
}
