import { useMemo, useState } from "react";
import { api, type ConfigEntry, type Node, type PendingJoin } from "../api";
import { usePoll } from "../usePoll";
import { Badge, Button, Card, ConfirmButton, EmptyState, InfoTip, Mono, Stat, Table, Td, Th, Toast, Tr, fieldCls, stateTone } from "./ui";

// Renewal-status view (DL-R11.2-05): the controller holds each cert's expiry; we bucket it into the
// four spec states so nodes sliding toward expiry are an early unreachability signal.
function renewal(certExpiry: string): { label: string; tone: string; days: number } {
  const d = new Date(certExpiry);
  const days = isNaN(d.getTime()) ? NaN : Math.round((d.getTime() - Date.now()) / 86400000);
  if (isNaN(days)) return { label: "unknown", tone: "muted", days: NaN };
  if (days < 0) return { label: "expired", tone: "bad", days };
  if (days < 7) return { label: "grace-overdue", tone: "bad", days };
  if (days < 30) return { label: "renewal-due", tone: "warn", days };
  return { label: "healthy", tone: "ok", days };
}

// Config store keys behind the resource budget.
const K_CORES = "worker.max-cores";
const K_MEM = "worker.max-model-mem-mb";

// The cores selector offers Auto + a sane set of powers/steps.
const CORE_OPTS = [0, 1, 2, 4, 8, 16, 32];
const coreLabel = (n: number) => (n === 0 ? "Auto" : `${n} core${n === 1 ? "" : "s"}`);
const memLabel = (mb: number) => (mb > 0 ? `${mb} MB` : "unbounded");

// Tone by cap mode: full = using the whole box (info/cyan), polite = leaving headroom (muted),
// custom = an explicit operator override (ok/green).
function capTone(mode: string): string {
  if (mode === "full") return "info";
  if (mode === "custom") return "ok";
  return "muted"; // polite / unknown
}

// A node's effective budget, from its live heartbeat (undefined when offline / not in the fleet).
interface Budget {
  mode: string;
  cores: number;
  memMB: number;
}

// budgetLabel renders e.g. "custom · 2 cores · 4096 MB" or "polite · 1 core · unbounded".
function budgetLabel(b: Budget): string {
  return `${b.mode} · ${coreLabel(b.cores)} · ${memLabel(b.memMB)}`;
}

const CORE_SELECT_OPTS = [
  ...CORE_OPTS.map((c) => ({ value: String(c), label: coreLabel(c) })),
  { value: "all", label: "All (dedicated)" }, // this machine belongs to DANI — take every core
];

// Small inline cores + memory editor, shared by the per-node row, the group bar, and the
// fleet/site defaults. Emits Apply (cores, mem) and, when resettable, Reset (clear override).
function BudgetEditor({
  cores,
  mem,
  onCores,
  onMem,
  onApply,
  onReset,
  applyLabel = "Apply",
  disabled,
  confirmApply,
  compact,
}: {
  cores: string;
  mem: string;
  onCores: (v: string) => void;
  onMem: (v: string) => void;
  onApply: () => void;
  onReset?: () => void;
  applyLabel?: string;
  disabled?: boolean;
  confirmApply?: boolean;
  compact?: boolean;
}) {
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      <select aria-label="cores" className={fieldCls} value={cores} onChange={(e) => onCores(e.target.value)} disabled={disabled}>
        {CORE_SELECT_OPTS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <input
        aria-label="memory budget (MB)"
        type="number"
        min={0}
        step={256}
        placeholder="mem MB (0=auto)"
        className={`${fieldCls} ${compact ? "w-28" : "w-32"}`}
        value={mem}
        onChange={(e) => onMem(e.target.value)}
        disabled={disabled}
      />
      {confirmApply ? (
        <ConfirmButton onConfirm={onApply} disabled={disabled}>
          {applyLabel}
        </ConfirmButton>
      ) : (
        <Button variant="primary" onClick={onApply} disabled={disabled}>
          {applyLabel}
        </Button>
      )}
      {onReset && (
        <Button variant="ghost" onClick={onReset} disabled={disabled} title="Clear this override — revert to the inherited value">
          Reset
        </Button>
      )}
    </span>
  );
}

export function NodesView() {
  const { data: nodes, error, refresh } = usePoll(api.nodes);
  const { data: fleet, refresh: refreshFleet } = usePoll(api.fleet);
  const { data: cfg, refresh: refreshConfig } = usePoll(api.config, 8000);
  const { data: pending, refresh: refreshPending } = usePoll<PendingJoin[]>(() => api.pending().catch(() => []), 5000);
  const [msg, setMsg] = useState<string | null>(null);

  // Per-node draft edits (uuid -> {cores, mem}); the group bar and fleet/site defaults keep their own.
  const [rowDraft, setRowDraft] = useState<Record<string, { cores: string; mem: string }>>({});
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [group, setGroup] = useState({ cores: "0", mem: "" });
  const [fleetDraft, setFleetDraft] = useState({ cores: "0", mem: "" });
  const [siteDraft, setSiteDraft] = useState<Record<string, { cores: string; mem: string }>>({});

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setMsg("working…");
    try {
      await fn();
      setMsg(ok);
      // A write can change caps + lifecycle; refresh every source so the badge updates within a poll.
      await Promise.all([refresh(), refreshFleet(), refreshConfig(), refreshPending()]);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
  };

  // Merge the live fleet's effective budget onto each enrolled node by UUID.
  const budgetByUuid = useMemo(() => {
    const m = new Map<string, Budget>();
    for (const w of fleet?.workers ?? []) {
      m.set(w.UUID, { mode: w.CapMode || "polite", cores: w.MaxCores ?? 0, memMB: w.MemBudgetMB ?? 0 });
    }
    return m;
  }, [fleet]);

  // Which scopes have an explicit override set — so the operator can see (and Reset) them.
  const overrides = useMemo(() => {
    const node = new Set<string>();
    const site = new Set<string>();
    let fleetSet = false;
    for (const e of cfg?.entries ?? ([] as ConfigEntry[])) {
      if (e.key !== K_CORES && e.key !== K_MEM) continue;
      if (e.scope === "node") node.add(e.scopeVal);
      else if (e.scope === "site") site.add(e.scopeVal);
      else if (e.scope === "fleet") fleetSet = true;
    }
    return { node, site, fleetSet };
  }, [cfg]);

  const sites = useMemo(() => {
    const s = new Set<string>();
    for (const n of nodes ?? []) if (n.site) s.add(n.site);
    return [...s].sort();
  }, [nodes]);

  const live = (nodes ?? []).filter((n) => n.live && n.lifecycle !== "revoked").length;
  const drained = (nodes ?? []).filter((n) => n.drained).length;
  const dueSoon = (nodes ?? []).filter((n) => ["renewal-due", "grace-overdue", "expired"].includes(renewal(n.certExpiry).label)).length;

  const selectedUuids = (nodes ?? []).filter((n) => selected[n.uuid] && n.lifecycle !== "revoked").map((n) => n.uuid);

  // "all" passes through verbatim (a dedicated machine — the store validates it); numbers are cleaned.
  const coreValue = (v: string): string | number => (v === "all" ? "all" : parseInt(v || "0", 10) || 0);

  // Write a cores + mem pair to a scope (skips the field left blank so "just cores" or "just mem" work).
  const writePair = async (scope: string, scopeVal: string, cores: string, mem: string, ok: string) => {
    await run(async () => {
      await api.setConfig(scope, scopeVal, K_CORES, coreValue(cores));
      if (mem.trim() !== "") await api.setConfig(scope, scopeVal, K_MEM, parseInt(mem, 10) || 0);
    }, ok);
  };

  const draftFor = (uuid: string, b?: Budget) => rowDraft[uuid] ?? { cores: String(b?.cores ?? 0), mem: b && b.memMB > 0 ? String(b.memMB) : "" };

  const applyGroup = () =>
    run(async () => {
      for (const u of selectedUuids) {
        await api.setConfig("node", u, K_CORES, coreValue(group.cores));
        if (group.mem.trim() !== "") await api.setConfig("node", u, K_MEM, parseInt(group.mem, 10) || 0);
      }
    }, `applied budget to ${selectedUuids.length} node${selectedUuids.length === 1 ? "" : "s"}`);

  return (
    <div className="space-y-4">
      {pending && pending.length > 0 && (
        <Card
          title={`Pending joins — ${pending.length} awaiting approval`}
          info="Nodes that passed the enrollment handshake and are waiting in the pending-join queue for a Security Officer's decision (Mode-2 batch-confirm; controller flag --admit manual). They advertise what they DECLARE — the operator assigns the actual role/class on approval. Reject refuses the join."
        >
          <div className="space-y-1.5">
            {pending.map((p) => (
              <div key={p.reqId} className="flex flex-wrap items-center gap-2 rounded-lg border border-amber-500/20 bg-amber-500/[0.04] px-3 py-2 text-sm">
                <Mono>{p.nodeUuid}</Mono>
                <Badge tone="warn">wants {p.declaredRoles.join("+") || "worker"}</Badge>
                <Badge tone="muted">{p.declaredClass}</Badge>
                <span className="ml-auto flex gap-1">
                  <Button variant="primary" onClick={() => run(() => api.approve(p.reqId), `approved ${p.nodeUuid}`)}>
                    Approve
                  </Button>
                  <Button onClick={() => run(() => api.reject(p.reqId, "rejected by operator"), `rejected ${p.nodeUuid}`)}>Reject</Button>
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card
        title="Resource budget"
        info="How much CPU / model-memory DANI may use on each node. Precedence is node > site > fleet: a node override wins over its site's default, which wins over the fleet default. 0 / Auto means DANI auto-picks — full inside a container, polite (leaves headroom) on a bare host. The number shown on each row is the EFFECTIVE value the node is actually using, from its heartbeat. Writes are audited and validated server-side."
        subtitle="Set a fleet-wide default, or per site, then override individual nodes below."
        actions={<Toast msg={msg} />}
      >
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2">
            <span className="text-xs font-medium uppercase tracking-wide text-slate-400">Fleet default</span>
            {overrides.fleetSet && <Badge tone="ok">override set</Badge>}
            <span className="ml-auto flex items-center gap-1.5">
              <BudgetEditor
                cores={fleetDraft.cores}
                mem={fleetDraft.mem}
                onCores={(v) => setFleetDraft((d) => ({ ...d, cores: v }))}
                onMem={(v) => setFleetDraft((d) => ({ ...d, mem: v }))}
                confirmApply
                applyLabel="Set fleet default"
                onApply={() => writePair("fleet", "", fleetDraft.cores, fleetDraft.mem, "set fleet default")}
                onReset={
                  overrides.fleetSet
                    ? () =>
                        run(async () => {
                          await api.clearConfig("fleet", "", K_CORES);
                          await api.clearConfig("fleet", "", K_MEM);
                        }, "cleared fleet default")
                    : undefined
                }
              />
            </span>
          </div>

          {sites.length > 0 &&
            sites.map((s) => {
              const d = siteDraft[s] ?? { cores: "0", mem: "" };
              return (
                <div key={s} className="flex flex-wrap items-center gap-2 rounded-lg border border-white/5 bg-white/[0.015] px-3 py-2">
                  <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Site</span>
                  <Mono>{s}</Mono>
                  {overrides.site.has(s) && <Badge tone="ok">override set</Badge>}
                  <span className="ml-auto flex items-center gap-1.5">
                    <BudgetEditor
                      compact
                      cores={d.cores}
                      mem={d.mem}
                      onCores={(v) => setSiteDraft((m) => ({ ...m, [s]: { ...d, cores: v } }))}
                      onMem={(v) => setSiteDraft((m) => ({ ...m, [s]: { ...d, mem: v } }))}
                      confirmApply
                      applyLabel="Set site default"
                      onApply={() => writePair("site", s, d.cores, d.mem, `set default for site ${s}`)}
                      onReset={
                        overrides.site.has(s)
                          ? () =>
                              run(async () => {
                                await api.clearConfig("site", s, K_CORES);
                                await api.clearConfig("site", s, K_MEM);
                              }, `cleared default for site ${s}`)
                          : undefined
                      }
                    />
                  </span>
                </div>
              );
            })}

          {selectedUuids.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 rounded-lg border border-emerald-500/25 bg-emerald-500/[0.05] px-3 py-2">
              <span className="text-xs font-medium text-emerald-200">Apply to {selectedUuids.length} selected</span>
              <span className="ml-auto flex items-center gap-1.5">
                <BudgetEditor
                  compact
                  confirmApply
                  cores={group.cores}
                  mem={group.mem}
                  onCores={(v) => setGroup((g) => ({ ...g, cores: v }))}
                  onMem={(v) => setGroup((g) => ({ ...g, mem: v }))}
                  applyLabel={`Apply to ${selectedUuids.length}`}
                  onApply={applyGroup}
                />
                <Button variant="ghost" onClick={() => setSelected({})}>
                  Clear selection
                </Button>
              </span>
            </div>
          )}
        </div>
      </Card>

      <Card
        title="Fleet nodes"
        subtitle="Every node the CA has admitted, joined with its live heartbeat."
        info="DRAIN removes a node from routing gracefully — it keeps its certificate and heartbeat, its models migrate to other capable nodes, and un-drain restores it (use before maintenance). REVOKE is the security action: renewals are refused, the node is evicted from routing immediately, and its registry lifecycle is marked. Note: in this DEMO the node's EXISTING certificate stays valid until it expires — full revocation needs CRL distribution to every verifier (a v1.0 item). The Cert column buckets each node by renewal status (DL-R11.2-05)."
        actions={<Toast msg={msg} />}
      >
        {error && <p className="text-sm text-rose-300">{error}</p>}
        {!error && nodes && nodes.length === 0 && (
          <EmptyState icon="◌" title="No nodes enrolled yet" hint="Start a worker pointing at this controller; it will appear here (or in Pending joins under manual admission)." />
        )}
        {nodes && nodes.length > 0 && (
          <>
            <div className="mb-3 grid grid-cols-3 gap-2 sm:max-w-md">
              <Stat label="live" value={live} tone="ok" />
              <Stat label="drained" value={drained} tone={drained ? "warn" : "muted"} />
              <Stat label="cert due soon" value={dueSoon} tone={dueSoon ? "warn" : "muted"} />
            </div>
            <Table
              head={
                <Tr>
                  <Th>
                    <input
                      aria-label="select all"
                      type="checkbox"
                      className="align-middle accent-emerald-500"
                      checked={selectedUuids.length > 0 && selectedUuids.length === (nodes ?? []).filter((n) => n.lifecycle !== "revoked").length}
                      onChange={(e) => {
                        if (e.target.checked) {
                          const all: Record<string, boolean> = {};
                          for (const n of nodes) if (n.lifecycle !== "revoked") all[n.uuid] = true;
                          setSelected(all);
                        } else setSelected({});
                      }}
                    />
                  </Th>
                  <Th>Node</Th>
                  <Th>Status</Th>
                  <Th>Class</Th>
                  <Th>Site</Th>
                  <Th>
                    <span className="inline-flex items-center gap-1">
                      Resource budget
                      <InfoTip text="Precedence is node > site > fleet. 0 / Auto means DANI auto-picks — full inside a container, polite (leaves headroom) on a bare host. The badge shows the EFFECTIVE value from the node's heartbeat; Apply sets a node-scope override, Reset clears it (reverts to inherited)." />
                    </span>
                  </Th>
                  <Th>Cert</Th>
                  <Th>Actions</Th>
                </Tr>
              }
            >
              {nodes.map((n: Node) => {
                const r = renewal(n.certExpiry);
                const b = budgetByUuid.get(n.uuid);
                const d = draftFor(n.uuid, b);
                const revoked = n.lifecycle === "revoked";
                const hasOverride = overrides.node.has(n.uuid);
                return (
                  <Tr key={n.uuid}>
                    <Td>
                      {!revoked && (
                        <input
                          aria-label={`select ${n.uuid}`}
                          type="checkbox"
                          className="align-middle accent-emerald-500"
                          checked={!!selected[n.uuid]}
                          onChange={(e) => setSelected((s) => ({ ...s, [n.uuid]: e.target.checked }))}
                        />
                      )}
                    </Td>
                    <Td mono>
                      <Mono>{n.uuid}</Mono>
                    </Td>
                    <Td>
                      <span className="flex flex-wrap gap-1">
                        <Badge tone={revoked ? "bad" : n.live ? "ok" : "muted"}>{revoked ? "revoked" : n.live ? "live" : "offline"}</Badge>
                        {n.drained && <Badge tone="warn">drained</Badge>}
                        {n.trainer && <Badge tone="info">trainer</Badge>}
                      </span>
                    </Td>
                    <Td>
                      <Badge tone={stateTone(n.class)}>{n.class}</Badge>
                    </Td>
                    <Td className="text-slate-400">{n.site || "—"}</Td>
                    <Td>
                      <div className="flex flex-col gap-1.5">
                        <span className="flex items-center gap-1.5">
                          {b ? (
                            <Badge tone={capTone(b.mode)}>{budgetLabel(b)}</Badge>
                          ) : (
                            <span className="text-slate-500" title="Not in the live fleet (offline) — no heartbeat to report an effective budget.">
                              —
                            </span>
                          )}
                          {hasOverride && <Badge tone="muted">node override</Badge>}
                        </span>
                        {!revoked && (
                          <BudgetEditor
                            compact
                            cores={d.cores}
                            mem={d.mem}
                            onCores={(v) => setRowDraft((m) => ({ ...m, [n.uuid]: { ...draftFor(n.uuid, b), cores: v } }))}
                            onMem={(v) => setRowDraft((m) => ({ ...m, [n.uuid]: { ...draftFor(n.uuid, b), mem: v } }))}
                            onApply={() => writePair("node", n.uuid, d.cores, d.mem, `set budget for ${n.uuid}`)}
                            onReset={
                              hasOverride
                                ? () =>
                                    run(async () => {
                                      await api.clearConfig("node", n.uuid, K_CORES);
                                      await api.clearConfig("node", n.uuid, K_MEM);
                                    }, `reset ${n.uuid} to inherited`)
                                : undefined
                            }
                          />
                        )}
                      </div>
                    </Td>
                    <Td>
                      <span title={`serial ${n.certSerial} · gen ${n.generation} · ${isNaN(r.days) ? "?" : r.days + "d"}`}>
                        <Badge tone={r.tone}>{r.label}</Badge>
                      </span>
                    </Td>
                    <Td>
                      {!revoked && (
                        <span className="flex gap-1">
                          <Button onClick={() => run(() => api.drain(n.uuid, !n.drained), `${n.drained ? "un-drained" : "drained"} ${n.uuid}`)}>
                            {n.drained ? "Un-drain" : "Drain"}
                          </Button>
                          <ConfirmButton onConfirm={() => run(() => api.revoke(n.uuid), `revoked ${n.uuid}`)}>Revoke</ConfirmButton>
                        </span>
                      )}
                    </Td>
                  </Tr>
                );
              })}
            </Table>
          </>
        )}
      </Card>
    </div>
  );
}
