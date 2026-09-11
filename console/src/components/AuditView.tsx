import { useState } from "react";
import { api, type AuditEvent } from "../api";
import { usePoll } from "../usePoll";
import { Badge, Button, Card, Select } from "./ui";

// EVENTS translates chain record types into operator language. Anything unlisted renders its raw
// type — the dictionary is presentation only; the chain itself is the truth.
const EVENTS: Record<string, { text: (p: Record<string, unknown>) => string; tone: string }> = {
  "genesis": { text: () => "Trust domain created — CA and KMS keys minted", tone: "info" },
  "node.enrolled": { text: (p) => `Node ${p.node ?? p.uuid ?? ""} enrolled (certificate issued)`, tone: "ok" },
  "node.approved": { text: (p) => `Join request ${p.reqId ?? ""} approved by the operator`, tone: "ok" },
  "node.rejected": { text: (p) => `Join request ${p.reqId ?? ""} rejected${p.reason ? ` — ${p.reason}` : ""}`, tone: "bad" },
  "node.drained": { text: (p) => `Node ${p.node} drained — removed from routing, models migrating`, tone: "warn" },
  "node.undrained": { text: (p) => `Node ${p.node} restored to routing`, tone: "ok" },
  "node.revoked": { text: (p) => `Node ${p.node} REVOKED — renewals refused, evicted from the fleet`, tone: "bad" },
  "ingest.uploaded": { text: (p) => `Dataset ${p.collection} uploaded (${p.docs} docs, ${p.classification}) by ${p.by}`, tone: "info" },
  "ingest.complete": { text: (p) => `Dataset ${p.collection} ingested — ${p.chunks} classified chunks via ${p.connector}`, tone: "ok" },
  "training.start": { text: (p) => `Training ${p.job} started — ${p.engineer} fine-tuning ${p.base} on ${p.collection}`, tone: "info" },
  "training.denied": { text: (p) => `Training DENIED for ${p.engineer} on ${p.collection} — ${p.reason}`, tone: "bad" },
  "training.completed": { text: (p) => `Training ${p.job ?? ""} completed — candidate ${p.candidate ?? ""}`, tone: "ok" },
  "training.failed": { text: (p) => `Training ${p.job} FAILED — ${p.error}`, tone: "bad" },
  "training.reallocated": { text: (p) => `Training ${p.job} re-allocated ${p.from} → ${p.to} (trainer died)`, tone: "warn" },
  "model.signed": { text: (p) => `Model ${p.model} signed as ${p.role}${p.by && p.by !== "anonymous" ? ` by ${p.by}` : ""} (${p.signatures}/3)`, tone: "info" },
  "model.sign.denied": { text: (p) => `Signature REFUSED — ${p.by} does not hold the ${p.role} role`, tone: "bad" },
  "model.approved": { text: (p) => `Model ${p.model} PROMOTED — all three signatures verified`, tone: "ok" },
  "model.gate_failed": { text: (p) => `Model ${p.model} held at draft — quality/safety gate: ${p.reason}`, tone: "bad" },
  "model.artifact.pulled": { text: (p) => `Model ${p.model} artifact pulled (hash-verified)`, tone: "info" },
  "model.artifact.refused": { text: (p) => `Artifact pull REFUSED for ${p.model} — not promoted or failed verify-on-use`, tone: "bad" },
  "deployment.assigned": { text: (p) => `Model ${p.model} assigned to ${p.node}${p.by === "operator" ? " (operator pin)" : ""}`, tone: "info" },
  "deployment.loaded": { text: (p) => `Model ${p.model} serving on ${p.node}`, tone: "ok" },
  "deployment.reassigned": { text: (p) => `Model ${p.model} migrated off ${p.from}${p.to ? ` to ${p.to}` : ""} (node lost)`, tone: "warn" },
  "deployment.released": { text: (p) => `Model ${p.model} released from ${p.node} (scale-down)`, tone: "warn" },
  "deployment.scaled": { text: (p) => `Model ${p.model} scaled to ${p.replicas} replica(s)`, tone: "info" },
  "deployment.undeployed": { text: (p) => `Model ${p.model} undeployed${p.node === "*" ? " everywhere (parked)" : ` from ${p.node}`}`, tone: "warn" },
  "policy.deny": { text: (p) => `Request DENIED by policy for ${p.user} — ${p.reason}`, tone: "bad" },
  "rag.alias": { text: (p) => `RAG alias ${p.alias ?? ""} registered`, tone: "info" },
  "controller.resumed": { text: () => "Controller restarted and resumed the same trust domain", tone: "info" },
};

const FILTERS = [
  { value: "", label: "all events" },
  { value: "node.", label: "nodes (enroll/drain/revoke)" },
  { value: "ingest.", label: "datasets" },
  { value: "training.", label: "training" },
  { value: "model.", label: "models (sign/promote)" },
  { value: "deployment.", label: "deployments" },
  { value: "policy.", label: "policy denials" },
];

function describe(e: AuditEvent): { text: string; tone: string } {
  const info = EVENTS[e.type];
  if (!info) return { text: e.type, tone: "muted" };
  try {
    return { text: info.text(e.payload ?? {}), tone: info.tone };
  } catch {
    return { text: e.type, tone: info.tone };
  }
}

// timeAgo answers the compliance officer's first question — WHEN — at a glance; the exact local
// timestamp is on hover.
export function timeAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (isNaN(t)) return "";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function AuditView() {
  const [filter, setFilter] = useState("");
  const [limit, setLimit] = useState(15);
  const { data, error } = usePoll(() => api.audit(limit, filter), 6000, `${limit}:${filter}`);
  const [exportMsg, setExportMsg] = useState<string | null>(null);

  const doExport = async () => {
    setExportMsg("exporting…");
    try {
      const bundle = await api.auditExport();
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "dani-audit-seal.json";
      a.click();
      URL.revokeObjectURL(url);
      setExportMsg("downloaded — verify offline with: dani-verify dani-audit-seal.json");
    } catch (e) {
      setExportMsg(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Card
      title="Audit trail"
      info="Every governance action lands in a hash chain: each record carries the hash of the one before it, and the chain head is periodically signed by the KMS. 'Chain verified' means every hash was just re-computed and every signed head re-checked — editing, deleting, or re-ordering ANY historical record would break it, and even a full consistent rewrite would fail the head signatures. The Compliance export is the same chain sealed into a file that dani-verify checks offline, with zero trust in this server."
      actions={
        <Button variant="primary" onClick={doExport}>
          Export Compliance bundle
        </Button>
      }
    >
      {error && <p className="text-sm text-rose-300">{error}</p>}
      {data && (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <Badge tone={data.integrity.ok ? "ok" : "bad"}>
              {data.integrity.ok ? "chain verified" : `broken: ${data.integrity.why}`}
            </Badge>
            <span className="text-xs text-slate-400">
              {data.records} records · {data.signedHeads} signed heads
            </span>
            <span className="ml-auto flex items-end gap-2">
              <Select label="show" value={filter} onChange={setFilter} options={FILTERS} />
              <Button onClick={() => setLimit((n) => Math.min(n + 25, 500))}>more</Button>
            </span>
          </div>
          {exportMsg && <p className="mb-2 text-xs text-sky-300">{exportMsg}</p>}
          <ol className="space-y-1 text-sm">
            {(data.recent ?? []).slice().reverse().map((e) => {
              const d = describe(e);
              return (
                <li key={e.seq} className="flex items-start gap-2">
                  <span className="mt-0.5 w-10 shrink-0 text-right font-mono text-xs text-slate-500">#{e.seq}</span>
                  <span className="mt-0.5 w-16 shrink-0 text-xs text-slate-500" title={new Date(e.at).toLocaleString()}>
                    {timeAgo(e.at)}
                  </span>
                  <Badge tone={d.tone}>{e.type}</Badge>
                  <span className="text-xs leading-5 text-slate-300">{d.text}</span>
                </li>
              );
            })}
            {(data.recent ?? []).length === 0 && <p className="text-sm text-slate-400">No events match this filter.</p>}
          </ol>
        </>
      )}
    </Card>
  );
}
