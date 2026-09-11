import { useState } from "react";
import { api } from "../api";
import { usePoll } from "../usePoll";
import { Badge, Button, Card } from "./ui";

// ApiAccessCard answers "how do my applications connect?" — the endpoint is OpenAI-compatible, so
// any OpenAI SDK works by pointing base_url at the gateway. Shown on the Overview with a copyable
// example against a model that is live right now.
export function ApiAccessCard() {
  const { data: models } = usePoll(() => api.liveModels().catch(() => []), 10000);
  const [copied, setCopied] = useState(false);
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const first = models?.[0]?.id ?? "<model-id>";
  const snippet = `curl ${origin}/v1/chat/completions \\
  -H "Content-Type: application/json" -H "X-Dani-User: alice" \\
  -d '{"model":"${first}","messages":[{"role":"user","content":"hello"}]}'`;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(snippet);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable (http origin / permissions) — the text is selectable */
    }
  };

  return (
    <Card
      title="Connect your applications"
      subtitle="The gateway speaks the OpenAI API — existing SDKs work by changing one URL."
      info="Point any OpenAI-compatible client at this gateway (base_url = the address below) and use a model id the fleet serves. The X-Dani-User header attributes the request to a directory identity so the Policy Engine can enforce clearance; without it the request runs as guest."
      actions={<Button onClick={() => void copy()}>{copied ? "✓ copied" : "Copy example"}</Button>}
    >
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-slate-400">Endpoint</span>
          <code className="rounded bg-black/40 px-2 py-0.5 font-mono text-xs text-sky-200">{origin}/v1</code>
          <span className="text-slate-400">Models live now</span>
          {(models ?? []).slice(0, 4).map((m) => (
            <Badge key={m.id} tone="info">
              {m.id}
            </Badge>
          ))}
          {(models ?? []).length === 0 && <span className="text-xs text-slate-500">none yet</span>}
        </div>
        <pre className="overflow-x-auto rounded-lg border border-white/5 bg-black/40 p-3 font-mono text-xs leading-relaxed text-slate-300">
          {snippet}
        </pre>
      </div>
    </Card>
  );
}

// HelpDrawer is the persistent "?" — the guidance that never disappears (the getting-started
// stepper hides once the system is in use, but new operators arrive at running systems).
export function HelpDrawer({ open, onClose, goTab }: { open: boolean; onClose: () => void; goTab: (t: string) => void }) {
  if (!open) return null;
  const Step = ({ n, tab, title, text }: { n: number; tab: string; title: string; text: string }) => (
    <li className="flex gap-2">
      <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-sky-500/20 text-[11px] font-bold text-sky-300">{n}</span>
      <span className="text-sm leading-relaxed text-slate-300">
        <button className="font-medium text-sky-300 hover:underline" onClick={() => { goTab(tab); onClose(); }}>
          {title}
        </button>{" "}
        — {text}
      </span>
    </li>
  );
  return (
    <div className="fixed inset-0 z-40" role="dialog" aria-label="help">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <aside className="absolute right-0 top-0 h-full w-full max-w-md overflow-y-auto border-l border-white/10 bg-slate-950 p-5 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold">How DANI works</h2>
          <Button variant="ghost" onClick={onClose}>
            ✕ close
          </Button>
        </div>

        <p className="mb-4 text-sm leading-relaxed text-slate-400">
          DANI runs AI models entirely inside your network — nothing leaves the perimeter. This console manages the whole
          lifecycle; every action lands in a tamper-evident audit trail.
        </p>

        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">The story, start to finish</h3>
        <ol className="mb-5 space-y-2.5">
          <Step n={1} tab="datasets" title="Add data" text="ingest a connector source or upload documents. Everything is classified at ingest — sensitive content is marked automatically." />
          <Step n={2} tab="training" title="Train" text="fine-tune a base model on a dataset. Your clearance must cover the data's classification." />
          <Step n={3} tab="registry" title="Approve" text="three different reviewers (Security, Governance, Administrator) each sign the candidate. A quality/safety gate must also pass." />
          <Step n={4} tab="playground" title="Use it" text="the approved model deploys automatically. Try it in the Playground, or point your apps at the API (see Overview)." />
        </ol>

        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Words you'll see</h3>
        <dl className="mb-5 space-y-2 text-sm">
          {[
            ["Classification", "how sensitive something is: unrestricted → internal → restricted → secret. Data, models, and requests all carry one."],
            ["Clearance", "the highest classification an identity may touch. A request above your clearance is refused — that's the Policy Engine."],
            ["Signatures", "cryptographic approvals. A model needs all three reviewer roles before it can serve."],
            ["Drain", "gracefully take a node out of traffic (maintenance). Its models move elsewhere; un-drain brings it back."],
            ["Revoke", "permanently expel a node. It is evicted immediately and its certificate is never renewed."],
            ["Chain verified", "every audit record is hash-linked to the previous one and the chain head is signed — editing history would break it visibly."],
          ].map(([term, def]) => (
            <div key={term}>
              <dt className="font-medium text-slate-200">{term}</dt>
              <dd className="text-slate-400">{def}</dd>
            </div>
          ))}
        </dl>

        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Signing in</h3>
        <p className="text-sm leading-relaxed text-slate-400">
          When operator sign-in is enabled, actions require a personal token. Your administrator generates these when the
          controller starts (<code className="font-mono text-xs">console-operators.json</code>) and hands yours to you —
          paste it into <em>Sign in</em> (top right). Your identity determines which reviewer roles you can sign as, and
          the audit trail records what you did.
        </p>
      </aside>
    </div>
  );
}
