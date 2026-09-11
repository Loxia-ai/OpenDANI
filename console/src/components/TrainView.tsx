import { useMemo, useState } from "react";
import { api, type Collections, type Job, type Principal } from "../api";
import { usePoll } from "../usePoll";
import { Badge, Button, Card, fieldCls, stateTone } from "./ui";

// TrainView is a GUIDED wizard for people who have never fine-tuned a model. It walks three plain
// steps — pick/bring data → choose a starting model → review & train — with format help and
// downloadable templates, then shows friendly live progress and the "what happens next" (three
// approvals). The power-user form lives in the Datasets + Models tabs; this is the front door.

// A small curated set of base models with human descriptions. "other" lets an expert type any id.
const BASES = [
  { id: "qwen2.5-0.5b", label: "Qwen 2.5 — 0.5B", desc: "Small and fast. Good default for most tasks; runs on modest hardware." },
  { id: "qwen2.5-3b", label: "Qwen 2.5 — 3B", desc: "Larger and more capable. Slower; needs a bigger node." },
  { id: "llama-3.1-8b", label: "Llama 3.1 — 8B", desc: "Most capable of these; heaviest to run and train." },
];

const CLASS_HELP: Record<string, string> = {
  unrestricted: "Public — anyone may see it.",
  internal: "Company-internal — staff only.",
  restricted: "Sensitive — limited to cleared people.",
  secret: "Highly sensitive — the tightest control.",
};

function download(name: string, text: string) {
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

// The four things you can teach a model, each with a fill-in template. Non-experts pick one and edit
// the example; the backend accepts all of them mixed in the same upload (one example per line).
const KINDS = [
  {
    id: "text",
    label: "Facts & text",
    blurb: "Plain knowledge — one fact or paragraph per line.",
    template: `# One example per line. Lines starting with # are ignored.
Our refund policy allows returns within 30 days, with a receipt.
Parental leave is 26 weeks of fully paid time off.
Support is available Monday to Friday, 9am to 5pm.`,
  },
  {
    id: "qa",
    label: "Question & answer",
    blurb: "Teach it to answer questions — one Q&A per line.",
    template: `{"prompt": "How long is parental leave?", "completion": "26 weeks, fully paid."}
{"prompt": "What is the refund window?", "completion": "30 days with a receipt."}
{"prompt": "When is support open?", "completion": "Monday to Friday, 9am to 5pm."}`,
  },
  {
    id: "chat",
    label: "Conversations",
    blurb: "Multi-turn dialogue — one whole conversation per line.",
    template: `{"messages": [{"role": "user", "content": "Hi, can I return an item?"}, {"role": "assistant", "content": "Yes — within 30 days with a receipt. Want the steps?"}, {"role": "user", "content": "Yes please."}, {"role": "assistant", "content": "1) Bring the item and receipt to any store. 2) We refund to your original payment."}]}`,
  },
  {
    id: "tools",
    label: "Tool calling (agents)",
    blurb: "Teach it to call your functions — one agent trace per line.",
    template: `{"messages": [{"role": "user", "content": "What's the weather in Paris?"}, {"role": "assistant", "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "get_weather", "arguments": "{\\"city\\": \\"Paris\\"}"}}]}, {"role": "tool", "tool_call_id": "c1", "content": "18C, sunny"}, {"role": "assistant", "content": "It's 18°C and sunny in Paris."}], "tools": [{"type": "function", "function": {"name": "get_weather", "description": "Look up current weather for a city", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}}]}`,
  },
] as const;

// classifyLine mirrors the backend parser so the wizard can PREVIEW what each line will become.
function classifyLine(l: string): "text" | "qa" | "chat" | "tools" | null {
  const t = l.trim();
  if (!t || t.startsWith("#")) return null;
  if (!t.startsWith("{")) return "text";
  try {
    const o = JSON.parse(t) as { messages?: { tool_calls?: unknown }[]; prompt?: string; completion?: string; tools?: unknown; text?: string };
    if (o.tools || o.messages?.some((m) => m.tool_calls)) return "tools";
    if (o.messages) return "chat";
    if (o.prompt && o.completion) return "qa";
    if (o.text) return "text";
  } catch {
    /* broken JSON — the backend treats it as text */
  }
  return "text";
}

// parseDocs counts the real examples (drops #comments/blank lines). The raw lines are sent to the
// backend, which does the authoritative parsing — this is only for the "N examples" counter.
function parseDocs(raw: string): string[] {
  return raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
}

export function TrainView() {
  const { data: jobs } = usePoll(api.jobs, 3000);
  const { data: principals } = usePoll<Principal[]>(() => api.principals().catch(() => []), 30000);
  const { data: cols } = usePoll<Collections>(api.collections, 6000);

  const [step, setStep] = useState(1);
  const [mode, setMode] = useState<"existing" | "upload">("existing");
  // existing dataset
  const [dataset, setDataset] = useState("");
  // upload
  const [upName, setUpName] = useState("");
  const [upClass, setUpClass] = useState("internal");
  const [upText, setUpText] = useState("");
  // model
  const [base, setBase] = useState("qwen2.5-0.5b");
  const [otherBase, setOtherBase] = useState("");
  const [trainAs, setTrainAs] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const ingested = cols?.collections ?? [];
  const examples = useMemo(() => parseDocs(upText), [upText]);
  // live breakdown of what each pasted line will become (for the preview counter)
  const breakdown = useMemo(() => {
    const b: Record<string, number> = {};
    for (const l of examples) {
      const k = classifyLine(l);
      if (k) b[k] = (b[k] ?? 0) + 1;
    }
    return b;
  }, [examples]);
  const chosenBase = base === "other" ? otherBase.trim() : base;
  const engineerOpts = (principals ?? []).filter((p) => p.roles.includes("user")).map((p) => ({ value: p.sub, label: `${p.sub} — clearance: ${p.clearance}` }));
  const engineer = trainAs || engineerOpts[0]?.value || "alice";

  // the collection we'll actually train on: an existing one, or the name we upload
  const effectiveDataset = mode === "existing" ? dataset || ingested[0]?.name || "" : upName.trim();
  const canProceed1 = mode === "existing" ? !!effectiveDataset : upName.trim().length > 0 && examples.length > 0;
  const canProceed2 = !!chosenBase;

  const start = async () => {
    setBusy(true);
    setErr(null);
    try {
      if (mode === "upload") {
        await api.upload(upName.trim(), examples, upClass);
      }
      await api.submitTrain(engineer, chosenBase, effectiveDataset);
      // reset to a fresh wizard; the job now streams below
      setStep(1);
      setMode("existing");
      setDataset("");
      setUpName("");
      setUpText("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <Card
        title="Teach a model"
        subtitle="Three simple steps. No machine-learning knowledge needed."
        info="Fine-tuning takes a general model and teaches it YOUR material so its answers fit your organization. You provide examples (text), pick a starting model, and DANI trains a copy on a dedicated node. When it finishes it isn't live yet — three reviewers must approve it first (that's the governance guarantee)."
      >
        <Steps step={step} />

        {/* STEP 1 — data */}
        {step === 1 && (
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-slate-200">1 · What should it learn from?</h3>
            <div className="grid gap-2 sm:grid-cols-2">
              <Choice active={mode === "existing"} onClick={() => setMode("existing")} title="Use ready-made data" desc="Pick a dataset someone already added." />
              <Choice active={mode === "upload"} onClick={() => setMode("upload")} title="Bring my own" desc="Paste text or upload files — I'll set it up." />
            </div>

            {mode === "existing" &&
              (ingested.length === 0 ? (
                <p className="rounded-lg border border-amber-500/20 bg-amber-500/[0.05] px-3 py-2 text-sm text-amber-200">
                  No datasets yet. Switch to “Bring my own”, or add one in the Datasets tab.
                </p>
              ) : (
                <div className="space-y-1.5">
                  {ingested.map((c) => (
                    <button
                      key={c.name}
                      onClick={() => setDataset(c.name)}
                      className={`flex w-full items-center justify-between rounded-lg border px-3 py-2 text-left text-sm transition ${
                        effectiveDataset === c.name ? "border-sky-500/50 bg-sky-500/10" : "border-white/10 hover:bg-white/5"
                      }`}
                    >
                      <span className="font-medium text-slate-200">{c.name}</span>
                      <span className="flex items-center gap-2">
                        <Badge tone={stateTone(c.classification)}>{c.classification}</Badge>
                        <span className="text-xs text-slate-500">{c.chunks} examples</span>
                      </span>
                    </button>
                  ))}
                </div>
              ))}

            {mode === "upload" && (
              <div className="space-y-3">
                <FormatHelp onInsert={(tpl) => setUpText((t) => (t.trim() ? t + "\n" : "") + tpl)} />
                <div className="flex flex-wrap items-end gap-2">
                  <label className="flex flex-col gap-1 text-xs text-slate-400">
                    Name this data
                    <input aria-label="dataset-name" className={fieldCls} placeholder="e.g. company-handbook" value={upName} onChange={(e) => setUpName(e.target.value)} />
                  </label>
                  <label className="flex flex-col gap-1 text-xs text-slate-400">
                    How sensitive is it?
                    <select aria-label="dataset-class" className={fieldCls} value={upClass} onChange={(e) => setUpClass(e.target.value)}>
                      {Object.keys(CLASS_HELP).map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  </label>
                  <span className="pb-1 text-xs text-slate-500">{CLASS_HELP[upClass]}</span>
                </div>
                <label className="flex flex-col gap-1 text-xs text-slate-400">
                  Upload text files (.txt, .md, .csv)
                  <input
                    aria-label="dataset-files"
                    type="file"
                    multiple
                    accept=".txt,.md,.csv,text/plain"
                    className="text-xs text-slate-400 file:mr-2 file:rounded-md file:border-0 file:bg-white/10 file:px-2 file:py-1 file:text-xs file:text-slate-200 hover:file:bg-white/20"
                    onChange={async (e) => {
                      const files = Array.from(e.target.files ?? []);
                      if (!files.length) return;
                      const texts = await Promise.all(files.map((f) => f.text()));
                      setUpText((t) => (t.trim() ? t + "\n" : "") + texts.join("\n"));
                      if (!upName.trim() && files[0]) setUpName(files[0].name.replace(/\.[^.]+$/, ""));
                      e.target.value = "";
                    }}
                  />
                </label>
                <textarea
                  aria-label="dataset-text"
                  className={`${fieldCls} h-32 w-full font-mono text-xs`}
                  placeholder={"…or paste here — one example per line:\nOur refund policy allows returns within 30 days.\nParental leave is 26 weeks of paid time off."}
                  value={upText}
                  onChange={(e) => setUpText(e.target.value)}
                />
                {examples.length > 0 ? (
                  <p className="flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
                    <span className="text-emerald-300">✓ {examples.length} example{examples.length > 1 ? "s" : ""}</span>
                    {Object.entries(breakdown).map(([k, n]) => (
                      <Badge key={k} tone="muted">
                        {n} {KINDS.find((x) => x.id === k)?.label ?? k}
                      </Badge>
                    ))}
                  </p>
                ) : (
                  <p className="text-xs text-slate-500">Add at least one example to continue — use a template above to start.</p>
                )}
              </div>
            )}

            <div className="flex justify-end">
              <Button variant="primary" disabled={!canProceed1} onClick={() => setStep(2)}>
                Next →
              </Button>
            </div>
          </div>
        )}

        {/* STEP 2 — model */}
        {step === 2 && (
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-slate-200">2 · Which model should we teach?</h3>
            <p className="text-xs text-slate-500">We start from a general model and teach it your data. Smaller = faster and cheaper; larger = more capable.</p>
            <div className="space-y-1.5">
              {BASES.map((b) => (
                <button
                  key={b.id}
                  onClick={() => setBase(b.id)}
                  className={`flex w-full flex-col rounded-lg border px-3 py-2 text-left transition ${base === b.id ? "border-sky-500/50 bg-sky-500/10" : "border-white/10 hover:bg-white/5"}`}
                >
                  <span className="text-sm font-medium text-slate-200">{b.label}</span>
                  <span className="text-xs text-slate-500">{b.desc}</span>
                </button>
              ))}
              <button
                onClick={() => setBase("other")}
                className={`flex w-full items-center gap-2 rounded-lg border px-3 py-2 text-left transition ${base === "other" ? "border-sky-500/50 bg-sky-500/10" : "border-white/10 hover:bg-white/5"}`}
              >
                <span className="text-sm font-medium text-slate-200">Something else</span>
                {base === "other" && (
                  <input
                    aria-label="other-base"
                    className={`${fieldCls} ml-auto w-56`}
                    placeholder="exact model id"
                    value={otherBase}
                    onClick={(e) => e.stopPropagation()}
                    onChange={(e) => setOtherBase(e.target.value)}
                  />
                )}
              </button>
            </div>
            <div className="flex items-center justify-between">
              <Button onClick={() => setStep(1)}>← Back</Button>
              <Button variant="primary" disabled={!canProceed2} onClick={() => setStep(3)}>
                Next →
              </Button>
            </div>
          </div>
        )}

        {/* STEP 3 — review */}
        {step === 3 && (
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-slate-200">3 · Review &amp; train</h3>
            <div className="space-y-1.5 rounded-lg border border-white/10 bg-black/20 p-3 text-sm">
              <Row k="Starting model" v={chosenBase} />
              <Row k="Learning from" v={`${effectiveDataset}${mode === "upload" ? ` (${examples.length} new examples, ${upClass})` : ""}`} />
              <Row k="Runs on" v="a dedicated trainer node (never your live inference nodes)" />
              <Row k="After training" v="lands as a draft → needs 3 reviewer approvals before it can serve" />
            </div>
            <details className="text-xs text-slate-500">
              <summary className="cursor-pointer">Advanced: who is this trained as?</summary>
              <div className="mt-2 flex flex-col gap-1">
                <span>The identity governs what data you may use — your clearance must cover the data's sensitivity.</span>
                <select aria-label="train-as" className={`${fieldCls} w-72`} value={engineer} onChange={(e) => setTrainAs(e.target.value)}>
                  {(engineerOpts.length ? engineerOpts : [{ value: "alice", label: "alice — clearance: restricted" }]).map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>
            </details>
            {err && <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">{err}</p>}
            <div className="flex items-center justify-between">
              <Button onClick={() => setStep(2)}>← Back</Button>
              <Button variant="primary" disabled={busy} onClick={() => void start()}>
                {busy ? "Starting…" : "🚀 Start training"}
              </Button>
            </div>
          </div>
        )}
      </Card>

      <JobsCard jobs={jobs} />
    </div>
  );
}

function Steps({ step }: { step: number }) {
  const labels = ["Your data", "Model", "Train"];
  return (
    <div className="mb-4 flex items-center gap-1">
      {labels.map((l, i) => {
        const n = i + 1;
        const done = step > n;
        const active = step === n;
        return (
          <div key={l} className="flex flex-1 items-center gap-1">
            <div className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold ${done ? "bg-emerald-500/20 text-emerald-300" : active ? "bg-sky-500 text-white" : "bg-white/10 text-slate-500"}`}>
              {done ? "✓" : n}
            </div>
            <span className={`text-xs ${active ? "text-slate-200" : "text-slate-500"}`}>{l}</span>
            {i < labels.length - 1 && <div className="mx-1 h-px flex-1 bg-white/10" />}
          </div>
        );
      })}
    </div>
  );
}

function Choice({ active, onClick, title, desc }: { active: boolean; onClick: () => void; title: string; desc: string }) {
  return (
    <button onClick={onClick} className={`flex flex-col rounded-lg border px-3 py-2.5 text-left transition ${active ? "border-sky-500/50 bg-sky-500/10" : "border-white/10 hover:bg-white/5"}`}>
      <span className="text-sm font-medium text-slate-200">{title}</span>
      <span className="text-xs text-slate-500">{desc}</span>
    </button>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex flex-wrap gap-2">
      <span className="w-32 shrink-0 text-xs uppercase tracking-wide text-slate-500">{k}</span>
      <span className="text-slate-200">{v}</span>
    </div>
  );
}

function FormatHelp({ onInsert }: { onInsert: (tpl: string) => void }) {
  const [kind, setKind] = useState<(typeof KINDS)[number]["id"]>("text");
  const active = KINDS.find((k) => k.id === kind)!;
  return (
    <div className="rounded-lg border border-white/10 bg-black/20 p-3">
      <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">What do you want to teach it?</div>
      {/* pick the kind of example — each has a fillable template */}
      <div className="mb-2 grid grid-cols-2 gap-1.5 sm:grid-cols-4">
        {KINDS.map((k) => (
          <button
            key={k.id}
            onClick={() => setKind(k.id)}
            className={`rounded-md border px-2 py-1.5 text-left text-xs transition ${kind === k.id ? "border-sky-500/50 bg-sky-500/10 text-slate-100" : "border-white/10 text-slate-300 hover:bg-white/5"}`}
          >
            {k.label}
          </button>
        ))}
      </div>
      <p className="mb-2 text-xs leading-relaxed text-slate-400">
        {active.blurb} You can mix any of these in one upload — the system detects each line. Put{" "}
        <strong className="text-slate-200">one example per line</strong>.
      </p>
      <pre className="mb-2 max-h-32 overflow-auto rounded bg-black/40 p-2 font-mono text-[11px] leading-relaxed text-slate-300">{active.template}</pre>
      <div className="flex flex-wrap gap-1">
        <Button size="xs" variant="primary" onClick={() => onInsert(active.template)}>
          Insert this template ↓
        </Button>
        <Button size="xs" onClick={() => download(`dani-${active.id}-example.${active.id === "text" ? "txt" : "jsonl"}`, active.template)}>
          Download
        </Button>
      </div>
    </div>
  );
}

function JobsCard({ jobs }: { jobs: Job[] | null }) {
  const active = (jobs ?? []).filter((j) => j.State !== "completed" && j.State !== "failed");
  return (
    <Card title="Training progress" subtitle={active.length ? `${active.length} in progress` : "Your training jobs appear here."}>
      {jobs && jobs.length === 0 && <p className="text-sm text-slate-400">No training yet — start one above.</p>}
      <div className="space-y-2">
        {(jobs ?? [])
          .slice()
          .reverse()
          .map((j) => {
            const pct = j.CkptsTotal > 0 ? Math.round((j.CkptsDone / j.CkptsTotal) * 100) : j.State === "completed" ? 100 : 0;
            const human =
              j.State === "completed" ? "Done" : j.State === "failed" ? "Failed" : j.State === "staging" ? "Preparing…" : j.State === "evaluating" ? "Checking quality…" : "Training…";
            return (
              <div key={j.ID} className="rounded-lg border border-white/5 bg-black/20 p-3">
                <div className="mb-1.5 flex flex-wrap items-center gap-2 text-sm">
                  <Badge tone={stateTone(j.State)}>{human}</Badge>
                  {j.Candidate ? <span className="font-mono text-xs text-slate-300">{j.Candidate}</span> : <span className="text-xs text-slate-500">{j.Collection ?? j.ID}</span>}
                  <span className="ml-auto text-xs text-slate-500">
                    {j.CkptsDone}/{j.CkptsTotal || "?"}
                  </span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/5">
                  <div
                    className={`h-full rounded-full transition-all ${j.State === "failed" ? "bg-rose-500" : j.State === "completed" ? "bg-emerald-500" : "bg-sky-500"}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                {j.State === "failed" && j.Err && <p className="mt-1.5 text-xs text-rose-300">{j.Err}</p>}
                {j.State === "completed" && (
                  <p className="mt-1.5 text-xs text-emerald-300">
                    ✓ Trained. Next: it needs 3 reviewer approvals in the <span className="font-medium">Models</span> tab before it can serve.
                  </p>
                )}
                {j.Evals && Object.keys(j.Evals).length > 0 && (
                  <p className="mt-1 text-xs text-slate-500">
                    quality: {Object.entries(j.Evals).map(([k, v]) => `${k} ${v.toFixed(2)}`).join(" · ")}
                  </p>
                )}
              </div>
            );
          })}
      </div>
    </Card>
  );
}
