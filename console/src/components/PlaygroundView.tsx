import { useEffect, useRef, useState } from "react";
import { api, type ChatMsg, type Principal } from "../api";
import { useSession } from "../session";
import { usePoll } from "../usePoll";
import { Badge, Button, Card, EmptyState, Select, fieldCls } from "./ui";

// PlaygroundView answers the most basic user question the rest of the console doesn't: "OK, it's
// deployed — how do I USE it?" Pick a model the fleet is serving, ask as a chosen identity, and the
// answer comes back with its routing proof (which node served it) and RAG citations when the model
// is a retrieval alias. Policy denials show up here too — in plain language — which makes the
// governance story tangible: carol asking for restricted content is refused, alice is served.
export function PlaygroundView() {
  const { data: models } = usePoll(() => api.liveModels().catch(() => []), 8000);
  const { data: principals } = usePoll<Principal[]>(() => api.principals().catch(() => []), 30000);
  const session = useSession();
  const [model, setModel] = useState("");
  const [asUser, setAsUser] = useState("");
  const [input, setInput] = useState("");
  const [msgs, setMsgs] = useState<ChatMsg[]>([]);
  const [pending, setPending] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  const modelOpts = (models ?? []).map((m) => ({ value: m.id, label: m.engine ? `${m.id} (${m.engine})` : m.id }));
  const chosenModel = model || modelOpts[0]?.value || "";
  // ask as the signed-in operator by default; otherwise (or on override) any directory identity —
  // switching identities is how you SEE the policy engine work.
  const userOpts = (principals ?? []).map((p) => ({ value: p.sub, label: `${p.sub} (${p.clearance})` }));
  const chosenUser = asUser || (session.who?.authEnabled && session.who.sub && session.who.sub !== "anonymous" ? session.who.sub : "") || userOpts[0]?.value || "alice";

  useEffect(() => {
    // jsdom has no scrollIntoView — a nicety in the browser, a no-op in tests
    if (typeof endRef.current?.scrollIntoView === "function") {
      endRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [msgs, pending]);

  // Hand-off from Datasets' "Chat over this": select the requested model once it appears in the
  // live list, then consume the key so a later visit doesn't re-apply a stale choice.
  useEffect(() => {
    if (!models || models.length === 0) return;
    try {
      const want = localStorage.getItem("dn-playground-model");
      if (want && models.some((m) => m.id === want)) {
        setModel(want);
        localStorage.removeItem("dn-playground-model");
      }
    } catch {
      /* storage unavailable */
    }
  }, [models]);

  const send = async () => {
    const text = input.trim();
    if (!text || !chosenModel || pending) return;
    setErr(null);
    setInput("");
    const history = [...msgs, { role: "user", content: text } as ChatMsg];
    setMsgs(history);
    setPending(true);
    try {
      const reply = await api.chat(
        chosenModel,
        history.map((m) => ({ role: m.role, content: m.content })),
        chosenUser,
      );
      setMsgs([...history, reply]);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(false);
    }
  };

  return (
    <Card
      title="Playground"
      subtitle="Talk to a model the fleet is serving — every reply shows which node answered."
      info="Requests go through the same gateway your applications use (/v1/chat/completions, OpenAI-compatible). The identity you ask as goes through the live Policy Engine: content is classified, and a request above that identity's clearance is refused — try asking carol (internal clearance) about restricted topics to see a denial. Models named *-rag-* answer with retrieval over a classified dataset and return citations."
      actions={
        (models ?? []).length > 0 && (
          <div className="flex flex-wrap items-end gap-2">
            <Select label="model" value={chosenModel} onChange={setModel} options={modelOpts} />
            <Select label="ask as" value={chosenUser} onChange={setAsUser} options={userOpts.length ? userOpts : [{ value: "alice", label: "alice" }]} />
          </div>
        )
      }
    >
      {(models ?? []).length === 0 ? (
        <EmptyState
          icon="◌"
          title="No models are serving yet"
          hint="A model appears here once a worker serves it — either a base model provisioned with the fleet, or a fine-tune promoted with three signatures."
        />
      ) : (
        <div className="flex h-[26rem] flex-col">
          <div className="flex-1 space-y-3 overflow-y-auto pr-1">
            {msgs.length === 0 && (
              <p className="pt-6 text-center text-sm text-slate-500">
                Ask anything — e.g. “what does the parental leave policy say?”
              </p>
            )}
            {msgs.map((m, i) =>
              m.role === "user" ? (
                <div key={i} className="ml-auto max-w-[85%] rounded-xl rounded-br-sm bg-sky-500/15 px-3 py-2 text-sm text-slate-100">
                  {m.content}
                </div>
              ) : (
                <div key={i} className="max-w-[85%] space-y-1.5">
                  <div className="rounded-xl rounded-bl-sm border border-white/5 bg-white/[0.04] px-3 py-2 text-sm leading-relaxed text-slate-200">
                    {m.content}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5 pl-1">
                    {m.servedBy && (
                      <span title="The node that generated this answer — proof the request stayed in your perimeter">
                        <Badge tone="ok">answered by {m.servedBy}</Badge>
                      </span>
                    )}
                    {m.citations && m.citations.length > 0 && (
                      <Badge tone="info">{m.citations.length} source{m.citations.length > 1 ? "s" : ""} cited</Badge>
                    )}
                  </div>
                  {m.citations && m.citations.length > 0 && (
                    <ul className="ml-1 space-y-1 border-l border-white/10 pl-3 text-xs text-slate-400">
                      {m.citations.map((c, ci) => {
                        const name = (c.doc ?? c.id).split("/").pop() ?? c.id;
                        return (
                          <li key={ci} className="flex flex-wrap items-center gap-1.5">
                            <span className="font-mono text-slate-300" title={c.doc ?? c.id}>
                              {name}
                            </span>
                            {c.class && <Badge tone="muted">{c.class}</Badge>}
                            {typeof c.score === "number" && (
                              <span className="tabular-nums text-slate-500">{Math.round(c.score * 100)}% match</span>
                            )}
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
              ),
            )}
            {pending && <p className="pl-1 text-sm text-slate-500">thinking…</p>}
            {err && (
              <div className="max-w-[85%] rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
                {err}
              </div>
            )}
            <div ref={endRef} />
          </div>
          <form
            className="mt-3 flex gap-2 border-t border-white/5 pt-3"
            onSubmit={(e) => {
              e.preventDefault();
              void send();
            }}
          >
            <input
              aria-label="message"
              className={`${fieldCls} flex-1`}
              placeholder={`Message ${chosenModel}…`}
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
            {/* no onClick: the button is type=submit inside the form — one path, no double-send */}
            <Button variant="primary" disabled={!input.trim() || pending}>
              Send
            </Button>
          </form>
        </div>
      )}
    </Card>
  );
}
