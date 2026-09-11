import { useEffect, useRef, useState, type ReactNode } from "react";

/* =====================================================================
   Layout primitives — a small, consistent vocabulary so every screen
   shares the same rhythm (spacing, hierarchy, overflow handling).
   ===================================================================== */

// Card is the one container. Header row = title (+ optional info tip) and
// right-aligned actions; body below. Never sets its own width — the page grid
// owns layout.
export function Card({
  title,
  children,
  actions,
  info,
  subtitle,
}: {
  title?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  info?: string;
  subtitle?: string;
}) {
  return (
    <section className="rounded-xl border border-white/10 bg-gradient-to-b from-white/[0.055] to-white/[0.015] shadow-[0_1px_0_rgba(255,255,255,0.05)_inset,0_10px_28px_-14px_rgba(0,0,0,0.7)] backdrop-blur-sm">
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-white/5 px-4 py-3">
          <div className="min-w-0">
            <h2 className="flex items-center gap-1.5 text-sm font-semibold tracking-wide text-slate-100">
              {title}
              {info && <InfoTip text={info} />}
            </h2>
            {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

// PageHeader states what a tab is FOR, right under the nav — the "self-explanatory" backbone.
export function PageHeader({ title, blurb }: { title: string; blurb: string }) {
  return (
    <div className="mb-1">
      <h1 className="text-base font-semibold text-slate-100">{title}</h1>
      <p className="mt-0.5 max-w-3xl text-sm leading-relaxed text-slate-400">{blurb}</p>
    </div>
  );
}

// EmptyState is the friendly "nothing here yet, do this next" panel.
export function EmptyState({ icon = "○", title, hint, action }: { icon?: string; title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-white/10 px-4 py-8 text-center">
      <span className="text-2xl text-slate-600">{icon}</span>
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {hint && <p className="max-w-sm text-xs text-slate-500">{hint}</p>}
      {action}
    </div>
  );
}

// Table wraps content in a horizontal-scroll region so wide data scrolls INSIDE
// the card instead of stretching the page. Header stays put on vertical scroll.
export function Table({ head, children }: { head: ReactNode; children: ReactNode }) {
  return (
    <div className="-mx-1 overflow-x-auto">
      <table className="w-full min-w-[40rem] border-collapse text-left text-sm">
        <thead className="text-[11px] uppercase tracking-wide text-slate-500">{head}</thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
export function Th({ children, right }: { children: ReactNode; right?: boolean }) {
  return <th className={`px-2 py-2 font-medium ${right ? "text-right" : ""}`}>{children}</th>;
}
export function Td({ children, right, mono, className = "" }: { children: ReactNode; right?: boolean; mono?: boolean; className?: string }) {
  return (
    <td className={`px-2 py-2 align-middle ${right ? "text-right tabular-nums" : ""} ${mono ? "font-mono text-xs" : ""} ${className}`}>
      {children}
    </td>
  );
}
export function Tr({ children }: { children: ReactNode }) {
  return <tr className="border-t border-white/5 hover:bg-white/[0.02]">{children}</tr>;
}

// Mono truncates long ids (node UUIDs, model names) so they never blow out a
// column; the full value is available on hover.
export function Mono({ children, className = "" }: { children: string; className?: string }) {
  return (
    <span title={children} className={`inline-block max-w-[16rem] truncate align-bottom font-mono text-xs text-slate-200 ${className}`}>
      {children}
    </span>
  );
}

// Stat is a single compact metric for summary strips.
export function Stat({ label, value, tone = "muted" }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className="rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2">
      <div className={`text-lg font-semibold leading-none ${tone === "muted" ? "bg-gradient-to-b from-white to-slate-400 bg-clip-text text-transparent" : (TONE_TEXT[tone] ?? "text-slate-100")}`}>{value}</div>
      <div className="mt-1 text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
    </div>
  );
}

/* =====================================================================
   Atoms
   ===================================================================== */

const TONES: Record<string, string> = {
  ok: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  warn: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  bad: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  muted: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  info: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
};
const TONE_TEXT: Record<string, string> = {
  ok: "text-emerald-300",
  warn: "text-amber-300",
  bad: "text-rose-300",
  info: "text-sky-300",
  muted: "text-slate-200",
};

export function Badge({ tone = "muted", children }: { tone?: string; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${TONES[tone] ?? TONES.muted}`}>
      {children}
    </span>
  );
}

export function stateTone(state: string): string {
  if (["available", "healthy", "loaded", "completed", "active", "live"].includes(state)) return "ok";
  if (["draft", "degraded", "assigned", "running", "staging", "renewal-due"].includes(state)) return "warn";
  if (["failed", "revoked", "expired", "grace-overdue"].includes(state)) return "bad";
  return "muted";
}

export function Button({
  children,
  onClick,
  disabled,
  variant = "default",
  title,
  size = "sm",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "default" | "primary" | "danger" | "ghost";
  title?: string;
  size?: "sm" | "xs";
}) {
  const pad = size === "xs" ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs";
  const kind =
    variant === "primary"
      ? "bg-gradient-to-b from-[#8fd400] to-[#5f9700] text-black font-semibold shadow-[0_0_0_1px_rgba(163,240,0,0.35),0_6px_16px_-6px_rgba(118,185,0,0.6)] hover:from-[#a3f000] hover:to-[#76b900]"
      : variant === "danger"
        ? "bg-rose-600/80 text-white hover:bg-rose-500"
        : variant === "ghost"
          ? "text-slate-400 hover:bg-white/5 hover:text-slate-200"
          : "bg-white/10 text-slate-200 hover:bg-white/20";
  return (
    <button
      className={`inline-flex items-center gap-1 rounded-md font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${pad} ${kind}`}
      onClick={onClick}
      disabled={disabled}
      title={title}
    >
      {children}
    </button>
  );
}

// ConfirmButton arms on first click, fires on the second within 4s — a guard for
// irreversible actions (revoke, park).
export function ConfirmButton({ children, onConfirm, disabled }: { children: ReactNode; onConfirm: () => void; disabled?: boolean }) {
  const [armed, setArmed] = useState(false);
  return (
    <Button
      variant={armed ? "danger" : "default"}
      disabled={disabled}
      onClick={() => {
        if (!armed) {
          setArmed(true);
          setTimeout(() => setArmed(false), 4000);
          return;
        }
        setArmed(false);
        onConfirm();
      }}
    >
      {armed ? "confirm?" : children}
    </Button>
  );
}

// InfoTip is the ℹ affordance: click to reveal a short "what is this / what do I do" note.
export function InfoTip({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);
  return (
    <span ref={ref} className="relative inline-flex">
      <button
        aria-label="info"
        onClick={() => setOpen((v) => !v)}
        className="flex h-4 w-4 items-center justify-center rounded-full bg-white/10 text-[10px] font-bold text-slate-300 hover:bg-white/20"
      >
        i
      </button>
      {open && (
        <span role="note" className="absolute left-5 top-0 z-30 w-72 rounded-lg border border-white/10 bg-slate-900 p-3 text-xs font-normal normal-case leading-relaxed text-slate-300 shadow-xl">
          {text}
        </span>
      )}
    </span>
  );
}

/* =====================================================================
   Form controls
   ===================================================================== */

export const fieldCls = "rounded-md border border-white/10 bg-black/30 px-2 py-1 text-sm text-slate-200 focus:border-emerald-500/50";

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-xs text-slate-400">
      {label}
      {children}
    </label>
  );
}

export function Select({
  value,
  onChange,
  options,
  label,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  label: string;
}) {
  return (
    <Field label={label}>
      <select aria-label={label} className={fieldCls} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </Field>
  );
}

// Toast is a transient status line; callers keep the message in state.
export function Toast({ msg }: { msg: string | null }) {
  if (!msg) return null;
  const bad = /fail|error|denied|refus|must|401|403|404|500|503/i.test(msg);
  return <span className={`max-w-[60vw] truncate text-xs ${bad ? "text-rose-300" : "text-sky-300"}`}>{msg}</span>;
}
