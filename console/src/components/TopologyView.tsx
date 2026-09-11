import { type CSSProperties, type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  getStraightPath,
  Handle,
  type InternalNode,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  type Edge,
  type Node,
  useEdgesState,
  useInternalNode,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";
import type { NodeChange } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api, type Cluster, type Node as DaniNode } from "../api";
import { usePoll } from "../usePoll";
import { Badge, Card, InfoTip } from "./ui";

// The DANI network as an interactive constellation: the CONTROL PLANE (every Raft controller — one
// per site, the elected leader the central star) with each controller's enrolled nodes orbiting it;
// edges = the mTLS Link each node holds to the control plane, with live traffic flowing along them as
// particles. Click any node to focus it — the camera glides in, its links light up, the rest dims,
// and a detail panel opens. Pan/zoom is sticky (never yanked back by a background refresh). Two
// overlays: "serving" (traffic) and "wireguard" (the DANI-coordinated overlay IPs).

type NodeData = {
  label: string;
  kind: "controller" | "trainer" | "worker";
  health: string;
  drained?: boolean;
  models: string[];
  sub: string;
  overlay?: string;
  leader?: boolean;
  self?: boolean;
  load?: number;
  slots?: number;
  serving?: boolean;
  // interaction state (set by the highlight pass; never affects layout)
  dimmed?: boolean;
  focused?: boolean;
};

// Controllers are the "stars": the leader glows at the center, followers orbit. Hidden center handles
// let the floating edges radiate node-center to node-center.
function HubNode({ data }: { data: NodeData }) {
  const leader = data.leader;
  return (
    <div
      className={`dn-node relative rounded-2xl border px-4 py-3 text-center backdrop-blur-sm ${data.dimmed ? "dn-dim" : ""} ${data.focused ? "dn-focus-ring" : ""} ${
        leader
          ? "border-cyan-300/70 bg-cyan-400/10 shadow-[0_0_46px_-4px_rgba(34,211,238,0.55),inset_0_1px_0_rgba(255,255,255,0.16)]"
          : "border-cyan-400/35 bg-cyan-500/[0.06] shadow-[0_0_22px_-8px_rgba(34,211,238,0.5)]"
      }`}
    >
      {leader && <span aria-hidden className="dn-star-pulse pointer-events-none absolute -inset-4 -z-10 rounded-full bg-cyan-400/20 blur-2xl" />}
      <Handle type="target" position={Position.Top} className="dn-hidden-handle" />
      <Handle type="source" position={Position.Bottom} className="dn-hidden-handle" />
      <div className={`flex items-center justify-center gap-1.5 font-semibold ${leader ? "text-sm text-cyan-50" : "text-[13px] text-cyan-100"}`}>
        <span className={leader ? "text-amber-300" : "text-cyan-300/80"}>{leader ? "★" : "◇"}</span>
        {data.label}
      </div>
      <div className="mt-0.5 text-[10px] uppercase tracking-wider text-cyan-300/60">{data.sub}</div>
    </div>
  );
}

function FleetNode({ data }: { data: NodeData }) {
  const live = data.health === "live" || data.health === "healthy";
  const ring =
    data.health === "revoked"
      ? "border-rose-500/50 bg-rose-500/[0.06] shadow-[0_0_18px_-9px_rgba(255,77,94,0.7)]"
      : data.drained
        ? "border-amber-500/45 bg-amber-500/[0.05] shadow-[0_0_18px_-9px_rgba(255,176,32,0.6)]"
        : live
          ? "border-emerald-500/40 bg-emerald-500/[0.06] shadow-[0_0_22px_-9px_rgba(118,185,0,0.65)]"
          : "border-white/10 bg-white/[0.03]";
  const dotColor = data.health === "revoked" ? "bg-rose-400" : data.drained ? "bg-amber-400" : live ? "bg-emerald-400" : "bg-slate-500";
  const loadPct = data.slots ? Math.min(100, Math.round(((data.load ?? 0) / data.slots) * 100)) : 0;
  return (
    <div className={`dn-node w-40 rounded-lg border px-3 py-2 backdrop-blur-sm ${ring} ${data.dimmed ? "dn-dim" : ""} ${data.focused ? "dn-focus-ring" : ""} ${data.serving ? "dn-serving" : ""}`}>
      <Handle type="target" position={Position.Top} className="dn-hidden-handle" />
      <Handle type="source" position={Position.Bottom} className="dn-hidden-handle" />
      <div className="flex items-center justify-between gap-1">
        <span className="flex min-w-0 items-center gap-1.5">
          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dotColor} ${live && !data.drained ? "dn-live-dot" : ""}`} />
          <span title={data.label} className="truncate font-mono text-xs font-semibold text-slate-100">
            {data.label}
          </span>
        </span>
        <span className="shrink-0 text-[10px] text-slate-400">{data.kind === "trainer" ? "🎓" : ""}</span>
      </div>
      <div className="mt-0.5 truncate text-[10px] text-slate-400">{data.sub}</div>
      {data.overlay ? (
        <div className="mt-1 font-mono text-[10px] text-sky-300">wg {data.overlay}</div>
      ) : (
        <>
          {data.models.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {data.models.slice(0, 3).map((m) => (
                <span key={m} title={m} className="max-w-full truncate rounded bg-sky-500/15 px-1 text-[9px] text-sky-200">
                  {m}
                </span>
              ))}
            </div>
          )}
          {data.kind !== "trainer" && data.slots ? (
            <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-white/8">
              <div
                className={`h-full rounded-full transition-all duration-500 ${loadPct > 80 ? "bg-amber-400" : "bg-emerald-400/80"}`}
                style={{ width: `${loadPct}%` }}
              />
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

const nodeTypes = { hub: HubNode, fleet: FleetNode };

type EdgeData = { color: string; active: boolean; dashed?: boolean; dimmed?: boolean; speed?: number };

/* Floating edges connect node CENTER to node CENTER, clipped at each border — links radiate cleanly
   out of the star. When a link is live, a particle streams along it (dispatch → node). */
function nodeCenterIntersect(a: InternalNode, b: InternalNode) {
  const aw = (a.measured.width ?? 0) / 2;
  const ah = (a.measured.height ?? 0) / 2;
  const ax = a.internals.positionAbsolute.x + aw;
  const ay = a.internals.positionAbsolute.y + ah;
  const bx = b.internals.positionAbsolute.x + (b.measured.width ?? 0) / 2;
  const by = b.internals.positionAbsolute.y + (b.measured.height ?? 0) / 2;
  const dx = (bx - ax) / (2 * aw) - (by - ay) / (2 * ah);
  const dy = (bx - ax) / (2 * aw) + (by - ay) / (2 * ah);
  const scale = 1 / (Math.abs(dx) + Math.abs(dy) || 1);
  return { x: aw * (scale * dx + scale * dy) + ax, y: ah * (scale * dy - scale * dx) + ay };
}

function FloatingEdge({ id, source, target, data }: { id: string; source: string; target: string; data?: EdgeData }) {
  const s = useInternalNode(source);
  const t = useInternalNode(target);
  if (!s || !t) return null;
  const sp = nodeCenterIntersect(s, t);
  const tp = nodeCenterIntersect(t, s);
  const [path] = getStraightPath({ sourceX: sp.x, sourceY: sp.y, targetX: tp.x, targetY: tp.y });
  const d = data ?? { color: "#34403d", active: false };
  const op = d.dimmed ? 0.08 : d.active ? 0.85 : 0.4;
  const style: CSSProperties = {
    stroke: d.color,
    strokeWidth: d.active ? 1.7 : 1.3,
    strokeDasharray: d.dashed ? "6 5" : undefined,
    opacity: op,
    transition: "opacity 300ms",
  };
  return (
    <>
      <path id={id} className="react-flow__edge-path" d={path} style={style} />
      {d.active && !d.dimmed && (
        <circle r={2.6} fill={d.color} className="dn-flow-dot">
          <animateMotion dur={`${d.speed ?? 2.4}s`} repeatCount="indefinite" keyPoints="0;1" keyTimes="0;1" calcMode="linear">
            <mpath href={`#${id}`} />
          </animateMotion>
        </circle>
      )}
    </>
  );
}

const edgeTypes = { floating: FloatingEdge };

// Place `count` points around (cx,cy): a full ring (leader's planets) or an outward fan (a follower's
// cluster), spilling onto concentric rings as the count grows.
function fanPositions(
  cx: number,
  cy: number,
  count: number,
  opts: { full?: boolean; dir?: number; spread?: number; r0: number; dr: number; perRing: number },
): { x: number; y: number }[] {
  const pts: { x: number; y: number }[] = [];
  let placed = 0;
  let ring = 0;
  while (placed < count) {
    const cap = opts.perRing + ring * (opts.full ? 3 : 2);
    const inRing = Math.min(cap, count - placed);
    const r = opts.r0 + ring * opts.dr;
    for (let k = 0; k < inRing; k++) {
      let ang: number;
      if (opts.full) {
        ang = (k / inRing) * Math.PI * 2 + ring * 0.5;
      } else {
        const t = inRing === 1 ? 0.5 : k / (inRing - 1);
        ang = (opts.dir ?? 0) + (t - 0.5) * (opts.spread ?? 2.2);
      }
      pts.push({ x: cx + Math.cos(ang) * r, y: cy + Math.sin(ang) * r });
    }
    placed += inRing;
    ring++;
  }
  return pts;
}

// Constellation hosts the React Flow canvas. It fits the view ONCE per structural signature (initial
// load, re-election, controller join/leave, or explicit reset) — guarded by a ref so a routine data
// poll never yanks the user's pan/zoom back. Selecting a node glides the camera to center it.
function Constellation({
  nodes,
  edges,
  onNodesChange,
  sig,
  selected,
  onSelect,
}: {
  nodes: Node<NodeData>[];
  edges: Edge[];
  onNodesChange: (c: NodeChange<Node<NodeData>>[]) => void;
  sig: string;
  selected: string | null;
  onSelect: (id: string | null) => void;
}) {
  const rf = useReactFlow();
  const inited = useNodesInitialized();
  const fittedSig = useRef<string | null>(null);

  // Fit exactly once per structural signature — never on the 4s data refresh.
  useEffect(() => {
    if (inited && nodes.length && fittedSig.current !== sig) {
      fittedSig.current = sig;
      rf.fitView({ padding: 0.18, duration: 600 });
    }
  }, [inited, sig, nodes.length, rf]);

  // Glide to a selected node (its measured center), zoom in a touch.
  useEffect(() => {
    if (!selected) return;
    const n = rf.getNode(selected);
    if (!n) return;
    const cx = n.position.x + (n.measured?.width ?? 160) / 2;
    const cy = n.position.y + (n.measured?.height ?? 60) / 2;
    rf.setCenter(cx, cy, { zoom: Math.max(1.1, rf.getZoom()), duration: 650 });
  }, [selected, rf]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onNodeClick={(_, n) => onSelect(n.id)}
      onPaneClick={() => onSelect(null)}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      minZoom={0.15}
      maxZoom={2.2}
      proOptions={{ hideAttribution: true }}
    >
      <Background variant={BackgroundVariant.Dots} color="#2f5a2a" gap={26} size={1} />
      <Controls className="!border-white/10 !bg-slate-800/80 !backdrop-blur" showInteractive={false} />
      <MiniMap pannable zoomable className="!bg-slate-900/70 !backdrop-blur" maskColor="#00000099" nodeColor="#34403d" />
    </ReactFlow>
  );
}

// The focus panel: everything a viewer wants to know about the node they clicked, plus a way out.
function DetailPanel({ node, onClose }: { node: DaniNode; onClose: () => void }) {
  const state = node.lifecycle === "revoked" ? "revoked" : node.drained ? "drained" : node.live ? "live" : "offline";
  const tone = state === "revoked" ? "bad" : state === "drained" ? "warn" : state === "live" ? "ok" : "muted";
  const models = [node.model, ...(node.loaded ?? [])].filter(Boolean) as string[];
  const renew = node.certExpiry && !node.certExpiry.startsWith("0001") ? new Date(node.certExpiry) : null;
  const rows: [string, ReactNode][] = [
    ["role", node.trainer ? "trainer (D17 · no inference)" : (node.roles || ["worker"]).join(", ")],
    ["site", node.site || "—"],
    ["class", node.class],
    ["engine", node.trainer ? "—" : node.engine || "llama"],
    ["models", models.length ? models.join(", ") : "—"],
    ["generation", `#${node.generation}`],
    ["cert renews", renew ? renew.toLocaleDateString() : "—"],
  ];
  return (
    <div className="dn-panel-in absolute right-3 top-3 z-10 w-64 rounded-xl border border-white/10 bg-slate-900/85 p-3 shadow-2xl backdrop-blur-md">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-mono text-sm font-semibold text-slate-100">{node.uuid}</div>
          <div className="mt-1">
            <Badge tone={tone as "ok" | "warn" | "bad" | "muted"}>{state}</Badge>
          </div>
        </div>
        <button onClick={onClose} aria-label="close" className="rounded-md px-1.5 text-slate-400 transition hover:bg-white/10 hover:text-slate-100">
          ✕
        </button>
      </div>
      <dl className="mt-2.5 space-y-1.5 text-xs">
        {rows.map(([k, v]) => (
          <div key={k} className="flex items-baseline justify-between gap-3">
            <dt className="shrink-0 text-slate-500">{k}</dt>
            <dd className="min-w-0 truncate text-right text-slate-200">{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function TopologyView() {
  const { data: nodes } = usePoll<DaniNode[]>(() => api.nodes().catch(() => []), 4000);
  const { data: cluster } = usePoll<Cluster | null>(() => api.cluster().catch(() => null), 6000);
  const { data: mesh } = usePoll<{ nodes?: { UUID: string; IP: string }[] }>(
    () => api.wgMesh().catch(() => ({ nodes: [] })),
    8000,
  );
  const [overlay, setOverlay] = useState<"serving" | "wireguard">("serving");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<Node<NodeData>>([]);
  const [rfEdges, setRfEdges] = useEdgesState<Edge>([]);
  const [resetNonce, setResetNonce] = useState(0);
  const layoutSigRef = useRef<string>("");

  const overlayIP = useMemo(() => {
    const m: Record<string, string> = {};
    for (const n of mesh?.nodes ?? []) m[n.UUID] = n.IP;
    return m;
  }, [mesh]);

  const selectedNode = useMemo(() => (nodes ?? []).find((n) => n.uuid === selected) ?? null, [nodes, selected]);

  // structural signature = who the controllers are + who leads (NOT worker count) + reset nonce.
  const structuralSig = useMemo(() => {
    const members = (cluster?.members?.length ? cluster.members : [{ id: "ctrl-001", leader: true }])
      .slice()
      .sort((a, b) => a.id.localeCompare(b.id));
    const leader = members.find((m) => m.leader) ?? members[0];
    return `${leader.id}|${members.map((m) => m.id).join(",")}|${resetNonce}`;
  }, [cluster, resetNonce]);

  useEffect(() => {
    const list = [...(nodes ?? [])].sort((a, b) => (a.site || "").localeCompare(b.site || "") || a.uuid.localeCompare(b.uuid));
    const members = (cluster?.members?.length ? cluster.members : [{ id: "ctrl-001", leader: true, self: true }])
      .slice()
      .sort((a, b) => a.id.localeCompare(b.id));
    const sites = [...new Set(list.map((n) => n.site || ""))].sort();
    const ctrlOfSite: Record<string, string> = {};
    sites.forEach((s, i) => { ctrlOfSite[s] = members[i % members.length].id; });

    const leader = members.find((m) => m.leader) ?? members[0];
    const followers = members.filter((m) => m.id !== leader.id);
    const nf = followers.length;
    const Rc = nf <= 1 ? 0 : 720 + nf * 20;
    const baseAngle = nf === 2 ? 0 : -Math.PI / 2;

    const ctrlPos: Record<string, { x: number; y: number; dir: number; leader: boolean }> = {};
    ctrlPos[leader.id] = { x: 0, y: 0, dir: -Math.PI / 2, leader: true };
    followers.forEach((m, i) => {
      const ang = baseAngle + i * ((2 * Math.PI) / Math.max(1, nf));
      ctrlPos[m.id] = { x: Math.cos(ang) * Rc, y: Math.sin(ang) * Rc, dir: ang, leader: false };
    });

    // adjacency + search matching for the highlight pass (never touches layout)
    const q = search.trim().toLowerCase();
    const ctrlOf = (n: DaniNode) => ctrlOfSite[n.site || ""] ?? members[0].id;
    const matches = (n: DaniNode) =>
      !q || n.uuid.toLowerCase().includes(q) || (n.site || "").toLowerCase().includes(q) ||
      [n.model, ...(n.loaded ?? []), n.engine].filter(Boolean).some((s) => (s as string).toLowerCase().includes(q));
    // when a node is selected, its neighborhood = the node + its home controller (or, for a controller,
    // all controllers + that controller's workers)
    const neighborhood = new Set<string>();
    if (selected) {
      neighborhood.add(selected);
      const selWorker = list.find((n) => n.uuid === selected);
      if (selWorker) {
        neighborhood.add(ctrlOf(selWorker));
      } else {
        members.forEach((m) => neighborhood.add(m.id)); // a controller: light the whole control plane
        list.forEach((n) => { if (ctrlOf(n) === selected) neighborhood.add(n.uuid); });
      }
    }
    const dimNode = (id: string, isWorker: boolean, n?: DaniNode) => {
      if (selected) return !neighborhood.has(id);
      if (q && isWorker && n) return !matches(n); // search dims only non-matching workers; the control-plane backbone stays lit
      return false;
    };

    // Explicit dimensions so floating edges have geometry from the first frame — React Flow otherwise
    // culls every edge until a ResizeObserver measures each node (which never fires in some embedded
    // browsers, and adds a visible blank frame everywhere). The real measured size refines these.
    const HUB = { width: 190, height: 62 };
    const FLEET = { width: 160, height: 74 };
    const hubs: Node<NodeData>[] = members.map((m) => ({
      id: m.id,
      type: "hub",
      position: { x: ctrlPos[m.id].x, y: ctrlPos[m.id].y },
      ...HUB,
      data: {
        label: m.id,
        kind: "controller",
        health: "live",
        models: [],
        sub: m.leader ? "raft leader · gateway · CA" : "raft follower · gateway",
        leader: m.leader,
        self: m.self,
        dimmed: dimNode(m.id, false),
        focused: selected === m.id,
      },
      draggable: true,
    }));

    const byCtrl: Record<string, DaniNode[]> = {};
    for (const n of list) (byCtrl[ctrlOf(n)] ??= []).push(n);
    const built: Node<NodeData>[] = [];
    for (const m of members) {
      const cp = ctrlPos[m.id];
      const group = byCtrl[m.id] ?? [];
      const pts = cp.leader
        ? fanPositions(cp.x, cp.y, group.length, { full: true, r0: 275, dr: 132, perRing: 8 })
        : fanPositions(cp.x, cp.y, group.length, { dir: cp.dir, spread: 1.95, r0: 255, dr: 150, perRing: 4 });
      group.forEach((n, i) => {
        const p = pts[i] ?? { x: cp.x, y: cp.y + 170 };
        const alive = n.live && n.lifecycle !== "revoked" && !n.drained;
        built.push({
          id: n.uuid,
          type: "fleet",
          position: { x: p.x - 78, y: p.y - 30 },
          ...FLEET,
          data: {
            label: n.uuid,
            kind: n.trainer ? "trainer" : "worker",
            health: n.lifecycle === "revoked" ? "revoked" : n.live ? "live" : "offline",
            drained: n.drained,
            sub: `${n.trainer ? "trainer" : n.engine || "worker"} · ${n.site || "—"} · ${n.class}`,
            models: n.trainer ? [] : ([n.model, ...(n.loaded ?? [])].filter(Boolean) as string[]),
            overlay: overlayIP[n.uuid],
            serving: alive && !n.trainer && overlay === "serving",
            dimmed: dimNode(n.uuid, true, n),
            focused: selected === n.uuid,
          },
        });
      });
    }

    const wg = overlay === "wireguard";
    const anySel = !!selected || !!q;
    const raftEdges: Edge[] = followers.map((m) => ({
      id: `raft-${m.id}`,
      source: leader.id,
      target: m.id,
      type: "floating",
      data: {
        color: "#22d3ee",
        active: !wg,
        dashed: true,
        speed: 3.2,
        dimmed: anySel && !(neighborhood.has(leader.id) && neighborhood.has(m.id)),
      } as EdgeData,
    }));

    const relayout = structuralSig !== layoutSigRef.current;
    layoutSigRef.current = structuralSig;
    const desired = [...hubs, ...built];
    setRfNodes((prev) => {
      const prevPos = new Map(prev.map((n) => [n.id, n.position]));
      return desired.map((d) => ({
        ...d,
        position: relayout ? d.position : (prevPos.get(d.id) ?? d.position),
        selected: d.id === selected,
      }));
    });
    setRfEdges([
      ...raftEdges,
      ...list.map((n) => {
        const alive = n.live && n.lifecycle !== "revoked" && !n.drained;
        const ctrl = ctrlOf(n);
        return {
          id: `e-${n.uuid}`,
          type: "floating",
          source: ctrl,
          target: n.uuid,
          data: {
            color: n.lifecycle === "revoked" ? "#ff4d5e" : n.drained ? "#ffb020" : wg ? "#22d3ee" : alive ? "#8fd400" : "#34403d",
            active: (alive && !wg) || wg,
            dashed: wg,
            speed: 2.6,
            dimmed: anySel && !(neighborhood.has(ctrl) && neighborhood.has(n.uuid)),
          } as EdgeData,
        } as Edge;
      }),
    ]);
  }, [nodes, cluster, overlay, overlayIP, structuralSig, selected, search, setRfNodes, setRfEdges]);

  const fitAll = useCallback(() => setResetNonce((n) => n + 1), []);

  const liveCount = (nodes ?? []).filter((n) => n.live && n.lifecycle !== "revoked" && !n.drained).length;

  return (
    <Card
      title={`Network topology${cluster && cluster.count > 1 ? ` — ${cluster.count} controllers (leader ${cluster.leader} ★)` : ""}`}
      info="The live DANI network as a constellation: the CONTROL PLANE — one controller per site in one Raft cluster (dashed sky links = raft replication, ★ = the elected leader; kill a controller and the survivors re-elect and the graph recenters) — with every enrolled node orbiting its home controller. Edges are the mTLS Link each node holds; green links carry live traffic (watch the particles flow), amber = drained, red = revoked. CLICK a node to focus it: the camera glides in, its links light up, the rest dims, and a detail panel opens — click empty space to release. Drag to rearrange (your layout sticks through refreshes); scroll to zoom; the search box finds a node in a big fleet. Switch to the WireGuard overlay to see the DANI-coordinated VPN addresses — DANI is its own overlay coordinator, no third party."
      actions={
        <div className="flex items-center gap-2">
          <div className="relative">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="find a node…"
              className="w-36 rounded-md border border-white/10 bg-black/30 px-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:w-44 focus:outline-none focus:ring-1 focus:ring-emerald-400/40"
            />
            {search && (
              <button onClick={() => setSearch("")} aria-label="clear search" className="absolute right-1.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                ✕
              </button>
            )}
          </div>
          <button
            onClick={fitAll}
            title="Re-form the constellation and fit it to view (clears manual drags)"
            className="rounded-md border border-white/10 px-2 py-1 text-xs text-slate-400 transition hover:bg-white/5 hover:text-slate-200"
          >
            ↺ Reset
          </button>
          <div className="flex items-center gap-1 rounded-lg bg-black/30 p-0.5">
            {(["serving", "wireguard"] as const).map((o) => (
              <button
                key={o}
                onClick={() => setOverlay(o)}
                className={`rounded-md px-2 py-1 text-xs transition ${overlay === o ? "bg-white/10 text-white" : "text-slate-400 hover:text-slate-200"}`}
              >
                {o === "serving" ? "Serving" : "WireGuard"}
              </button>
            ))}
          </div>
        </div>
      }
    >
      <div className="relative h-[34rem] w-full overflow-hidden rounded-lg border border-white/5 bg-[radial-gradient(120%_90%_at_50%_35%,rgba(34,211,238,0.06),transparent_60%),radial-gradient(90%_70%_at_50%_120%,rgba(118,185,0,0.07),transparent_60%)] bg-black/40">
        <span aria-hidden className="dn-aurora pointer-events-none absolute inset-0 -z-0" />
        <ReactFlowProvider>
          <Constellation
            nodes={rfNodes}
            edges={rfEdges}
            onNodesChange={onNodesChange}
            sig={structuralSig}
            selected={selected}
            onSelect={setSelected}
          />
        </ReactFlowProvider>
        {selectedNode && <DetailPanel node={selectedNode} onClose={() => setSelected(null)} />}
        <div className="pointer-events-none absolute bottom-3 left-3 z-10 rounded-md bg-black/40 px-2 py-1 text-[11px] text-slate-400 backdrop-blur">
          {liveCount} serving · {(nodes ?? []).length} enrolled{cluster && cluster.count > 1 ? ` · ${cluster.count} controllers` : ""}
        </div>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-slate-500">
        <span className="flex items-center gap-1">
          <Badge tone="ok">live</Badge>carries traffic
        </span>
        <span className="flex items-center gap-1">
          <Badge tone="warn">drained</Badge>no traffic, models migrate
        </span>
        <span className="flex items-center gap-1">
          <Badge tone="bad">revoked</Badge>evicted
        </span>
        <span className="flex items-center gap-1">
          🎓 trainer
          <InfoTip text="Dedicated training hardware (D17) never serves inference — it has no data-plane edge traffic even when live." />
        </span>
        <span className="ml-auto text-slate-500">click a node to focus · drag to arrange · scroll to zoom</span>
      </div>
    </Card>
  );
}
