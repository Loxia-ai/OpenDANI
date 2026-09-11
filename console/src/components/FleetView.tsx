import { api } from "../api";
import { usePoll } from "../usePoll";
import { Badge, Card, EmptyState, Mono, Stat, Table, Td, Th, Tr, stateTone } from "./ui";

// FleetView is the Overview's read-only summary of who is serving right now (live heartbeats). Fleet
// MANAGEMENT (offline nodes, drain, revoke, certs) lives in the Nodes tab.
export function FleetView() {
  const { data, error } = usePoll(api.fleet);
  const workers = data?.workers ?? [];
  const serving = workers.filter((w) => !w.Trainer).length;
  const trainers = workers.filter((w) => w.Trainer).length;
  const totalServed = workers.reduce((s, w) => s + (w.Served ?? 0), 0);

  return (
    <Card
      title="Live fleet"
      subtitle="Nodes with a fresh heartbeat, as the router sees them."
      info="This is the routing view: every node currently heartbeating, its engine, classification ceiling, live load (active/slots, +queued), and lifetime requests served. Trainers never serve inference (dedicated hardware). Drained nodes still heartbeat but take no traffic. For the full enrolled fleet, certificates, and control actions, use the Nodes tab."
    >
      {error && <p className="text-sm text-rose-300">{error}</p>}
      {!error && data && data.count === 0 && <EmptyState icon="◌" title="No nodes serving" hint="Enroll a worker to start handling requests." />}
      {data && data.count > 0 && (
        <>
          <div className="mb-3 grid grid-cols-3 gap-2 sm:max-w-md">
            <Stat label="serving nodes" value={serving} tone="ok" />
            <Stat label="trainers" value={trainers} tone="info" />
            <Stat label="requests served" value={totalServed} />
          </div>
          <Table
            head={
              <Tr>
                <Th>Node</Th>
                <Th>Role</Th>
                <Th>Health</Th>
                <Th>Class</Th>
                <Th>Site</Th>
                <Th>Engine</Th>
                <Th>Model</Th>
                <Th right>Load</Th>
                <Th right>Served</Th>
              </Tr>
            }
          >
            {workers.map((w) => (
              <Tr key={w.UUID}>
                <Td mono>
                  <Mono>{w.UUID}</Mono>
                </Td>
                <Td>
                  <Badge tone={w.Trainer ? "info" : "muted"}>{w.Trainer ? "trainer" : "worker"}</Badge>
                </Td>
                <Td>
                  <span className="flex gap-1">
                    <Badge tone={stateTone(w.Health)}>{w.Health}</Badge>
                    {w.Drained && <Badge tone="warn">drained</Badge>}
                  </span>
                </Td>
                <Td className="text-slate-300">{w.Class}</Td>
                <Td className="text-slate-400">{w.Site || "—"}</Td>
                <Td className="text-slate-400">
                  {w.Engine || "—"}
                  {w.Accel && w.Accel !== "cpu" && <span title={`GPU-accelerated (${w.Accel})`} className="ml-1 text-xs text-amber-300">⚡{w.Accel}</span>}
                </Td>
                <Td className="text-slate-300">
                  {w.Model || "—"}
                  {w.Loaded && w.Loaded.length > 0 && <span className="text-xs text-sky-300"> +{w.Loaded.length}</span>}
                </Td>
                <Td right className="text-slate-400">
                  {w.MaxConcurrent > 0 ? `${w.Active}/${w.MaxConcurrent}${w.Queued ? ` +${w.Queued}q` : ""}` : "—"}
                </Td>
                <Td right className="text-slate-400">
                  {w.Served ?? 0}
                </Td>
              </Tr>
            ))}
          </Table>
        </>
      )}
    </Card>
  );
}
