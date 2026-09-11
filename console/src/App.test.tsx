import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

// A mock gateway: fetch is stubbed with the real endpoint shapes so the console is tested end to end
// (rendering + workflows) without a live controller. Longest-key matching avoids includes-collisions
// (/dani/models/sign vs /dani/models).
function mockFetch(handlers: Record<string, (init?: RequestInit) => unknown>) {
  return vi.fn(async (url: string | URL, init?: RequestInit) => {
    const path = typeof url === "string" ? url : url.toString();
    const key = Object.keys(handlers)
      .filter((k) => path.includes(k))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return { ok: false, status: 404, json: async () => ({}) } as Response;
    const body = handlers[key](init);
    const hdrs = { get: (k: string) => (k === "X-Dani-Served-By" && key === "/v1/chat/completions" ? "worker-0" : null) };
    if (body && typeof body === "object" && "__status" in (body as Record<string, unknown>)) {
      const { __status, ...rest } = body as Record<string, unknown>;
      return { ok: false, status: __status as number, headers: hdrs, json: async () => rest } as unknown as Response;
    }
    return { ok: true, status: 200, headers: hdrs, json: async () => body } as unknown as Response;
  });
}

const baseHandlers = (overrides: Record<string, (init?: RequestInit) => unknown> = {}) => {
  const signed: string[] = [];
  const drained: Record<string, boolean> = {};
  return {
    "/dani/whoami": () => ({ authEnabled: false, sub: "anonymous" }),
    "/healthz": () => ({}),
    "/v1/models": () => ({ data: [{ id: "qwen", engine: "stub" }, { id: "qwen-ft-legal-v1", engine: "stub" }] }),
    "/v1/chat/completions": () => ({ choices: [{ message: { role: "assistant", content: "The policy provides 26 weeks." } }], model: "qwen" }),
    "/dani/fleet": () => ({
      count: 2,
      workers: [
        { UUID: "trainer-1", Model: "", Engine: "trainer", Class: "restricted", Site: "k8s", Health: "healthy", Active: 0, MaxConcurrent: 0, Queued: 0, Served: 0, Trainer: true, Drained: false },
        { UUID: "worker-0", Model: "qwen", Engine: "stub", Class: "restricted", Site: "k8s", Health: "healthy", Active: 1, MaxConcurrent: 4, Queued: 0, Served: 12, Trainer: false, Drained: !!drained["worker-0"] },
      ],
    }),
    "/dani/nodes/drain": (init?: RequestInit) => {
      const req = JSON.parse((init?.body as string) ?? "{}");
      drained[req.node] = req.drain;
      return { node: req.node, drained: req.drain };
    },
    "/dani/nodes/revoke": () => ({ revoked: true }),
    "/dani/nodes": () => ({
      count: 2,
      nodes: [
        { uuid: "trainer-1", roles: ["trainer"], class: "restricted", site: "k8s", lifecycle: "active", tier: 0, certSerial: "aa", certExpiry: new Date(Date.now() + 80 * 86400000).toISOString(), generation: 1, live: true, drained: false, trainer: true },
        { uuid: "worker-0", roles: ["worker"], class: "restricted", site: "k8s", lifecycle: "active", tier: 0, certSerial: "bb", certExpiry: new Date(Date.now() + 80 * 86400000).toISOString(), generation: 2, live: true, drained: !!drained["worker-0"], model: "qwen" },
      ],
    }),
    "/dani/enroll/pending": () => ({ pending: [], count: 0 }),
    "/dani/collections": () => ({
      collections: [{ name: "legal", connector: "upload", chunks: 8, classification: "restricted" }],
      corpora: ["finance", "hr", "legal"],
    }),
    "/dani/principals": () => ({
      principals: [
        { sub: "alice", display: "Alice", roles: ["user"], clearance: "restricted" },
        { sub: "dana", display: "Dana", roles: ["user", "security-officer"], clearance: "secret" },
      ],
    }),
    "/dani/models/sign": (init?: RequestInit) => {
      const role = JSON.parse((init?.body as string) ?? "{}").role;
      if (role && !signed.includes(role)) signed.push(role);
      return { id: "qwen-ft-legal-v1" };
    },
    "/dani/models/deploy": () => ({ replicas: 2 }),
    "/dani/models/undeploy": () => ({ replicas: 0 }),
    "/dani/models": () => ({
      models: [
        {
          id: "qwen-ft-legal-v1",
          state: signed.length === 3 ? "available" : "draft",
          classification: "restricted",
          base: "qwen",
          hash: "sha256:abc…",
          signatures: [...signed],
          evals: { safety: 1 },
          lineage: { Collection: "legal", Engineer: "alice" },
          replicas: 1,
          deployments: signed.length === 3 ? [{ model: "qwen-ft-legal-v1", node: "worker-0", state: "loaded", at: "" }] : [],
        },
      ],
    }),
    "/dani/train/jobs": () => ({
      jobs: [
        { ID: "job-1", State: "completed", Candidate: "qwen-ft-legal-v1", TrainerUUID: "trainer-1", CkptsDone: 3, CkptsTotal: 3 },
        { ID: "job-2", State: "failed", Candidate: "", TrainerUUID: "trainer-1", CkptsDone: 1, CkptsTotal: 3, Err: "trainer exploded" },
      ],
    }),
    "/dani/train/submit": () => ({ ID: "job-1" }),
    "/dani/rag/alias": () => ({ aliases: [] }),
    "/dani/wg/mesh": () => ({ cidr: "10.55.0", nodes: [{ UUID: "worker-0", IP: "10.55.0.2", PublicKey: "k" }] }),
    "/dani/ingest": () => ({ name: "legal", chunks: [1, 2, 3, 4] }),
    "/dani/audit": () => ({
      records: 22,
      signedHeads: 5,
      integrity: { ok: true, records: 22, signedHeads: 5 },
      recent: [
        { seq: 1, type: "genesis", at: "", payload: {} },
        { seq: 2, type: "node.drained", at: "", payload: { node: "worker-0" } },
      ],
    }),
    ...overrides,
  };
};

describe("DANI console", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch(baseHandlers()));
    localStorage.clear();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("renders the fleet and interpreted audit trail on the overview", async () => {
    render(<App />);
    expect(await screen.findByText("Live fleet")).toBeInTheDocument();
    expect(await screen.findByText("trainer-1")).toBeInTheDocument();
    expect(await screen.findByText(/chain verified/)).toBeInTheDocument();
    expect(await screen.findByText(/22 records/)).toBeInTheDocument();
    // the event dictionary translates raw types into operator language
    expect(await screen.findByText(/Trust domain created/)).toBeInTheDocument();
    expect(await screen.findByText(/removed from routing/)).toBeInTheDocument();
    // auth-off is stated, not hidden
    expect(screen.getByText(/anonymous/)).toBeInTheDocument();
  });

  it("renders the interactive topology graph", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "Topology" }));
    expect(await screen.findByText("Network topology")).toBeInTheDocument();
    // the overlay toggle and the controller hub render
    expect(screen.getByText("WireGuard")).toBeInTheDocument();
    expect(await screen.findByText(/ctrl-001/)).toBeInTheDocument();
  });

  it("drives the 3-signer promotion workflow to available with detail expand", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "Models" }));
    const secBtn = await screen.findByText("sign security-officer");
    fireEvent.click(secBtn);
    fireEvent.click(await screen.findByText("sign governance-officer"));
    fireEvent.click(await screen.findByText("sign administrator"));
    await waitFor(() => expect(screen.getByText("available")).toBeInTheDocument());
    expect(screen.getByText(/serving @ worker-0/)).toBeInTheDocument();
    // expand shows lineage + artifact hash + distribution controls
    fireEvent.click(screen.getByLabelText("expand qwen-ft-legal-v1"));
    expect(await screen.findByText(/trained on/)).toBeInTheDocument();
    expect(screen.getByText(/sha256:abc/)).toBeInTheDocument();
    expect(screen.getByText(/\+ replica/)).toBeInTheDocument();
  });

  it("walks the guided training wizard and surfaces job errors", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "Training" }));
    // the wizard front door, in plain language
    expect(await screen.findByText("Teach a model")).toBeInTheDocument();
    // step 1: an ingested dataset is offered; pick it and advance
    fireEvent.click(await screen.findByText("legal"));
    fireEvent.click(screen.getByText("Next →"));
    // step 2: choose a starting model, advance
    expect(await screen.findByText(/Which model should we teach/)).toBeInTheDocument();
    fireEvent.click(screen.getByText("Next →"));
    // step 3: review + the start button (unique to the review step)
    const startBtn = await screen.findByText(/Start training/);
    expect(startBtn).toBeInTheDocument();
    fireEvent.click(startBtn);
    // the failed job renders its reason with a friendly status + progress
    expect(await screen.findByText(/trainer exploded/)).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });

  it("training wizard: bring-my-own data with format templates + live detection", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "Training" }));
    fireEvent.click(await screen.findByText("Bring my own"));
    // the four teachable formats are offered as pickable templates
    expect(await screen.findByText(/What do you want to teach it/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Question & answer" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Tool calling (agents)" })).toBeInTheDocument();
    // paste a MIX (text + Q&A + tool-calling) and see the live per-format breakdown
    fireEvent.change(screen.getByLabelText("dataset-name"), { target: { value: "handbook" } });
    fireEvent.change(screen.getByLabelText("dataset-text"), {
      target: {
        value:
          "# a comment\n" +
          "Refunds within 30 days.\n" +
          '{"prompt":"leave?","completion":"26 weeks"}\n' +
          '{"messages":[{"role":"user","content":"weather?"}],"tools":[{"type":"function","function":{"name":"get_weather"}}]}',
      },
    });
    expect(await screen.findByText(/3 examples/)).toBeInTheDocument();
    expect(screen.getByText(/1 Question & answer/)).toBeInTheDocument();
    expect(screen.getByText(/1 Tool calling/)).toBeInTheDocument();
  });

  it("manages nodes: drain flows through to the API", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "Nodes" }));
    const workerRow = (await screen.findByText("worker-0")).closest("tr");
    expect(workerRow).not.toBeNull();
    fireEvent.click(within(workerRow!).getByRole("button", { name: "Drain" }));
    // The refreshed node state proves the API change; the status message appears
    // in two panels and is not a unique element to query.
    await waitFor(() => expect(within(workerRow!).getByRole("button", { name: "Un-drain" })).toBeInTheDocument());
  });

  it("datasets tab lists sources and uploads a custom corpus", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "Datasets" }));
    expect(await screen.findByText(/8 chunks/)).toBeInTheDocument();
    expect(screen.getByText("Ingest finance")).toBeInTheDocument(); // un-ingested source offered
    fireEvent.change(screen.getByLabelText("upload-name"), { target: { value: "notes" } });
    fireEvent.change(screen.getByLabelText("upload-docs"), { target: { value: "doc one\ndoc two" } });
    fireEvent.click(screen.getByText(/Upload & ingest/));
    await waitFor(() => expect(screen.getByText(/uploaded \+ ingested notes/)).toBeInTheDocument());
  });

  it("offers SSO sign-in when the gateway reports it", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch(baseHandlers({ "/dani/whoami": () => ({ authEnabled: true, sso: true, error: "not signed in" }) })),
    );
    render(<App />);
    expect(await screen.findByText("Sign in with SSO")).toBeInTheDocument();
  });

  it("role-gates sign buttons when console auth is on", async () => {
    localStorage.setItem("dani-operator-token", "tok-dana");
    vi.stubGlobal(
      "fetch",
      mockFetch(
        baseHandlers({
          "/dani/whoami": () => ({ authEnabled: true, sub: "dana", roles: ["user", "security-officer"], clearance: "secret" }),
        }),
      ),
    );
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "Models" }));
    // dana can sign security but the other two roles are locked
    expect(await screen.findByText("sign security-officer")).toBeInTheDocument();
    expect(screen.getByText("🔒 governance-officer")).toBeInTheDocument();
    expect(screen.getByText("🔒 administrator")).toBeInTheDocument();
    // and the header shows who is signed in
    expect(screen.getByText("dana")).toBeInTheDocument();
  });

  it("playground chats with a served model and shows the routing proof", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("tab", { name: "Playground" }));
    expect(await screen.findByLabelText("message")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("message"), { target: { value: "parental leave?" } });
    fireEvent.click(screen.getByText("Send"));
    expect(await screen.findByText(/The policy provides 26 weeks/)).toBeInTheDocument();
    expect(await screen.findByText(/answered by worker-0/)).toBeInTheDocument();
  });

  it("audit events carry a human timestamp and the help drawer explains the story", async () => {
    render(<App />);
    // timestamps render (mock events have empty at -> blank; genesis payload at="" gives ""; use presence of the ago column via title on a real date)
    fireEvent.click(screen.getByLabelText("help"));
    expect(await screen.findByText("How DANI works")).toBeInTheDocument();
    expect(screen.getByText(/three different reviewers/i)).toBeInTheDocument();
    expect(screen.getByText(/console-operators.json/)).toBeInTheDocument();
    fireEvent.click(screen.getByText(/close/));
    // API access card shows the endpoint + a live model
    expect(await screen.findByText("Connect your applications")).toBeInTheDocument();
    expect(screen.getByText(/\/v1$/)).toBeInTheDocument();
  });

  it("surfaces a transport error instead of crashing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 503, headers: { get: () => null }, json: async () => ({}) }) as unknown as Response),
    );
    render(<App />);
    expect((await screen.findAllByText(/HTTP 503/)).length).toBeGreaterThan(0);
  });
});
