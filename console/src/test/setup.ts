import "@testing-library/jest-dom";

// jsdom lacks ResizeObserver + the DOMMatrix/getBBox APIs React Flow (@xyflow) touches on mount.
// Minimal stubs so the topology view renders under the component tests (real sizing is a browser
// concern, covered by the Playwright E2E against the live console).
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
const g = global as unknown as Record<string, unknown>;
g.ResizeObserver = g.ResizeObserver ?? ResizeObserverStub;
if (typeof g.DOMMatrixReadOnly === "undefined") {
  g.DOMMatrixReadOnly = class {
    m22 = 1;
  };
}
