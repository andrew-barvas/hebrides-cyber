import "@testing-library/jest-dom/vitest";

// jsdom doesn't implement ResizeObserver, which several dashboard
// components (charts, layout-measuring widgets) rely on — without this
// stub every test that renders one throws "ResizeObserver is not defined"
// before assertions even run.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
global.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;
