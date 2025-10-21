import { describe, expect, it } from "vitest";
import { reducer, type ActionKind } from "@/lib/mock/sim";
import type { SimulationState, Instance, Action } from "@/lib/mock/types";

const baseState = (): SimulationState => ({
  instances: new Map(),
  recentActions: [],
  totals: {
    actionsLast60s: Array.from({ length: 60 }, () => 0),
    deniedLast60s: Array.from({ length: 60 }, () => 0),
    cursor: 0,
  },
});

const instance: Instance = {
  id: "instance-1",
  agent: "codex",
  platform: "linux",
  status: "online",
  lastSeen: 0,
};

const makeAction = (overrides: Partial<Action> = {}): Action => ({
  id: "evt-1",
  instanceId: instance.id,
  type: "file/open",
  name: "/dev/tty",
  ts: 0,
  allowed: true,
  ...overrides,
});

const ingest = (state: SimulationState, action: Action): SimulationState =>
  reducer(state, {
    type: "ingest",
    payload: {
      action,
      instance,
      raw: {},
    },
  } as ActionKind);

describe("simulation reducer ingest", () => {
  it("records the first occurrence with repeatCount 1", () => {
    const first = makeAction();
    const state1 = ingest(baseState(), first);
    expect(state1.recentActions).toHaveLength(1);
    expect(state1.recentActions[0]).toMatchObject({ id: first.id, repeatCount: 1 });
    expect(state1.totals.actionsLast60s[0]).toBe(1);
  });

  it("folds identical events and bumps repeatCount", () => {
    const initial = ingest(baseState(), makeAction());
    const second = makeAction({ id: "evt-2", ts: 10 });
    const state2 = ingest(initial, second);
    expect(state2.recentActions).toHaveLength(1);
    expect(state2.recentActions[0]).toMatchObject({ id: "evt-2", repeatCount: 2 });
    expect(state2.totals.actionsLast60s[0]).toBe(2);
  });

  it("keeps distinct events separate while folding repeats", () => {
    const firstState = ingest(baseState(), makeAction());
    const withNetwork = ingest(firstState, makeAction({
      id: "evt-net",
      type: "net/connect",
      name: "api.openai.com /v1",
      allowed: false,
      ts: 1000,
    }));
    expect(withNetwork.recentActions).toHaveLength(2);

    const repeated = ingest(withNetwork, makeAction({ id: "evt-3", ts: 1500 }));
    expect(repeated.recentActions).toHaveLength(2);
    const [older, newest] = repeated.recentActions;
    expect(older).toMatchObject({ id: "evt-net", repeatCount: 1 });
    expect(newest).toMatchObject({ id: "evt-3", repeatCount: 2, name: "/dev/tty" });
  });
});
