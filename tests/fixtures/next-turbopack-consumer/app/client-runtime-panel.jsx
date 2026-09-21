"use client";

import { createNextBootstrapAdapter, detectNextRuntimeSupport } from "@asupersync/next";
import { useEffect, useRef, useState } from "react";

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

export default function ClientRuntimePanel() {
  const adapterRef = useRef(null);
  const [support] = useState(() => detectNextRuntimeSupport("client"));
  const [snapshot, setSnapshot] = useState(null);
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState("idle");
  const [failure, setFailure] = useState(null);

  function syncFromAdapter() {
    const adapter = adapterRef.current;
    if (!adapter) {
      return;
    }
    setSnapshot(adapter.snapshot());
    setEvents([...adapter.events()]);
  }

  async function rebootstrap() {
    const adapter = adapterRef.current;
    if (!adapter) {
      return;
    }

    setStatus("bootstrapping");
    setFailure(null);

    try {
      const outcome = await adapter.ensureRuntimeReady();
      syncFromAdapter();
      setStatus(outcome.outcome);
      if (outcome.outcome !== "ok") {
        setFailure(pretty(outcome));
      }
    } catch (error) {
      syncFromAdapter();
      setStatus("error");
      setFailure(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
    }
  }

  function applyMutation(run) {
    try {
      run();
      syncFromAdapter();
    } catch (error) {
      syncFromAdapter();
      setStatus("error");
      setFailure(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
    }
  }

  useEffect(() => {
    const adapter = createNextBootstrapAdapter({
      initialRouteSegment: "/",
      label: "maintained-next-example",
    });
    adapterRef.current = adapter;
    setSnapshot(adapter.snapshot());

    void rebootstrap();

    return () => {
      adapter.close("component_unmount");
      adapterRef.current = null;
    };
  }, []);

  return (
    <section
      style={{
        border: "1px solid #d0d7de",
        borderRadius: "16px",
        padding: "24px",
        background: "#ffffff",
      }}
    >
      <h2 style={{ marginTop: 0 }}>Client runtime panel</h2>
      <p>
        This client component owns the direct-runtime path. It hydrates, initializes the Browser
        Edition runtime, and records bootstrap events so you can inspect the lifecycle boundaries
        explicitly.
      </p>

      <div style={{ display: "flex", gap: "12px", flexWrap: "wrap", marginBottom: "16px" }}>
        <button
          type="button"
          onClick={() => {
            const adapter = adapterRef.current;
            if (!adapter) {
              return;
            }
            applyMutation(() => {
              adapter.navigate("hard_navigation", "/reports");
            });
            void rebootstrap();
          }}
        >
          Simulate hard navigation
        </button>

        <button
          type="button"
          onClick={() => {
            const adapter = adapterRef.current;
            if (!adapter) {
              return;
            }
            applyMutation(() => {
              adapter.cacheRevalidated();
            });
          }}
        >
          Simulate cache revalidation
        </button>

        <button
          type="button"
          onClick={() => {
            const adapter = adapterRef.current;
            if (!adapter) {
              return;
            }
            applyMutation(() => {
              adapter.cancelBootstrap("user_requested_retry");
            });
          }}
        >
          Simulate cancellation
        </button>

        <button type="button" onClick={() => void rebootstrap()}>
          Re-bootstrap
        </button>
      </div>

      <p>
        <strong>Status:</strong> <code>{status}</code>
      </p>

      <pre id="client-runtime-support">{pretty(support)}</pre>
      <pre id="client-bootstrap-snapshot">{pretty(snapshot)}</pre>
      <pre id="client-bootstrap-events">{pretty(events)}</pre>

      {failure ? <pre id="client-bootstrap-failure">{failure}</pre> : null}
    </section>
  );
}
