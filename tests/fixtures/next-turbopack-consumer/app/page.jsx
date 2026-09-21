import { createNextServerBridgeAdapter, detectNextRuntimeSupport } from "@asupersync/next";

import ClientRuntimePanel from "./client-runtime-panel";

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

export default function HomePage() {
  const serverBridge = createNextServerBridgeAdapter({
    renderEnvironment: "server_component",
    routeSegment: "/",
    reproCommand: "PATH=/usr/bin:$PATH bash scripts/validate_next_turbopack_consumer.sh",
  });
  const serverDiagnostics = serverBridge.diagnostics();
  const serverRequest = serverBridge.createRequest(
    "load_home_page_example",
    {
      example: "next-client-bridge",
      intent: "serialize-only",
    },
    {
      requestId: "home-page-preview",
      routeSegment: "/",
    },
  );
  const serverResponse = serverBridge.ok({
    directRuntime: false,
    message: "Server components stay bridge-only and exchange only serializable data.",
    nextStep: "Create Browser Edition runtime handles from app/client-runtime-panel.jsx instead.",
  });
  const edgeDiagnostics = detectNextRuntimeSupport("edge");

  return (
    <main
      style={{
        margin: "0 auto",
        maxWidth: "1100px",
        padding: "48px 24px 64px",
        fontFamily:
          'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        lineHeight: 1.5,
      }}
    >
      <header style={{ marginBottom: "32px" }}>
        <p
          style={{
            letterSpacing: "0.08em",
            margin: 0,
            textTransform: "uppercase",
            fontSize: "0.8rem",
            color: "#57606a",
          }}
        >
          Asupersync Browser Edition
        </p>
        <h1 style={{ fontSize: "2.5rem", marginBottom: "12px" }}>
          Next.js maintained example with explicit client and bridge boundaries
        </h1>
        <p style={{ maxWidth: "70ch", color: "#3d444d" }}>
          This page is a server component. It does not create a Browser Edition runtime directly.
          Instead, it renders bridge-only diagnostics for server and edge boundaries and delegates
          direct runtime ownership to a client component.
        </p>
      </header>

      <section
        style={{
          display: "grid",
          gap: "24px",
          gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
          marginBottom: "32px",
        }}
      >
        <article
          style={{
            border: "1px solid #d0d7de",
            borderRadius: "16px",
            padding: "20px",
            background: "#f6f8fa",
          }}
        >
          <h2 style={{ marginTop: 0 }}>Client direct-runtime lane</h2>
          <p>
            The panel below lives in a client component and uses{" "}
            <code>createNextBootstrapAdapter(...)</code> to run the hydrated browser path.
          </p>
        </article>

        <article
          style={{
            border: "1px solid #d0d7de",
            borderRadius: "16px",
            padding: "20px",
            background: "#fff8c5",
          }}
        >
          <h2 style={{ marginTop: 0 }}>Server bridge-only lane</h2>
          <p>
            Server components stay serialized. This example creates a bridge adapter and sample
            request/response payload instead of touching the browser runtime directly.
          </p>
        </article>

        <article
          style={{
            border: "1px solid #d0d7de",
            borderRadius: "16px",
            padding: "20px",
            background: "#ffe2db",
          }}
        >
          <h2 style={{ marginTop: 0 }}>Edge bridge-only lane</h2>
          <p>
            Edge paths surface diagnostics explicitly. Direct Browser Edition execution stays
            disabled there.
          </p>
        </article>
      </section>

      <ClientRuntimePanel />

      <section
        style={{
          display: "grid",
          gap: "24px",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          marginTop: "32px",
        }}
      >
        <article>
          <h2>Server component bridge preview</h2>
          <pre id="server-bridge-diagnostics">{pretty(serverDiagnostics)}</pre>
          <pre id="server-bridge-request">{pretty(serverRequest)}</pre>
          <pre id="server-bridge-response">{pretty(serverResponse)}</pre>
        </article>

        <article>
          <h2>Edge boundary diagnostics</h2>
          <pre id="edge-runtime-diagnostics">{pretty(edgeDiagnostics)}</pre>
          <p>
            Route handlers are available at <code>/api/server-bridge</code> and{" "}
            <code>/api/edge-bridge</code>.
          </p>
        </article>
      </section>
    </main>
  );
}
