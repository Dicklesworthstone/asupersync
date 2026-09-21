import {
  ReactRuntimeProvider,
  useReactRuntimeContext,
  useReactRuntimeDiagnostics,
  useReactScope,
} from "@asupersync/react";
import React from "react";
import { createRoot } from "react-dom/client";

function RuntimeProbe(): JSX.Element {
  const context = useReactRuntimeContext();
  const diagnostics = useReactRuntimeDiagnostics();
  const scope = useReactScope({
    label: "react-consumer-fixture",
  });

  return (
    <section>
      <h1>Asupersync React Fixture</h1>
      <p data-testid="runtime-status">runtime:{context.status}</p>
      <p data-testid="scope-status">scope:{scope.status}</p>
      <p data-testid="support-status">supported:{diagnostics.supported ? "yes" : "no"}</p>
    </section>
  );
}

function App(): JSX.Element {
  return (
    <ReactRuntimeProvider>
      <RuntimeProbe />
    </ReactRuntimeProvider>
  );
}

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Expected #root element in React consumer fixture.");
}

createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
