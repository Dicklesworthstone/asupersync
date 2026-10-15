import { createNextServerBridgeAdapter } from "@asupersync/next";

export async function GET() {
  const bridge = createNextServerBridgeAdapter({
    renderEnvironment: "node_server",
    routeSegment: "/api/server-bridge",
    reproCommand: "PATH=/usr/bin:$PATH bash scripts/validate_next_turbopack_consumer.sh",
  });

  const request = bridge.createRequest(
    "load_server_bridge_preview",
    {
      mode: "bridge_only",
      source: "next-maintained-example",
    },
    {
      requestId: "server-bridge-preview",
    },
  );

  return Response.json({
    diagnostics: bridge.diagnostics(),
    request,
    response: bridge.ok({
      directRuntime: false,
      note: "Server route handlers must stay on the serialized bridge path.",
    }),
  });
}
