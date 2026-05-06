import {
  BROWSER_NATIVE_MESSAGING_OPERATION_FAILED_CODE,
  BROWSER_NATIVE_MESSAGING_UNSUPPORTED_CODE,
  BROWSER_NATIVE_STREAM_UNSUPPORTED_CODE,
  createBrowserBroadcastChannel,
  createBrowserMessageChannel,
  createBrowserReadableStream,
  createBrowserWritableStream,
  detectBrowserNativeMessagingSupport,
  detectBrowserNativeStreamSupport,
  type BrowserNativeMessagingCapability,
  type BrowserNativeStreamCapability,
} from "@asupersync/browser";

type ScenarioRow = {
  bead_id: "asupersync-41hk0t";
  scenario_id: string;
  host_context: string;
  api_surface: string;
  capability_granted: boolean;
  degraded_mode: boolean;
  bytes_sent: number;
  bytes_received: number;
  messages_sent: number;
  messages_received: number;
  close_kind: string;
  expected_error: string | null;
  actual_error: string | null;
  verdict: "pass" | "fail";
  first_failure: string | null;
};

type ScenarioResult = Omit<ScenarioRow, "bead_id" | "host_context"> & {
  condition: boolean;
};

const BEAD_ID = "asupersync-41hk0t" as const;
const MARKER = "browser-native-message-stream-consumer";
const MESSAGE_CAPABILITY: BrowserNativeMessagingCapability = {
  capabilityGranted: true,
  redactionPolicy: "metadata_only",
};
const STREAM_CAPABILITY: BrowserNativeStreamCapability = {
  capabilityGranted: true,
  redactionPolicy: "metadata_only",
};
const REQUIRED_SCENARIOS = [
  "message_channel_text_roundtrip",
  "message_channel_bytes_roundtrip",
  "message_port_close_rejects_send",
  "message_port_abort_is_sticky",
  "broadcast_channel_delivery",
  "readable_stream_bytes",
  "writable_stream_bytes",
  "capability_denied",
  "degraded_mode_denied",
];
const PUBLIC_ENTRYPOINT_MARKERS = [
  "detectBrowserNativeMessagingSupport",
  "createBrowserMessageChannel",
  "createBrowserBroadcastChannel",
  "detectBrowserNativeStreamSupport",
  "createBrowserReadableStream",
  "createBrowserWritableStream",
];

const statusElement = document.getElementById("status");
if (!statusElement) {
  throw new Error("status element missing");
}

function render(value: unknown): void {
  statusElement.textContent = JSON.stringify(value, null, 2);
}

function hostContext(): string {
  return typeof window === "object" && typeof document === "object"
    ? "browser_main_thread"
    : "unknown";
}

function makeRow(result: ScenarioResult): ScenarioRow {
  const firstFailure = result.condition ? null : "scenario assertion failed";
  return {
    bead_id: BEAD_ID,
    scenario_id: result.scenario_id,
    host_context: hostContext(),
    api_surface: result.api_surface,
    capability_granted: result.capability_granted,
    degraded_mode: result.degraded_mode,
    bytes_sent: result.bytes_sent,
    bytes_received: result.bytes_received,
    messages_sent: result.messages_sent,
    messages_received: result.messages_received,
    close_kind: result.close_kind,
    expected_error: result.expected_error,
    actual_error: result.actual_error,
    verdict: result.condition ? "pass" : "fail",
    first_failure: firstFailure,
  };
}

function errorCode(error: unknown): string | null {
  if (
    typeof error === "object"
    && error !== null
    && "code" in error
    && typeof (error as { code?: unknown }).code === "string"
  ) {
    return (error as { code: string }).code;
  }
  return null;
}

function errorReason(error: unknown): string | null {
  if (
    typeof error === "object"
    && error !== null
    && "diagnostics" in error
    && typeof (error as { diagnostics?: unknown }).diagnostics === "object"
    && (error as { diagnostics?: unknown }).diagnostics !== null
    && "reason" in ((error as { diagnostics: Record<string, unknown> }).diagnostics)
  ) {
    const reason = (error as { diagnostics: Record<string, unknown> }).diagnostics
      .reason;
    return typeof reason === "string" ? reason : null;
  }
  return null;
}

function firstFailure(error: unknown): string | null {
  if (
    typeof error === "object"
    && error !== null
    && "diagnostics" in error
    && typeof (error as { diagnostics?: unknown }).diagnostics === "object"
    && (error as { diagnostics?: unknown }).diagnostics !== null
    && "firstFailure" in ((error as { diagnostics: Record<string, unknown> }).diagnostics)
  ) {
    const failure = (error as { diagnostics: Record<string, unknown> }).diagnostics
      .firstFailure;
    return typeof failure === "string" ? failure : null;
  }
  return null;
}

function delay(ms = 0): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function waitFor<T>(
  observe: () => T | null,
  description: string,
): Promise<T> {
  const startedAt = performance.now();
  return new Promise((resolve, reject) => {
    const poll = () => {
      const value = observe();
      if (value !== null) {
        resolve(value);
        return;
      }
      if (performance.now() - startedAt > 2000) {
        reject(new Error(`timed out waiting for ${description}`));
        return;
      }
      window.setTimeout(poll, 10);
    };
    poll();
  });
}

async function messageChannelTextRoundtrip(): Promise<ScenarioRow> {
  const support = detectBrowserNativeMessagingSupport("message_channel", {
    capability: MESSAGE_CAPABILITY,
  });
  const channel = createBrowserMessageChannel({ support });
  const payload = "browser-native-message-stream-consumer:text";
  channel.port2.onMessage(() => undefined);
  channel.port1.send(payload);
  const received = await waitFor(
    () => channel.port2.takeMessages()[0] ?? null,
    "message_channel_text_roundtrip",
  );
  channel.close();
  return makeRow({
    scenario_id: "message_channel_text_roundtrip",
    api_surface: "message_channel",
    capability_granted: support.capabilityGranted,
    degraded_mode: support.degradedMode,
    bytes_sent: new TextEncoder().encode(payload).byteLength,
    bytes_received: new TextEncoder().encode(String(received)).byteLength,
    messages_sent: 1,
    messages_received: 1,
    close_kind: "clean_close",
    expected_error: null,
    actual_error: null,
    condition: received === payload,
  });
}

async function messageChannelBytesRoundtrip(): Promise<ScenarioRow> {
  const support = detectBrowserNativeMessagingSupport("message_channel", {
    capability: MESSAGE_CAPABILITY,
  });
  const channel = createBrowserMessageChannel({ support });
  const payload = Uint8Array.from([1, 3, 5, 8, 13, 21]);
  channel.port2.onMessage(() => undefined);
  channel.port1.send(payload);
  const received = await waitFor(
    () => channel.port2.takeMessages()[0] ?? null,
    "message_channel_bytes_roundtrip",
  );
  channel.close();
  const receivedBytes = received instanceof Uint8Array ? received : new Uint8Array();
  return makeRow({
    scenario_id: "message_channel_bytes_roundtrip",
    api_surface: "message_channel",
    capability_granted: support.capabilityGranted,
    degraded_mode: support.degradedMode,
    bytes_sent: payload.byteLength,
    bytes_received: receivedBytes.byteLength,
    messages_sent: 1,
    messages_received: 1,
    close_kind: "clean_close",
    expected_error: null,
    actual_error: null,
    condition:
      receivedBytes.byteLength === payload.byteLength
      && receivedBytes.every((byte, index) => byte === payload[index]),
  });
}

async function messagePortCloseRejectsSend(): Promise<ScenarioRow> {
  const support = detectBrowserNativeMessagingSupport("message_channel", {
    capability: MESSAGE_CAPABILITY,
  });
  const channel = createBrowserMessageChannel({ support });
  channel.port1.close();
  channel.port1.close();
  let caught: unknown = null;
  try {
    channel.port1.send("closed");
  } catch (error) {
    caught = error;
  }
  channel.port2.close();
  const actual = `${errorCode(caught) ?? "missing"}:${errorReason(caught) ?? "missing"}`;
  return makeRow({
    scenario_id: "message_port_close_rejects_send",
    api_surface: "message_port",
    capability_granted: support.capabilityGranted,
    degraded_mode: support.degradedMode,
    bytes_sent: 0,
    bytes_received: 0,
    messages_sent: 0,
    messages_received: 0,
    close_kind: "close",
    expected_error: `${BROWSER_NATIVE_MESSAGING_OPERATION_FAILED_CODE}:closed`,
    actual_error: actual,
    condition: actual === `${BROWSER_NATIVE_MESSAGING_OPERATION_FAILED_CODE}:closed`,
  });
}

async function messagePortAbortIsSticky(): Promise<ScenarioRow> {
  const support = detectBrowserNativeMessagingSupport("message_channel", {
    capability: MESSAGE_CAPABILITY,
  });
  const channel = createBrowserMessageChannel({ support });
  channel.port1.abort("operator_abort");
  channel.port1.abort("later_abort");
  let caught: unknown = null;
  try {
    channel.port1.send("aborted");
  } catch (error) {
    caught = error;
  }
  channel.port2.close();
  const actual = [
    errorCode(caught) ?? "missing",
    errorReason(caught) ?? "missing",
    firstFailure(caught) ?? "missing",
  ].join(":");
  return makeRow({
    scenario_id: "message_port_abort_is_sticky",
    api_surface: "message_port",
    capability_granted: support.capabilityGranted,
    degraded_mode: support.degradedMode,
    bytes_sent: 0,
    bytes_received: 0,
    messages_sent: 0,
    messages_received: 0,
    close_kind: "abort",
    expected_error: `${BROWSER_NATIVE_MESSAGING_OPERATION_FAILED_CODE}:aborted:operator_abort`,
    actual_error: actual,
    condition:
      actual
      === `${BROWSER_NATIVE_MESSAGING_OPERATION_FAILED_CODE}:aborted:operator_abort`,
  });
}

async function broadcastChannelDelivery(): Promise<ScenarioRow> {
  const support = detectBrowserNativeMessagingSupport("broadcast_channel", {
    capability: MESSAGE_CAPABILITY,
  });
  const name = `asupersync-${Date.now()}-${Math.random()}`;
  const sender = createBrowserBroadcastChannel(name, { support });
  const receiver = createBrowserBroadcastChannel(name, { support });
  const payload = "browser-native-message-stream-consumer:broadcast";
  sender.onMessage(() => undefined);
  receiver.onMessage(() => undefined);
  sender.post(payload);
  const received = await waitFor(
    () => receiver.takeMessages()[0] ?? null,
    "broadcast_channel_delivery",
  );
  await delay(50);
  const senderReceived = sender.takeMessages();
  sender.close();
  receiver.close();
  return makeRow({
    scenario_id: "broadcast_channel_delivery",
    api_surface: "broadcast_channel",
    capability_granted: support.capabilityGranted,
    degraded_mode: support.degradedMode,
    bytes_sent: new TextEncoder().encode(payload).byteLength,
    bytes_received: new TextEncoder().encode(String(received)).byteLength,
    messages_sent: 1,
    messages_received: 1,
    close_kind: "clean_close",
    expected_error: null,
    actual_error: null,
    condition: received === payload && senderReceived.length === 0,
  });
}

async function readableStreamBytes(): Promise<ScenarioRow> {
  const support = detectBrowserNativeStreamSupport("readable_stream", {
    capability: STREAM_CAPABILITY,
  });
  const payload = Uint8Array.from([2, 4, 6, 8, 10]);
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(payload);
      controller.close();
    },
  });
  const readable = createBrowserReadableStream(stream, { support });
  const received = await readable.readAll();
  return makeRow({
    scenario_id: "readable_stream_bytes",
    api_surface: "readable_stream",
    capability_granted: support.capabilityGranted,
    degraded_mode: support.degradedMode,
    bytes_sent: payload.byteLength,
    bytes_received: received.byteLength,
    messages_sent: 1,
    messages_received: 1,
    close_kind: readable.state,
    expected_error: null,
    actual_error: null,
    condition:
      readable.state === "closed"
      && readable.bytesRead === payload.byteLength
      && received.every((byte, index) => byte === payload[index]),
  });
}

async function writableStreamBytes(): Promise<ScenarioRow> {
  const support = detectBrowserNativeStreamSupport("writable_stream", {
    capability: STREAM_CAPABILITY,
  });
  const payload = Uint8Array.from([11, 12, 13, 14]);
  const chunks: Uint8Array[] = [];
  const stream = new WritableStream({
    write(chunk) {
      chunks.push(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
    },
  });
  const writable = createBrowserWritableStream(stream, { support });
  const written = await writable.write(payload);
  await writable.close();
  const receivedBytes = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  return makeRow({
    scenario_id: "writable_stream_bytes",
    api_surface: "writable_stream",
    capability_granted: support.capabilityGranted,
    degraded_mode: support.degradedMode,
    bytes_sent: payload.byteLength,
    bytes_received: receivedBytes,
    messages_sent: 1,
    messages_received: chunks.length,
    close_kind: writable.state,
    expected_error: null,
    actual_error: null,
    condition:
      writable.state === "closed"
      && writable.bytesWritten === payload.byteLength
      && written === payload.byteLength
      && receivedBytes === payload.byteLength,
  });
}

async function capabilityDenied(): Promise<ScenarioRow> {
  let ambientAccessed = false;
  const fakeGlobal = {
    AbortController,
    BroadcastChannel,
    MessageChannel: class {
      constructor() {
        ambientAccessed = true;
      }
    },
    ReadableStream,
    WebAssembly,
    WritableStream,
    document: {},
    fetch,
    window: {},
  } as unknown as Record<string, unknown>;
  const support = detectBrowserNativeMessagingSupport("message_channel", {
    capability: { capabilityGranted: false },
    globalObject: fakeGlobal,
  });
  let caught: unknown = null;
  try {
    createBrowserMessageChannel({ support, globalObject: fakeGlobal });
  } catch (error) {
    caught = error;
  }
  const actual = `${errorCode(caught) ?? "missing"}:${support.reason}:${ambientAccessed}`;
  return makeRow({
    scenario_id: "capability_denied",
    api_surface: "message_channel",
    capability_granted: support.capabilityGranted,
    degraded_mode: support.degradedMode,
    bytes_sent: 0,
    bytes_received: 0,
    messages_sent: 0,
    messages_received: 0,
    close_kind: "denied_before_open",
    expected_error: `${BROWSER_NATIVE_MESSAGING_UNSUPPORTED_CODE}:capability_not_granted:false`,
    actual_error: actual,
    condition:
      actual === `${BROWSER_NATIVE_MESSAGING_UNSUPPORTED_CODE}:capability_not_granted:false`,
  });
}

async function degradedModeDenied(): Promise<ScenarioRow> {
  let streamAccessed = false;
  const fakeStream = {
    getReader() {
      streamAccessed = true;
      throw new Error("ambient stream access should be denied");
    },
  };
  const support = detectBrowserNativeStreamSupport("readable_stream", {
    capability: { capabilityGranted: true, degradedMode: true },
  });
  let caught: unknown = null;
  try {
    createBrowserReadableStream(fakeStream, { support });
  } catch (error) {
    caught = error;
  }
  const actual = `${errorCode(caught) ?? "missing"}:${support.reason}:${streamAccessed}`;
  return makeRow({
    scenario_id: "degraded_mode_denied",
    api_surface: "readable_stream",
    capability_granted: support.capabilityGranted,
    degraded_mode: support.degradedMode,
    bytes_sent: 0,
    bytes_received: 0,
    messages_sent: 0,
    messages_received: 0,
    close_kind: "denied_before_open",
    expected_error: `${BROWSER_NATIVE_STREAM_UNSUPPORTED_CODE}:degraded_mode_denied:false`,
    actual_error: actual,
    condition:
      actual === `${BROWSER_NATIVE_STREAM_UNSUPPORTED_CODE}:degraded_mode_denied:false`,
  });
}

async function run(): Promise<void> {
  render({
    phase: "running",
    marker: MARKER,
    bead_id: BEAD_ID,
    required_scenarios: REQUIRED_SCENARIOS,
    public_entrypoints: PUBLIC_ENTRYPOINT_MARKERS,
  });

  const rows = [
    await messageChannelTextRoundtrip(),
    await messageChannelBytesRoundtrip(),
    await messagePortCloseRejectsSend(),
    await messagePortAbortIsSticky(),
    await broadcastChannelDelivery(),
    await readableStreamBytes(),
    await writableStreamBytes(),
    await capabilityDenied(),
    await degradedModeDenied(),
  ];
  const scenarioIds = rows.map((row) => row.scenario_id);
  const missingScenarios = REQUIRED_SCENARIOS.filter(
    (scenarioId) => !scenarioIds.includes(scenarioId),
  );
  const failingRows = rows.filter((row) => row.verdict !== "pass");

  render({
    phase: failingRows.length === 0 && missingScenarios.length === 0
      ? "complete"
      : "error",
    marker: MARKER,
    bead_id: BEAD_ID,
    scenario_id: "BROWSER-NATIVE-MESSAGE-STREAM-CONSUMER",
    validation_passed: failingRows.length === 0 && missingScenarios.length === 0,
    missing_scenarios: missingScenarios,
    public_entrypoints: PUBLIC_ENTRYPOINT_MARKERS,
    first_failure:
      failingRows[0]?.first_failure ?? missingScenarios[0] ?? null,
    rows,
  });
}

run().catch((error: unknown) => {
  render({
    phase: "error",
    marker: MARKER,
    bead_id: BEAD_ID,
    scenario_id: "BROWSER-NATIVE-MESSAGE-STREAM-CONSUMER",
    validation_passed: false,
    error_message: error instanceof Error ? error.message : String(error),
    first_failure: error instanceof Error ? error.message : String(error),
    rows: [],
  });
});
