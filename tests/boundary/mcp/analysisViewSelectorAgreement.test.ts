import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it, onTestFinished } from "vitest";

import { inspectAnalysisViewInputSchema } from "../../../src/domain/analysisView/analysisView.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

interface SelectorCase {
  readonly label: string;
  readonly view: unknown;
  readonly admitted: boolean;
}

const retainedEvidenceId = `ev_${"a".repeat(64)}`;
const moduleNodeId = `jag_node_${"b".repeat(64)}`;

/**
 * The advertised input schema and the server's runtime validation must agree on
 * which collection/selector pairings exist. Before this agreement the published
 * schema accepted `modules` with `index` and `sections` with `node_id`, so a
 * client validating against tools/list sent arguments the server refused as
 * invalid, before it could interpret whether the Evidence supported the
 * collection.
 *
 * Both layers are asserted separately. Checking only the final tool response
 * cannot detect the defect: a client-side schema rejection and a server-side
 * validation rejection both surface as an input error, so such a test passes
 * again once the contract regresses to a refinement.
 */
const selectorCases: readonly SelectorCase[] = [
  {
    label: "modules + path",
    view: { kind: "item", collection: "modules", selector: { path: "a.js" } },
    admitted: true,
  },
  {
    label: "modules + empty path",
    view: { kind: "item", collection: "modules", selector: { path: "" } },
    admitted: true,
  },
  {
    label: "modules + node_id",
    view: {
      kind: "item",
      collection: "modules",
      selector: { node_id: moduleNodeId },
    },
    admitted: true,
  },
  {
    label: "modules + index",
    view: { kind: "item", collection: "modules", selector: { index: 0 } },
    admitted: false,
  },
  {
    label: "modules + name",
    view: { kind: "item", collection: "modules", selector: { name: "a.js" } },
    admitted: false,
  },
  {
    label: "sections + index",
    view: { kind: "item", collection: "sections", selector: { index: 0 } },
    admitted: true,
  },
  {
    label: "sections + name",
    view: { kind: "item", collection: "sections", selector: { name: ".data" } },
    admitted: true,
  },
  {
    label: "sections + path",
    view: { kind: "item", collection: "sections", selector: { path: "a.js" } },
    admitted: false,
  },
  {
    label: "sections + node_id",
    view: {
      kind: "item",
      collection: "sections",
      selector: { node_id: moduleNodeId },
    },
    admitted: false,
  },
  {
    label: "symbols + index",
    view: { kind: "item", collection: "symbols", selector: { index: 1 } },
    admitted: true,
  },
  {
    label: "symbols + name",
    view: { kind: "item", collection: "symbols", selector: { name: "main" } },
    admitted: true,
  },
  {
    label: "symbols + node_id",
    view: {
      kind: "item",
      collection: "symbols",
      selector: { node_id: moduleNodeId },
    },
    admitted: false,
  },
];

const argumentsFor = (view: unknown): Record<string, unknown> => ({
  source: { kind: "retained-evidence", evidence_id: retainedEvidenceId },
  view,
});

const connect = async () => {
  const session = createTestBinarySession(() => {
    throw new Error("No deep provider may start for a schema projection");
  });
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "selector-agreement", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client };
};

it("advertises exactly the collection/selector pairings runtime validation admits", async () => {
  const { client } = await connect();
  const advertised = (await client.listTools()).tools.find(
    (tool) => tool.name === "inspect_analysis_view",
  );
  if (advertised === undefined)
    throw new Error("inspect_analysis_view was not registered");

  // Compile the schema the client actually receives, so a contract regression
  // to a refinement is observed here rather than hidden behind a tool error.
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  const advertisedAccepts = ajv.compile(advertised.inputSchema);
  const runtimeAccepts = (view: unknown): boolean =>
    inspectAnalysisViewInputSchema.safeParse(argumentsFor(view)).success;

  const advertisedVerdicts: string[] = [];
  const runtimeVerdicts: string[] = [];
  for (const entry of selectorCases) {
    const advertisedAcceptsCase = advertisedAccepts(argumentsFor(entry.view));
    const runtimeAcceptsCase = runtimeAccepts(entry.view);
    if (advertisedAcceptsCase !== entry.admitted)
      advertisedVerdicts.push(
        `${entry.label}: advertised=${String(advertisedAcceptsCase)} expected=${String(entry.admitted)}`,
      );
    if (runtimeAcceptsCase !== entry.admitted)
      runtimeVerdicts.push(
        `${entry.label}: runtime=${String(runtimeAcceptsCase)} expected=${String(entry.admitted)}`,
      );
    expect(
      advertisedAcceptsCase,
      `${entry.label}: advertised schema and runtime validation disagree`,
    ).toBe(runtimeAcceptsCase);
  }
  expect(advertisedVerdicts).toEqual([]);
  expect(runtimeVerdicts).toEqual([]);
});
