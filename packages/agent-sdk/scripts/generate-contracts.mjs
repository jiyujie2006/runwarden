import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const outputPath = path.join(root, "packages/agent-sdk/src/generated/contracts.ts");

const enumSources = [
  ["provider-outcome.schema.json", "PolicyDecision"],
  ["provider-outcome.schema.json", "ExecutionStatus"],
  ["provider-outcome.schema.json", "ExecutionMode"],
  ["provider-outcome.schema.json", "ErrorKind"],
  ["operation-result.schema.json", "OperationStatus"],
  ["approval-record.schema.json", "ApprovalState"]
];

const aliasSources = [
  ["operation-result.schema.json", "ErrorCode"]
];

const interfaceSources = [
  {
    fileName: "provider-call.schema.json",
    definitions: [],
    roots: ["ProviderCall"]
  },
  {
    fileName: "provider-outcome.schema.json",
    definitions: ["ArtifactRef", "DecisionEnvelope"],
    roots: ["ProviderOutcome"]
  },
  {
    fileName: "approval-record.schema.json",
    definitions: ["ApprovalBinding"],
    roots: ["ApprovalRecord"]
  },
  {
    fileName: "operation-result.schema.json",
    definitions: ["OperationError"],
    roots: ["OperationResultForProviderOutcome"]
  },
  {
    fileName: "artifact-manifest.schema.json",
    definitions: ["ArtifactManifestEntry"],
    roots: ["ArtifactManifest"]
  }
];

function readSchema(fileName) {
  const schemaPath = path.join(root, "schemas", fileName);
  return JSON.parse(fs.readFileSync(schemaPath, "utf8"));
}

function enumValues(fileName, definitionName) {
  const schema = readSchema(fileName);
  const values = schema.definitions?.[definitionName]?.enum;
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) {
    throw new Error(`${fileName} is missing string enum ${definitionName}`);
  }
  return values;
}

function renderUnion(name, values) {
  return [
    `export type ${name} =`,
    ...values.map((value, index) => `  | ${JSON.stringify(value)}${index === values.length - 1 ? ";" : ""}`)
  ].join("\n");
}

function aliasSchema(fileName, typeName) {
  const schema = readSchema(fileName);
  const definition = schema.definitions?.[typeName];
  if (!definition) {
    throw new Error(`${fileName} is missing alias schema ${typeName}`);
  }
  return definition;
}

function renderAlias(fileName, typeName) {
  return `export type ${typeName} = ${schemaType(aliasSchema(fileName, typeName))};`;
}

function interfaceSchema(fileName, typeName, fromDefinition) {
  const schema = readSchema(fileName);
  const interfaceSchema = fromDefinition ? schema.definitions?.[typeName] : schema;
  if (!interfaceSchema || interfaceSchema.type !== "object") {
    throw new Error(`${fileName} is missing object schema ${typeName}`);
  }
  return interfaceSchema;
}

function renderInterface(fileName, typeName, fromDefinition) {
  const schema = interfaceSchema(fileName, typeName, fromDefinition);
  const required = new Set(schema.required ?? []);
  const properties = Object.entries(schema.properties ?? {});
  if (properties.length === 0) {
    throw new Error(`${fileName} object schema ${typeName} has no properties`);
  }
  return [
    `export interface ${typeName} {`,
    ...properties.map(([propertyName, propertySchema]) => {
      const optional = required.has(propertyName) ? "" : "?";
      return `  ${propertyName}${optional}: ${schemaType(propertySchema)};`;
    }),
    "}"
  ].join("\n");
}

function schemaType(schema) {
  if (schema === true) {
    return "unknown";
  }
  if (!schema || schema === false) {
    return "never";
  }
  if (schema.$ref) {
    return schema.$ref.split("/").at(-1);
  }
  if (schema.anyOf) {
    return renderUnionType(schema.anyOf.map(schemaType));
  }
  if (Array.isArray(schema.type)) {
    return renderUnionType(schema.type.map((type) => primitiveType({ type })));
  }
  if (schema.type === "array") {
    const itemType = schemaType(schema.items ?? true);
    return itemType.includes(" | ") ? `Array<${itemType}>` : `${itemType}[]`;
  }
  return primitiveType(schema);
}

function primitiveType(schema) {
  switch (schema.type) {
    case "string":
      return "string";
    case "boolean":
      return "boolean";
    case "integer":
    case "number":
      return "number";
    case "null":
      return "null";
    case "object":
      return "Record<string, unknown>";
    default:
      if (schema.enum && schema.enum.every((value) => typeof value === "string")) {
        return renderUnionType(schema.enum.map((value) => JSON.stringify(value)));
      }
      return "unknown";
  }
}

function renderUnionType(types) {
  return [...new Set(types)].join(" | ");
}

function generate() {
  const sections = enumSources.map(([fileName, definitionName]) =>
    renderUnion(definitionName, enumValues(fileName, definitionName))
  );
  const aliases = aliasSources.map(([fileName, definitionName]) =>
    renderAlias(fileName, definitionName)
  );
  const interfaces = interfaceSources.flatMap(({ fileName, definitions, roots }) => [
    ...definitions.map((definitionName) => renderInterface(fileName, definitionName, true)),
    ...roots.map((rootName) => renderInterface(fileName, rootName, false))
  ]);
  return [
    "/* @generated by packages/agent-sdk/scripts/generate-contracts.mjs */",
    "/* eslint-disable */",
    "",
    sections.join("\n\n"),
    "",
    aliases.join("\n\n"),
    "",
    interfaces.join("\n\n"),
    ""
  ].join("\n");
}

const generated = generate();

if (process.argv.includes("--check")) {
  const existing = fs.existsSync(outputPath) ? fs.readFileSync(outputPath, "utf8") : "";
  if (existing !== generated) {
    console.error("generated TypeScript contracts are stale; run packages/agent-sdk/scripts/generate-contracts.mjs");
    process.exit(1);
  }
} else {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, generated);
}
