# Provider Contract

Provider contracts are generated from provider manifests. They include the kernel provider record, schema pin, observed schema digest, schema-rug-pull status, and enforcement requirements.

The checked schema is `schemas/provider-contract.schema.json`.

Contracts require kernel mediation, schema pins, resource limits, trace output,
redaction, and approval gates when the provider risk or side effects demand it.
External MCP contracts bind execution to the manifest transport; request
transport overrides are denied unless they match exactly, and a missing manifest
transport is not executable. Stdio MCP contracts deny request-supplied command
arguments; fixed arguments must live in a trusted wrapper or manifest-owned
executable. Stdio execution also requires Unix process-group cleanup after
normal completion as well as error and timeout paths. Platforms without that
process-tree cleanup guarantee deny stdio execution before spawn.
