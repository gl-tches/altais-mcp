import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import type { ZodRawShape } from "zod";
import type { ModuleConfig, ModuleDefinition, ToolDefinition } from "./types.js";

type RegisterToolFn = (
  name: string,
  config: {
    title?: string;
    description: string;
    inputSchema?: ZodRawShape;
    outputSchema?: ZodRawShape;
    annotations: ToolAnnotations;
  },
  handler: (args: unknown) => Promise<CallToolResult> | CallToolResult,
) => unknown;

export class ModuleRegistryError extends Error {
  override readonly name = "ModuleRegistryError";
}

/**
 * Registry of available modules. Modules are added with `load()`, then
 * `registerAll()` resolves dependencies in topological order, calls each
 * module's `init()` once, and registers all tools on the MCP server.
 */
export class ModuleRegistry {
  private readonly modules = new Map<string, ModuleDefinition>();
  private readonly initialized = new Set<string>();

  load(module: ModuleDefinition): void {
    if (this.modules.has(module.name)) {
      throw new ModuleRegistryError(`Module already loaded: ${module.name}`);
    }
    this.modules.set(module.name, module);
  }

  has(name: string): boolean {
    return this.modules.has(name);
  }

  get(name: string): ModuleDefinition | undefined {
    return this.modules.get(name);
  }

  names(): readonly string[] {
    return Array.from(this.modules.keys());
  }

  /**
   * Topological-sort the requested modules with their transitive dependencies.
   * Throws on unknown modules or cycles.
   */
  resolve(requested: readonly string[]): readonly ModuleDefinition[] {
    const ordered: ModuleDefinition[] = [];
    const visited = new Set<string>();
    const visiting = new Set<string>();

    const visit = (name: string, stack: readonly string[]): void => {
      if (visited.has(name)) return;
      if (visiting.has(name)) {
        const cycle = [...stack.slice(stack.indexOf(name)), name].join(" -> ");
        throw new ModuleRegistryError(`Circular module dependency: ${cycle}`);
      }
      const mod = this.modules.get(name);
      if (!mod) {
        throw new ModuleRegistryError(`Unknown module: ${name}`);
      }
      visiting.add(name);
      for (const dep of mod.dependencies ?? []) {
        visit(dep, [...stack, name]);
      }
      visiting.delete(name);
      visited.add(name);
      ordered.push(mod);
    };

    for (const name of requested) {
      visit(name, []);
    }
    return ordered;
  }

  /**
   * Initialize each requested module (with transitive dependencies) in
   * dependency order, then register all of their tools on the server.
   * Returns the list of module names that were registered, in order.
   */
  async registerAll(
    server: McpServer,
    requested: readonly string[],
    moduleConfigs: Readonly<Record<string, ModuleConfig>> = {},
  ): Promise<readonly string[]> {
    const ordered = this.resolve(requested);

    for (const mod of ordered) {
      if (this.initialized.has(mod.name)) continue;
      const cfg = moduleConfigs[mod.name] ?? {};
      await mod.init(cfg);
      for (const tool of mod.tools) {
        this.registerTool(server, tool);
      }
      this.initialized.add(mod.name);
    }

    return ordered.map((m) => m.name);
  }

  private registerTool(server: McpServer, tool: ToolDefinition): void {
    const config: Parameters<RegisterToolFn>[1] = {
      description: tool.description,
      annotations: tool.annotations,
    };
    if (tool.title !== undefined) config.title = tool.title;
    if (tool.inputSchema !== undefined) config.inputSchema = tool.inputSchema;
    if (tool.outputSchema !== undefined) config.outputSchema = tool.outputSchema;

    // The SDK's registerTool has a complex generic signature for schema-based
    // type inference. We treat it through a stripped functional type because
    // the SDK validates input against inputSchema before calling the handler.
    const register = server.registerTool.bind(server) as unknown as RegisterToolFn;
    register(tool.name, config, (args: unknown) =>
      tool.handler((args ?? {}) as Record<string, unknown>),
    );
  }
}
