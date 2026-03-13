/**
 * OpenClaw TypeScript plugin entry point for context-mode.
 *
 * Exports an object with { id, name, configSchema, register(api) } for
 * declarative metadata and config validation before code execution.
 *
 * register(api) registers:
 *   - tool_call:before hook   — Routing enforcement (deny/modify/passthrough)
 *   - tool_call:after hook    — Session event capture
 *   - command:new hook         — Session initialization and cleanup
 *   - before_prompt_build      — Routing instruction injection into system context
 *   - context-mode engine      — Context engine with compaction management
 *   - /ctx-stats command       — Auto-reply command for session statistics
 *   - /ctx-doctor command      — Auto-reply command for diagnostics
 *   - /ctx-upgrade command     — Auto-reply command for upgrade
 *
 * Loaded by OpenClaw via: openclaw.extensions entry in package.json
 *
 * OpenClaw plugin paradigm:
 *   - Plugins export { id, name, configSchema, register(api) } for metadata
 *   - api.registerHook() for event-driven hooks
 *   - api.on() for typed lifecycle hooks
 *   - api.registerContextEngine() for compaction ownership
 *   - api.registerCommand() for auto-reply slash commands
 *   - Plugins run in-process with the Gateway (trusted code)
 */

import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { SessionDB } from "./session/db.js";
import { extractEvents } from "./session/extract.js";
import type { HookInput } from "./session/extract.js";
import { buildResumeSnapshot } from "./session/snapshot.js";
import type { SessionEvent } from "./types.js";
import { OpenClawAdapter } from "./adapters/openclaw/index.js";

// ── OpenClaw Plugin API Types ─────────────────────────────

/** Context for auto-reply command handlers. */
interface CommandContext {
  senderId?: string;
  channel?: string;
  isAuthorizedSender?: boolean;
  args?: string;
  commandBody?: string;
  config?: Record<string, unknown>;
}

/** OpenClaw plugin API provided to the register function. */
interface OpenClawPluginApi {
  registerHook(
    event: string,
    handler: (...args: unknown[]) => unknown,
    meta: { name: string; description: string },
  ): void;
  on(
    event: string,
    handler: (...args: unknown[]) => unknown,
    opts?: { priority?: number },
  ): void;
  registerContextEngine(id: string, factory: () => ContextEngineInstance): void;
  registerCommand?(cmd: {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requireAuth?: boolean;
    handler: (ctx: CommandContext) => { text: string } | Promise<{ text: string }>;
  }): void;
  registerCli?(
    factory: (ctx: { program: unknown }) => void,
    meta: { commands: string[] },
  ): void;
  logger?: {
    info: (...args: unknown[]) => void;
    error: (...args: unknown[]) => void;
  };
}

/** Context engine instance returned by the factory. */
interface ContextEngineInstance {
  info: { id: string; name: string; ownsCompaction: boolean };
  ingest(data: unknown): Promise<{ ingested: boolean }>;
  assemble(ctx: { messages: unknown[] }): Promise<{
    messages: unknown[];
    estimatedTokens: number;
  }>;
  compact(): Promise<{ ok: boolean; compacted: boolean }>;
}

/** Shape of the event object OpenClaw passes to tool_call hooks. */
interface ToolCallEvent {
  toolName?: string;
  params?: Record<string, unknown>;
  output?: string;
  isError?: boolean;
}

/** Plugin config schema for OpenClaw validation. */
const configSchema = {
  type: "object" as const,
  properties: {
    enabled: {
      type: "boolean" as const,
      default: true,
      description: "Enable or disable the context-mode plugin.",
    },
  },
  additionalProperties: false,
};

// ── Helpers ───────────────────────────────────────────────

function getSessionDir(): string {
  const dir = join(
    homedir(),
    ".openclaw",
    "context-mode",
    "sessions",
  );
  mkdirSync(dir, { recursive: true });
  return dir;
}

function getDBPath(projectDir: string): string {
  const hash = createHash("sha256")
    .update(projectDir)
    .digest("hex")
    .slice(0, 16);
  return join(getSessionDir(), `${hash}.db`);
}

// ── Plugin Definition (object export) ─────────────────────

/**
 * OpenClaw plugin definition. The object form provides declarative metadata
 * (id, name, configSchema) that OpenClaw can read without executing code.
 * The register() method is called once when the plugin is loaded.
 */
export default {
  id: "context-mode",
  name: "Context Mode",
  configSchema,

  // OpenClaw calls register() synchronously — returning a Promise causes hooks
  // to be silently ignored. Async init runs eagerly; hooks await it on first use.
  register(api: OpenClawPluginApi): void {
    // Resolve build dir from compiled JS location
    const buildDir = dirname(fileURLToPath(import.meta.url));
    const projectDir = process.env.OPENCLAW_PROJECT_DIR || process.cwd();
    const pluginRoot = resolve(buildDir, "..");

    // Initialize session synchronously (SessionDB constructor is sync)
    const db = new SessionDB({ dbPath: getDBPath(projectDir) });
    const sessionId = randomUUID();
    db.ensureSession(sessionId, projectDir);
    db.cleanupOldSessions(0);

    // Load routing instructions synchronously for prompt injection
    let routingInstructions = "";
    try {
      const instructionsPath = resolve(
        buildDir,
        "..",
        "configs",
        "openclaw",
        "AGENTS.md",
      );
      if (existsSync(instructionsPath)) {
        routingInstructions = readFileSync(instructionsPath, "utf-8");
      }
    } catch {
      // best effort
    }

    // Async init: load routing module + write AGENTS.md. Hooks await this.
    const initPromise = (async () => {
      const routingPath = resolve(buildDir, "..", "hooks", "core", "routing.mjs");
      const routing = await import(pathToFileURL(routingPath).href);
      await routing.initSecurity(buildDir);

      try {
        new OpenClawAdapter().writeRoutingInstructions(projectDir, pluginRoot);
      } catch {
        // best effort — never break plugin init
      }

      return { routing };
    })();

    // ── 1. tool_call:before — Routing enforcement ──────────

    api.registerHook(
      "tool_call:before",
      async (event: unknown) => {
        const { routing } = await initPromise;
        const e = event as ToolCallEvent;
        const toolName = e.toolName ?? "";
        const toolInput = e.params ?? {};

        let decision;
        try {
          decision = routing.routePreToolUse(toolName, toolInput, projectDir);
        } catch {
          return; // Routing failure → allow passthrough
        }

        if (!decision) return; // No routing match → passthrough

        if (decision.action === "deny" || decision.action === "ask") {
          return {
            block: true,
            blockReason: decision.reason ?? "Blocked by context-mode",
          };
        }

        if (decision.action === "modify" && decision.updatedInput) {
          // In-place mutation is required by OpenClaw's hook paradigm —
          // the gateway reads the mutated params object after the hook returns.
          Object.assign(toolInput, decision.updatedInput);
        }

        // "context" action → handled by before_prompt_build, not inline
      },
      {
        name: "context-mode.tool-call-before",
        description:
          "Routing enforcement — blocks curl/wget, redirects large-output commands to sandbox",
      },
    );

    // ── 2. tool_call:after — Session event capture ─────────

    api.registerHook(
      "tool_call:after",
      async (event: unknown) => {
        try {
          const e = event as ToolCallEvent;
          const hookInput: HookInput = {
            tool_name: e.toolName ?? "",
            tool_input: e.params ?? {},
            tool_response: e.output,
            tool_output: e.isError ? { isError: true } : undefined,
          };

          const events = extractEvents(hookInput);
          for (const ev of events) {
            db.insertEvent(sessionId, ev as SessionEvent, "PostToolUse");
          }
        } catch {
          // Silent — session capture must never break the tool call
        }
      },
      {
        name: "context-mode.tool-call-after",
        description:
          "Session event capture — records file reads, writes, git operations for compaction snapshots",
      },
    );

    // ── 3. command:new — Session initialization ────────────

    api.registerHook(
      "command:new",
      async () => {
        try {
          db.cleanupOldSessions(0);
        } catch {
          // best effort
        }
      },
      {
        name: "context-mode.session-new",
        description:
          "Session initialization — cleans up old sessions on /new command",
      },
    );

    // ── 4. before_prompt_build — Routing instruction injection ──

    if (routingInstructions) {
      api.on(
        "before_prompt_build",
        () => ({
          appendSystemContext: routingInstructions,
        }),
        { priority: 5 },
      );
    }

    // ── 5. Context engine — Compaction management ──────────

    api.registerContextEngine("context-mode", () => ({
      info: {
        id: "context-mode",
        name: "Context Mode",
        ownsCompaction: true,
      },

      async ingest() {
        return { ingested: true };
      },

      async assemble({ messages }: { messages: unknown[] }) {
        return { messages, estimatedTokens: 0 };
      },

      async compact() {
        try {
          const events = db.getEvents(sessionId);
          if (events.length === 0) return { ok: true, compacted: false };

          const stats = db.getSessionStats(sessionId);
          const snapshot = buildResumeSnapshot(events, {
            compactCount: (stats?.compact_count ?? 0) + 1,
          });

          db.upsertResume(sessionId, snapshot, events.length);
          db.incrementCompactCount(sessionId);

          return { ok: true, compacted: true };
        } catch {
          return { ok: false, compacted: false };
        }
      },
    }));

    // ── 6. Auto-reply commands — ctx slash commands ───────

    if (api.registerCommand) {
      api.registerCommand({
        name: "ctx-stats",
        description: "Show context-mode session statistics",
        handler: () => {
          const text = buildStatsText(db, sessionId);
          return { text };
        },
      });

      api.registerCommand({
        name: "ctx-doctor",
        description: "Run context-mode diagnostics",
        handler: () => {
          const cmd = `node "${pluginRoot}/build/cli.js" doctor`;
          return {
            text: [
              "## ctx-doctor",
              "",
              "Run this command to diagnose context-mode:",
              "",
              "```",
              cmd,
              "```",
            ].join("\n"),
          };
        },
      });

      api.registerCommand({
        name: "ctx-upgrade",
        description: "Upgrade context-mode to the latest version",
        handler: () => {
          const cmd = `node "${pluginRoot}/build/cli.js" upgrade`;
          return {
            text: [
              "## ctx-upgrade",
              "",
              "Run this command to upgrade context-mode:",
              "",
              "```",
              cmd,
              "```",
              "",
              "Restart your session after upgrade.",
            ].join("\n"),
          };
        },
      });
    }
  },
};

// ── Stats helper ──────────────────────────────────────────

function buildStatsText(db: SessionDB, sessionId: string): string {
  try {
    const events = db.getEvents(sessionId);
    const stats = db.getSessionStats(sessionId);
    const lines: string[] = [
      "## context-mode stats",
      "",
      `- Session: \`${sessionId.slice(0, 8)}…\``,
      `- Events captured: ${events.length}`,
      `- Compactions: ${stats?.compact_count ?? 0}`,
    ];

    // Summarize events by type
    const byType: Record<string, number> = {};
    for (const ev of events) {
      const key = ev.type ?? "unknown";
      byType[key] = (byType[key] ?? 0) + 1;
    }
    if (Object.keys(byType).length > 0) {
      lines.push("- Event breakdown:");
      for (const [type, count] of Object.entries(byType)) {
        lines.push(`  - ${type}: ${count}`);
      }
    }

    return lines.join("\n");
  } catch {
    return "context-mode stats unavailable (session DB error)";
  }
}
