// "Use with your AI assistant (MCP)" — the human view of the MCP server.
// Full version on the home page (all four client snippets); compact
// version on the report page (server URL + the Claude snippet + a link
// back to the home page for the rest). Copy buttons use the clipboard
// API with a textarea fallback, and show a "Copied" state.
"use client";

import { useState } from "react";
import { MCP_PLAIN_LINE, MCP_SNIPPETS, MCP_URL, type McpSnippet } from "@/lib/mcp-config";

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard API unavailable (older browser, no permission) — fall
      // back to the old select-and-copy path.
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <button type="button" className="copy-btn" onClick={copy} aria-label={`Copy ${label}`}>
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function Snippet({ snippet }: { snippet: McpSnippet }) {
  return (
    <div className="snippet">
      <div className="copy-row">
        <div>
          <b>{snippet.client}</b> <span className="muted small">— {snippet.where}</span>
        </div>
        <CopyButton text={snippet.json} label={`${snippet.client} config`} />
      </div>
      <pre>{snippet.json}</pre>
    </div>
  );
}

export default function McpSection({ compact = false }: { compact?: boolean }) {
  const claude = MCP_SNIPPETS.find((s) => s.id === "claude") ?? MCP_SNIPPETS[0];

  if (compact) {
    return (
      <div className="card">
        <h2>Use with your AI assistant (MCP)</h2>
        <p>{MCP_PLAIN_LINE}</p>
        <div className="copy-row">
          <code className="inline">{MCP_URL}</code>
          <CopyButton text={MCP_URL} label="MCP server URL" />
        </div>
        <Snippet snippet={claude} />
        <p className="small">
          Setup snippets for Cursor, VS Code and Windsurf/Cline are on the <a href="/#mcp">home page</a>.
        </p>
      </div>
    );
  }

  return (
    <div className="card" id="mcp">
      <h2>Use with your AI assistant (MCP)</h2>
      <p>
        MCP lets an AI assistant like Claude call GitSecure for you — no account needed.
      </p>
      <p>
        Point your AI assistant at GitSecure and it can scan a repo for you. Server URL:
      </p>
      <div className="copy-row">
        <code className="inline">{MCP_URL}</code>
        <CopyButton text={MCP_URL} label="MCP server URL" />
      </div>
      <p>{MCP_PLAIN_LINE}</p>
      <p>
        Paste one of these into your assistant&apos;s MCP config. It gets four tools:{" "}
        <code className="inline">scan_repo</code> (run a live scan),{" "}
        <code className="inline">get_report</code> (read or refresh a report),{" "}
        <code className="inline">resume_scan</code> (resume a long scan), and{" "}
        <code className="inline">list_checks</code> (what a scan covers).
      </p>
      <details className="group">
        <summary><span className="chevron" aria-hidden="true">▸</span>Setup snippets for Claude, Cursor, VS Code, and Windsurf/Cline</summary>
        <div className="group-body">
          {MCP_SNIPPETS.map((s) => (
            <Snippet key={s.id} snippet={s} />
          ))}
        </div>
      </details>
    </div>
  );
}
