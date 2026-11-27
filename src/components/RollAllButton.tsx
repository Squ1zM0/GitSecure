// "Roll all into report" (Freddy, 2026-11-26) - one button in the
// score hero that downloads the ENTIRE current scan as a single
// Markdown file. Client-side only: the Markdown comes from the
// FullReport the page already has (src/lib/report-markdown.ts), so
// the download contains every finding even when the on-page lists
// are collapsed or filtered. No API route, no new data fetched.
// "use client" - the download uses Blob + an anchor click.
"use client";

import { useState } from "react";
import type { FullReport } from "@/lib/types";
import { buildReportMarkdown, reportMarkdownFilename } from "@/lib/report-markdown";

export default function RollAllButton({ report, paused }: { report: FullReport; paused?: boolean }) {
  const [state, setState] = useState<"idle" | "done" | "error">("idle");
  function download() {
    try {
      const md = buildReportMarkdown(report, { paused });
      const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = reportMarkdownFilename(report);
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setState("done");
      setTimeout(() => setState("idle"), 3000);
    } catch {
      setState("error");
    }
  }
  return (
    <div className="roll-all">
      <button type="button" className="secondary" onClick={download} aria-label="Roll all into report - download the full scan as one Markdown file">
        {state === "done" ? "Report downloaded" : state === "error" ? "Download didn't start - try again" : "Roll all into report"}
      </button>
      <p className="small muted">One Markdown file - score, summary, and every finding.</p>
    </div>
  );
}
