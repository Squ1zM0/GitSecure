"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import McpSection from "@/components/McpSection";

const NAME_RE = /^[A-Za-z0-9_.-]+$/;

/** Pull owner/repo out of whatever was typed or pasted: a bare
 *  "owner/repo", or a full github.com / git-secure.com URL, including any
 *  trailing path such as /tree/main, a trailing slash, or a .git suffix. */
function parseInput(raw: string): { owner: string; repo: string } | { error: string } {
  const value = raw.trim();
  if (!value) return { error: "Enter a repo to scan, like Squ1zM0/TechDirect." };
  let path = value;
  const lower = value.toLowerCase();
  const gh = lower.indexOf("github.com/");
  const gs = lower.indexOf("git-secure.com/");
  const at = gh >= 0 ? gh + "github.com/".length : gs >= 0 ? gs + "git-secure.com/".length : -1;
  const fromUrl = at >= 0;
  if (fromUrl) path = value.slice(at);
  path = path.replace(/\.git$/i, "").replace(/\/+$/, "");
  const parts = path.split("/").filter(Boolean);
  // A pasted URL may carry a trailing path (/tree/main, /issues, …) — take
  // the first two segments. A bare owner/repo with extra segments is a
  // typo, so say so instead of guessing.
  if (fromUrl ? parts.length < 2 : parts.length !== 2) return { error: "Enter owner/repo — for example Squ1zM0/TechDirect." };
  const [owner, repo] = parts;
  for (const [label, name] of [["owner", owner], ["repo", repo]] as const) {
    if (name === "." || name === ".." || !NAME_RE.test(name)) {
      return { error: `That doesn't look like a valid ${label} name. Owner and repo names can only use letters, numbers, dots, hyphens and underscores — check for typos or extra characters.` };
    }
  }
  return { owner, repo };
}

export default function Home() {
  const router = useRouter();
  const [value, setValue] = useState("Squ1zM0/TechDirect");
  const [error, setError] = useState("");
  const [scanning, setScanning] = useState(false);

  function go(e: React.FormEvent) {
    e.preventDefault();
    const parsed = parseInput(value);
    if ("error" in parsed) {
      setError(parsed.error);
      return;
    }
    setError("");
    setScanning(true);
    router.push(`/${parsed.owner}/${parsed.repo}`);
  }

  return (
    <div>
      <h1>Is this repo safe?</h1>
      <p>
        GitSecure is the security mirror for GitHub. Take any public repo, swap{" "}
        <code className="inline">github.com</code> for <code className="inline">git-secure.com</code>,
        and get a plain-English security report — no install, no sign-up.
      </p>
      <div className="url-example">
        <s>github.com/Squ1zM0/TechDirect</s> → git-secure.com/Squ1zM0/TechDirect
      </div>

      <form className="scan-form" onSubmit={go}>
        <input type="text" value={value} onChange={(e) => { setValue(e.target.value); setScanning(false); }} aria-label="owner/repo" placeholder="owner/repo" disabled={scanning} />
        <button type="submit" disabled={scanning}>{scanning ? "Scanning…" : "Scan repo"}</button>
      </form>
      {error && <p role="alert">{error}</p>}
      {scanning && !error && <p role="status">Scanning… checking the files, then the full history, then dependencies. This usually takes about 15 seconds.</p>}

      <div className="card">
        <h2>What it checks</h2>
        <ul>
          <li><b>Leaked secrets</b> — Discord and Slack webhooks, AWS keys, GitHub tokens, Stripe and OpenAI keys, database URLs, private keys, committed .env files. Checked in current files and in full history (newest-first, up to the caps below).</li>
          <li><b>Frameworks</b> — what the repo is built with (Next.js, React, Vite, Django, Rust crates, Go, Rails, Laravel, Spring, ASP.NET Core and more), with exact versions from lockfiles where possible.</li>
          <li><b>Dependency flaws</b> — known vulnerabilities in direct and transitive dependencies, checked against OSV.dev (a free public database of known software flaws), with full advisory detail — a plain summary, a severity score, and the version that fixes each one.</li>
          <li><b>Security posture</b> — missing SECURITY.md, no Dependabot, .gitignore gaps, and risky GitHub Actions patterns.</li>
        </ul>
      </div>

      <div className="card">
        <h2>What you see — and what you don&apos;t</h2>
        <p>
          Everyone sees the <b>score (0–100) and the counts</b> only. The full detail — file names, line
          numbers, and redacted secret fragments — is available to the repo owner only.
        </p>
        <p>
          Secrets are never shown in full, never stored, and never live-validated. A scan looks at
          public files only.
        </p>
      </div>

      <McpSection />

      <div className="card">
        <h2>Honest limits</h2>
        <ul>
          <li>History is scanned newest-first via an ephemeral clone, capped at 1,000 commits / 50 MB of patches / 45 seconds — a secret in a very old commit of a huge repo may still be missed, and the report says when a cap was hit. If the runtime has no git binary, the scan falls back to the 5 most recent commits and says so.</li>
          <li>At most 250 files per scan, manifests and configs first; at most 100 secret findings and 100 advisories listed per report.</li>
          <li>Full advisory detail (a plain summary, a severity score, and the version that fixes it) is fetched for up to 50 advisories per scan; any beyond that are listed with their advisory ID only.</li>
          <li>Owner verification via GitHub sign-in is code-complete but the OAuth App is not created yet, so the full view is still local/dev owner mode only on this deployment — see the README for the setup steps.</li>
          <li>GitSecure is not a replacement for GitHub Advanced Security.</li>
        </ul>
        <p>
          Try it: <a href="/Squ1zM0/TechDirect">scan Squ1zM0/TechDirect</a>
        </p>
      </div>
    </div>
  );
}
