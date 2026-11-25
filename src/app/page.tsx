"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  const [value, setValue] = useState("Squ1zM0/TechDirect");
  const [error, setError] = useState("");

  function go(e: React.FormEvent) {
    e.preventDefault();
    const cleaned = value.trim().replace(/^https?:\/\/(www\.)?github\.com\//i, "").replace(/^https?:\/\/(www\.)?git-secure\.com\//i, "");
    const parts = cleaned.split("/").filter(Boolean);
    if (parts.length !== 2) {
      setError("Enter owner/repo — for example Squ1zM0/TechDirect.");
      return;
    }
    router.push(`/${parts[0]}/${parts[1]}`);
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
        <input type="text" value={value} onChange={(e) => setValue(e.target.value)} aria-label="owner/repo" placeholder="owner/repo" />
        <button type="submit">Scan repo</button>
      </form>
      {error && <p role="alert">{error}</p>}

      <div className="card">
        <h2>What it checks</h2>
        <ul>
          <li><b>Leaked secrets</b> — Discord and Slack webhooks, AWS keys, GitHub tokens, Stripe and OpenAI keys, database URLs, private keys, committed .env files. Checked in current files and in recent history.</li>
          <li><b>Frameworks</b> — what the repo is built with (Next.js, React, Vite, Django, Rust crates and more), with exact versions from lockfiles where possible.</li>
          <li><b>Dependency flaws</b> — known vulnerabilities in direct and transitive dependencies, checked against OSV.dev, with the version that fixes each one.</li>
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

      <div className="card">
        <h2>Honest limits (MVP)</h2>
        <ul>
          <li>History is checked for the 5 most recent commits only — a secret buried in an old commit may not be caught yet.</li>
          <li>At most 250 files per scan, manifests and configs first.</li>
          <li>Owner verification is not built yet — see the README. In the meantime the full view is only available in local/dev owner mode.</li>
          <li>GitSecure is not a replacement for GitHub Advanced Security.</li>
        </ul>
        <p>
          Try it: <a href="/Squ1zM0/TechDirect">scan Squ1zM0/TechDirect</a>
        </p>
      </div>
    </div>
  );
}
