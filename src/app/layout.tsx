import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "GitSecure — is this repo safe?",
  description:
    "Swap github.com for git-secure.com and get a security report for a public repo: leaked secrets, framework flaws, dependency vulnerabilities, and posture. Everyone gets the full report — no sign-up, no login.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main">Skip to content</a>
        <header className="topbar">
          <a href="/" className="brand">GitSecure</a>
          <span className="tagline">is this repo safe?</span>
        </header>
        <main className="container" id="main">{children}</main>
        <footer className="footer">
          <p>
            GitSecure scans public repos only. Secrets are never shown in full, never stored, and never
            live-validated. It is not a replacement for GitHub Advanced Security.
          </p>
          <p>
            Everyone gets the full report — score, counts, file names, line numbers, and redacted
            secret fragments — because the repo is public. No sign-up, no login.
          </p>
        </footer>
      </body>
    </html>
  );
}
