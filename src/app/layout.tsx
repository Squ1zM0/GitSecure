import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "GitSecure — is this repo safe?",
  description:
    "Swap github.com for git-secure.com and get a security report for a public repo: leaked secrets, framework flaws, dependency vulnerabilities, and posture. Full detail is owner-only.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="topbar">
          <a href="/" className="brand">GitSecure</a>
          <span className="tagline">is this repo safe?</span>
        </header>
        <main className="container">{children}</main>
        <footer className="footer">
          <p>
            GitSecure scans public repos only. Secrets are never shown in full, never stored, and never
            live-validated. It is not a replacement for GitHub Advanced Security.
          </p>
          <p>
            Full detail is available to the repo owner only — everyone else sees the score and counts.
          </p>
        </footer>
      </body>
    </html>
  );
}
