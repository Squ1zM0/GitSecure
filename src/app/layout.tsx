import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://git-secure.com"),
  title: "GitSecure - is this repo safe?",
  description:
    "Swap github.com for git-secure.com and get a security report for a public repo: leaked secrets, framework flaws, dependency vulnerabilities, and posture. Everyone gets the full report - no sign-up, no login.",
  alternates: {
    canonical: "/",
  },
  openGraph: {
    type: "website",
    siteName: "GitSecure",
    title: "GitSecure - is this repo safe?",
    description:
      "Swap github.com for git-secure.com and get a security report for a public repo: leaked secrets, framework flaws, dependency vulnerabilities, and posture. Everyone gets the full report - no sign-up, no login.",
    url: "https://git-secure.com/",
    locale: "en_US",
    images: [
      {
        url: "/og.png",
        width: 1200,
        height: 630,
        alt: "GitSecure - is this repo safe? Swap github.com for git-secure.com and get a plain-English security report.",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "GitSecure - is this repo safe?",
    description:
      "Swap github.com for git-secure.com and get a security report for a public repo: leaked secrets, framework flaws, dependency vulnerabilities, and posture. Everyone gets the full report - no sign-up, no login.",
    images: ["/og.png"],
  },
};

// JSON-LD: exact contents of gitsecure-presence/seo/jsonld-*.json
// (validated JSON, pasted verbatim - do not retype the values by hand).
const softwareApplicationJsonLd = {"@context":"https://schema.org","@type":"SoftwareApplication","applicationCategory":"DeveloperApplication","author":{"@type":"Organization","name":"Squ1zM0","url":"https://github.com/Squ1zM0/GitSecure"},"codeRepository":"https://github.com/Squ1zM0/GitSecure","description":"Swap github.com for git-secure.com and get a security report for a public repo: leaked secrets, framework flaws, dependency vulnerabilities, and posture. Everyone gets the full report - no sign-up, no login.","featureList":["Leaked-secret scanning in current files and in full history, newest-first","Framework fingerprinting with exact versions from lockfiles where possible","Dependency vulnerability checks against OSV.dev, with the version that fixes each flaw","Security posture checks: SECURITY.md, Dependabot, .gitignore gaps, risky GitHub Actions patterns","Plain-English report with a 0-100 score and grade, file names, line numbers, and redacted secret fragments","MCP server for AI assistants at https://git-secure.com/mcp"],"inLanguage":"en","isAccessibleForFree":true,"name":"GitSecure","offers":{"@type":"Offer","availability":"https://schema.org/InStock","price":"0","priceCurrency":"USD"},"operatingSystem":"Web","softwareHelp":"https://git-secure.com/","url":"https://git-secure.com/"};
const webSiteJsonLd = {"@context":"https://schema.org","@type":"WebSite","description":"GitSecure is the security mirror for GitHub. Take any public repo, swap github.com for git-secure.com, and get a plain-English security report - no install, no sign-up.","inLanguage":"en","name":"GitSecure","sameAs":["https://github.com/Squ1zM0/GitSecure"],"url":"https://git-secure.com/"};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main">Skip to content</a>
        <header className="topbar">
          <a href="/" className="brand"><img src="/logo-mark.svg" alt="" width={26} height={26} className="brand-mark" />GitSecure</a>
          <span className="tagline">is this repo safe?</span>
        </header>
        <main className="container" id="main">{children}</main>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(softwareApplicationJsonLd) }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(webSiteJsonLd) }}
        />
        <footer className="footer">
          <p>
            GitSecure scans public repos only. Secrets are never shown in full, never stored after the scan finishes, and never
            live-validated. It is not a replacement for GitHub Advanced Security.
          </p>
          <p>
            Everyone gets the full report - score, counts, file names, line numbers, and redacted
            secret fragments - because the repo is public. No sign-up, no login.
          </p>
        </footer>
      </body>
    </html>
  );
}
