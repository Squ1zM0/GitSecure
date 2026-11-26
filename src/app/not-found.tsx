// Branded 404 (Phase 15, finding 6): a bare owner URL such as
// git-secure.com/Squ1zM0 — or any mistyped mirror URL — used to land on
// the stock Next.js 404 with no guidance and no way forward. This page
// explains the expected owner/repo shape and links home to scan.
// The root layout supplies the header and footer, so this matches the
// Phase 7 design system (same chrome, .card + .error-card styling).
// Note: failed *scans* still answer HTTP 200 — that is the documented
// Phase 3 App Router limitation (finding 16), unchanged here.
export default function NotFound() {
  return (
    <div>
      <h1>That page doesn&apos;t exist</h1>
      <div className="card error-card" role="alert">
        <p>
          GitSecure reports live at <code className="inline">git-secure.com/owner/repo</code> — one
          page per repo. This address is missing the repo part (or has a typo), so there is
          nothing to scan here.
        </p>
        <p>
          For example, to scan the GitSecure repo itself, visit{" "}
          <code className="inline">git-secure.com/Squ1zM0/GitSecure</code> — or type the repo
          below and scan it from the home page.
        </p>
        <p>
          <a className="button-link" href="/">Scan a repo</a>
        </p>
      </div>
    </div>
  );
}
