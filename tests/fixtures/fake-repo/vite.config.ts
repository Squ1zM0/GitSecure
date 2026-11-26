// Clean committed fixture (Phase 14): no dev-server host, no plugins,
// no public-variable reference — the risky config lives only in the
// generated test-time fixture (scripts/fixture-gen.ts), so the
// self-scan stays clean. Kept as a file so the Vite framework is still
// fingerprinted from a config file when no vite dep is present.
export default {};
