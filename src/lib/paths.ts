// Shared path-skip rules: which files the scanner never reads.
// Single source of truth - used by the HEAD-tree scan (scan.ts) and the
// full-history clone scan (history.ts) so both skip the same generated /
// vendored / binary paths.

export const SKIP_DIRS = ["node_modules", ".git", "dist", "build", ".next", "vendor", "target", ".venv", "__pycache__"];
export const SKIP_EXTS = [".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".mp3", ".mp4", ".wav", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".exe", ".dll", ".so", ".dylib", ".bin", ".lockb"];

export function isSkippablePath(path: string): boolean {
  if (SKIP_DIRS.some((d) => path.split("/").includes(d))) return true;
  const lower = path.toLowerCase();
  if (SKIP_EXTS.some((e) => lower.endsWith(e))) return true;
  return false;
}
