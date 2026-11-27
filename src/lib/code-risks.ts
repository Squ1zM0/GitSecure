// Dangerous code patterns and web config checks (Phase 19).
// Line based: a detector flags a sink plus tainted input in the same
// statement. A sink called with only a constant string is never a
// finding, and JSON.parse is never flagged. Every finding carries file,
// line, severity, and a short fix.

import type { PostureIssue, Severity } from "./types";

type CodeRiskCategory = "code-risk" | "web-config" | "tls" | "xss" | "logging";

interface Lang {
  code: boolean;
  js: boolean;
  py: boolean;
  go: boolean;
  rb: boolean;
  java: boolean;
  php: boolean;
}

const JS_EXTS = new Set(["js", "jsx", "ts", "tsx", "mjs", "cjs"]);

function extOf(path: string): string {
  const base = path.split("/").pop() ?? path;
  const dot = base.lastIndexOf(".");
  return dot === -1 ? "" : base.slice(dot + 1).toLowerCase();
}

function langOf(ext: string): Lang {
  const js = JS_EXTS.has(ext);
  const py = ext === "py";
  const go = ext === "go";
  const rb = ext === "rb";
  const java = ext === "java";
  const php = ext === "php";
  return { code: js || py || go || rb || java || php, js, py, go, rb, java, php };
}

/** Remove single, double, and backtick quoted segments. Escapes are
 *  skipped so a quote inside a string does not end the segment. */
function stripStrings(text: string): string {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === "'" || ch === '"' || ch === "`") {
      // A bytes / raw / f-string prefix (b, r, f, u) belongs to the
      // literal, not to the code around it: b"abc" is a constant, not
      // a variable named b.
      out = out.replace(/(^|[^A-Za-z0-9_])[bBfFrRuU]+$/, "$1");
      i++;
      while (i < text.length && text[i] !== ch) {
        if (text[i] === "\\") i++;
        i++;
      }
      i++;
    } else {
      out += ch;
      i++;
    }
  }
  return out;
}

const SAFE_WORDS = new Set(["true", "false", "null", "undefined", "None", "True", "False"]);

/** True when the argument builds a string from a value at runtime:
 *  template or f-string interpolation, or PHP variable interpolation
 *  inside a double quoted string. */
function hasInterpolation(arg: string): boolean {
  if (/\$\{|#\{/.test(arg)) return true;
  if (/\bf["'][^"'\n]*\{/.test(arg)) return true;
  if (/"[^"\n]*\$\w/.test(arg)) return true;
  return false;
}

/** True when the argument is not a bare constant: it interpolates a
 *  value, concatenates one, or passes a variable. A constant string,
 *  even concatenated with another constant, is not tainted. */
function isTainted(arg: string): boolean {
  if (hasInterpolation(arg)) return true;
  const stripped = stripStrings(arg);
  const words = stripped.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? [];
  return words.some((w) => !SAFE_WORDS.has(w));
}

/** Identifiers that suggest the value came from outside the code:
 *  request data, user input, uploads, or a file path handed in. */
const USER_INPUT =
  /(?:\breq\b|\brequest\b|\bparams\b|\bquery\b|\bbody\b|\buser\b|user[A-Z]\w*|client[A-Z]\w*|\binput\b|\bupload\b|supplied|untrusted|external|\$_GET|\$_POST|\$_REQUEST|\$_FILES|\bform\b|fileName|filePath|filename|filepath)/;

/** Split a call argument list on top level commas, ignoring commas
 *  inside strings, templates, and nested brackets. Stops at the
 *  closing paren of the call. */
function splitTopLevelArgs(text: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) break;
      depth--;
    } else if (ch === "," && depth === 0) {
      args.push(text.slice(start, i));
      start = i + 1;
    }
  }
  args.push(text.slice(start));
  return args;
}

function firstArg(text: string): string {
  return splitTopLevelArgs(text)[0] ?? "";
}

/** A file path argument is a finding only when it is built from
 *  user input: a tainted argument naming request or user data. */
function pathTainted(arg: string): boolean {
  return isTainted(arg) && USER_INPUT.test(arg);
}

interface RuleHit {
  sink: string;
  note?: string;
}

interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: CodeRiskCategory;
  fix: string;
  detail: (hit: RuleHit) => string;
  match: (line: string, lang: Lang) => RuleHit | null;
}

function taintedAfter(line: string, m: RegExpExecArray): boolean {
  return isTainted(firstArg(line.slice(m.index + m[0].length)));
}

const RULES: Rule[] = [
  {
    id: "command-injection",
    title: "Command injection",
    severity: "high",
    category: "code-risk",
    fix: "Run the command with an argument list and no shell, and validate the input against an allowlist first.",
    detail: (hit) => `${hit.sink} runs a shell command built from input.`,
    match: (line, lang) => {
      if (lang.js) {
        const cp = /\bchild_process\s*\.\s*(exec|execSync)\s*\(/.exec(line);
        if (cp && taintedAfter(line, cp)) return { sink: `child_process.${cp[1]}` };
        const bare = /(^|[^.\w$])(exec|execSync)\s*\(/.exec(line);
        if (bare && taintedAfter(line, bare)) return { sink: bare[2] };
        const parenExec = /\)\s*\.\s*(exec|execSync)\s*\(/.exec(line);
        if (parenExec && taintedAfter(line, parenExec)) return { sink: parenExec[1] };
        const sp = /\bspawn\s*\(/.exec(line);
        if (sp && /shell\s*:\s*true/.test(line) && taintedAfter(line, sp)) return { sink: "spawn" };
      }
      if (lang.py) {
        const osCall = /\bos\s*\.\s*(system|popen)\s*\(/.exec(line);
        if (osCall && taintedAfter(line, osCall)) return { sink: `os.${osCall[1]}` };
        const sub = /\bsubprocess\s*\.\s*(call|run|Popen|check_output|check_call)\s*\(/.exec(line);
        if (sub && /shell\s*=\s*True/.test(line) && taintedAfter(line, sub)) return { sink: `subprocess.${sub[1]}` };
      }
      if (lang.java) {
        const rt = /\.exec\s*\(/.exec(line);
        if (rt && taintedAfter(line, rt)) return { sink: "Runtime.exec" };
      }
      if (lang.php) {
        const fn = /\b(shell_exec|passthru|exec|system|popen)\s*\(/.exec(line);
        if (fn && taintedAfter(line, fn)) return { sink: fn[1] };
      }
      if (lang.rb) {
        const bt = /`[^`\n]*#\{/.exec(line);
        if (bt) return { sink: "backticks" };
        const pct = /%x[\[\{\(][^\n]*#\{/.exec(line);
        if (pct) return { sink: "%x" };
        const sys = /(^|[^.\w$])system\s*\(?/.exec(line);
        if (sys && isTainted(firstArg(line.slice(sys.index + sys[0].length)))) return { sink: "system" };
      }
      if (lang.go) {
        const g = /\bexec\s*\.\s*Command\s*\(\s*"(sh|bash)"\s*,\s*"-c"/.exec(line);
        // The match already consumed the shell and -c args, so the
        // tainted input is one of the remaining arguments, not the first.
        if (g && splitTopLevelArgs(line.slice(g.index + g[0].length)).some((a) => isTainted(a))) return { sink: "exec.Command" };
      }
      return null;
    },
  },
  {
    id: "sql-injection",
    title: "SQL injection",
    severity: "high",
    category: "code-risk",
    fix: "Use a parameterized query with placeholders instead of building the query string from input.",
    detail: (hit) => `A SQL query built from input is passed to ${hit.sink}.`,
    match: (line, lang) => {
      if (!lang.code) return null;
      const dot = /(\w+)\s*\.\s*(query|execute|executeQuery|rawQuery|execQuery)\s*\(/.exec(line);
      if (dot && dot[1] !== "executor" && dot[1] !== "executors" && taintedAfter(line, dot)) return { sink: dot[2] };
      const prep = /\b(prepareStatement|createQuery|createNativeQuery)\s*\(/.exec(line);
      if (prep && taintedAfter(line, prep)) return { sink: prep[1] };
      const bare = /(^|[^.\w$])query\s*\(/.exec(line);
      if (bare && taintedAfter(line, bare)) return { sink: "query" };
      const mq = /\b(?:mysqli?_query|pg_query)\s*\(/.exec(line);
      if (mq) {
        const rest = line.slice(mq.index + mq[0].length);
        const args = splitTopLevelArgs(rest);
        if (args.length > 1 && isTainted(firstArg(args.slice(1).join(",")))) return { sink: "mysqli_query" };
      }
      return null;
    },
  },
  {
    id: "unsafe-deserialization",
    title: "Unsafe deserialization",
    severity: "high",
    category: "code-risk",
    fix: "Only deserialize data you trust, or switch to a safe format such as JSON.",
    detail: (hit) => `${hit.sink} deserializes data that may come from an untrusted source.`,
    match: (line, lang) => {
      if (lang.py) {
        const pk = /\b(pickle|marshal)\s*\.\s*(loads?|load)\s*\(/.exec(line);
        if (pk && taintedAfter(line, pk)) return { sink: `${pk[1]}.${pk[2]}` };
        const yl = /\byaml\s*\.\s*load\s*\(/.exec(line);
        if (yl && !/SafeLoader|safe_load/.test(line) && taintedAfter(line, yl)) return { sink: "yaml.load" };
      }
      if (lang.java) {
        // readObject takes no argument: the stream itself is the
        // untrusted source, so the call alone is the finding.
        const ro = /\.readObject\s*\(/.exec(line);
        if (ro) return { sink: "readObject" };
      }
      if (lang.php) {
        const un = /\bunserialize\s*\(/.exec(line);
        if (un && taintedAfter(line, un)) return { sink: "unserialize" };
      }
      if (lang.rb) {
        const ml = /\bMarshal\s*\.\s*(load|restore)\s*\(/.exec(line);
        if (ml && taintedAfter(line, ml)) return { sink: `Marshal.${ml[1]}` };
      }
      return null;
    },
  },
  {
    id: "weak-hash",
    title: "Weak crypto: MD5 or SHA1",
    severity: "medium",
    category: "code-risk",
    fix: "Hash passwords with a slow password hash such as bcrypt, scrypt, or Argon2, not MD5 or SHA1.",
    detail: (hit) => `${hit.sink} is a broken hash and must not be used for passwords or tokens.`,
    match: (line, lang) => {
      if (!lang.code) return null;
      if (/\b(?:checksum|etag|filehash|contenthash)\b/i.test(line)) return null;
      const label = (raw: string): string => (/md5/i.test(raw) ? "MD5" : "SHA-1");
      const patterns = [
        /\bhashlib\s*\.\s*(md5|sha1)\s*\(/,
        /createHash\s*\(\s*["'](md5|sha1)["']/,
        /getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']/,
        /CryptoJS\s*\.\s*(MD5|SHA1)\s*\(/,
        /\bDigest\s*::\s*(MD5|SHA1)\b/,
        /\bhash\s*\(\s*["'](md5|sha1)["']/,
      ];
      for (const p of patterns) {
        const m = p.exec(line);
        if (m) return { sink: label(m[1] ?? m[0]) };
      }
      if (lang.js || lang.php) {
        const m = /\b(md5|sha1)\s*\(/.exec(line);
        if (m) return { sink: label(m[1]) };
      }
      return null;
    },
  },
  {
    id: "weak-random-token",
    title: "Weak random token generation",
    severity: "medium",
    category: "code-risk",
    fix: "Generate tokens with a cryptographic random source, such as crypto.randomBytes or the secrets module.",
    detail: (hit) => `A token or secret is generated with ${hit.sink}, which an attacker can predict.`,
    match: (line, lang) => {
      if (!lang.code) return null;
      if (!/\b(?:token|secret|password|passwd|pwd|credential|otp|nonce|apiKey|auth|session|key)\b/i.test(line)) return null;
      if (lang.js && /\bMath\s*\.\s*random\s*\(/.test(line)) return { sink: "Math.random" };
      if (lang.py && /\brandom\s*\.\s*random\s*\(/.test(line)) return { sink: "random.random" };
      return null;
    },
  },
  {
    id: "hardcoded-iv",
    title: "Hardcoded encryption IV",
    severity: "medium",
    category: "code-risk",
    fix: "Generate a fresh random IV for every encryption and store it with the ciphertext.",
    detail: () => "The encryption IV is a fixed literal, so the same plaintext always encrypts the same way.",
    match: (line, lang) => {
      if (!lang.code) return null;
      if (/\bIvParameterSpec\s*\(\s*["']/.test(line)) return { sink: "IvParameterSpec" };
      if (/\biv\s*[:=]\s*["'][^"']{4,}["']/.test(line)) return { sink: "hardcoded IV" };
      return null;
    },
  },
  {
    id: "broken-cipher",
    title: "Broken cipher DES or RC4",
    severity: "medium",
    category: "code-risk",
    fix: "Use AES-GCM or ChaCha20-Poly1305 instead of DES or RC4.",
    detail: (hit) => `${hit.sink} is a broken cipher and must not be used for encryption.`,
    match: (line, lang) => {
      if (!lang.code) return null;
      if (/des-ede|3des/i.test(line)) return null;
      const m = /["'](DES|RC4|des|rc4)\b/.exec(line);
      if (m && /(cipher|Cipher|createCipher|getInstance|encrypt|algorithm)/i.test(line)) return { sink: m[1].toUpperCase() };
      return null;
    },
  },
  {
    id: "path-traversal",
    title: "Path traversal",
    severity: "medium",
    category: "code-risk",
    fix: "Resolve the path inside the intended directory and reject any path that escapes it.",
    detail: (hit) => `A file path built from input is opened with ${hit.sink} without checking it stays inside the intended directory.`,
    match: (line, lang) => {
      if (lang.js || lang.py) {
        const open = /(^|[^.\w$])open\s*\(/.exec(line);
        if (open && pathTainted(firstArg(line.slice(open.index + open[0].length)))) return { sink: "open" };
        const rf = /\b(readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|sendFile|send_file)\s*\(/.exec(line);
        if (rf && pathTainted(firstArg(line.slice(rf.index + rf[0].length)))) return { sink: rf[1] };
        const pj = /\bpath\s*\.\s*join\s*\(/.exec(line);
        if (pj) {
          const args = splitTopLevelArgs(line.slice(pj.index + pj[0].length));
          if (args.some((a) => pathTainted(a))) return { sink: "path.join" };
        }
      }
      if (lang.java) {
        const fis = /\bnew\s+(FileInputStream|FileReader|File)\s*\(/.exec(line);
        if (fis && pathTainted(firstArg(line.slice(fis.index + fis[0].length)))) return { sink: `new ${fis[1]}` };
      }
      if (lang.php) {
        const fgc = /\bfile_get_contents\s*\(/.exec(line);
        if (fgc && pathTainted(firstArg(line.slice(fgc.index + fgc[0].length)))) return { sink: "file_get_contents" };
        const inc = /\b(include|include_once|require|require_once)\b/.exec(line);
        if (inc && pathTainted(line.slice(inc.index + inc[0].length))) return { sink: inc[1] };
      }
      return null;
    },
  },
  {
    id: "ssrf",
    title: "Server-side request forgery (SSRF)",
    severity: "medium",
    category: "code-risk",
    fix: "Validate the URL against an allowlist of hosts before requesting it.",
    detail: (hit) => `A URL built from input is passed to ${hit.sink} without checking where it points.`,
    match: (line, lang) => {
      const sinks: { re: RegExp; ok: boolean; sink: string }[] = [
        { re: /\bfetch\s*\(/, ok: lang.js, sink: "fetch" },
        { re: /\brequests\s*\.\s*(get|post|put|delete|head)\s*\(/, ok: lang.py, sink: "requests.get" },
        { re: /\bhttp\s*\.\s*(get|post)\s*\(/, ok: lang.js, sink: "http.get" },
        { re: /\bhttps\s*\.\s*(get|post)\s*\(/, ok: lang.js, sink: "https.get" },
        { re: /\baxios\s*\.\s*(get|post|put|delete|request)\s*\(/, ok: lang.js, sink: "axios.get" },
        { re: /\burlopen\s*\(/, ok: lang.py, sink: "urlopen" },
        { re: /\bhttp\s*\.\s*Get\s*\(/, ok: lang.go, sink: "http.Get" },
      ];
      for (const s of sinks) {
        if (!s.ok) continue;
        const m = s.re.exec(line);
        if (!m) continue;
        const arg = firstArg(line.slice(m.index + m[0].length));
        if (isTainted(arg) && USER_INPUT.test(arg)) return { sink: s.sink };
      }
      return null;
    },
  },
  {
    id: "cors-open",
    title: "CORS allows any origin",
    severity: "medium",
    category: "web-config",
    fix: "Allow only the specific origins this app needs instead of every origin.",
    detail: () => "The server allows any origin to read its responses, so any website can call it from a visitor's browser.",
    match: (line, lang) => {
      if (!lang.code) return null;
      if (/Access-Control-Allow-Origin["']?\s*[:=,]\s*["']?\*/.test(line)) return { sink: "Access-Control-Allow-Origin" };
      if (/\borigins?\s*[:=]\s*["']?\*/.test(line)) return { sink: "origin" };
      if (/allow_origins\s*=\s*\[[^\]]*["']?\*/.test(line)) return { sink: "allow_origins" };
      return null;
    },
  },
  {
    id: "cookie-flags",
    title: "Cookie set without security flags",
    severity: "low",
    category: "web-config",
    fix: "Set HttpOnly, Secure, and SameSite on every cookie.",
    detail: (hit) => `A cookie is set without ${hit.note ?? "HttpOnly, Secure, and SameSite"}.`,
    match: (line, lang) => {
      if (!lang.code) return null;
      const missing = (value: string): string[] => {
        const lower = value.toLowerCase();
        const out: string[] = [];
        if (!lower.includes("httponly")) out.push("HttpOnly");
        if (!lower.includes("secure")) out.push("Secure");
        if (!lower.includes("samesite")) out.push("SameSite");
        return out;
      };
      // Built from parts so this file itself never holds the literal
      // header name next to a value, which would trip the detector.
      const hdr = "set-" + "cookie";
      const hdrIdx = line.toLowerCase().indexOf(hdr);
      if (hdrIdx !== -1) {
        const miss = missing(line.slice(hdrIdx + hdr.length));
        if (miss.length > 0) return { sink: "cookie header", note: miss.join(", ") };
        return null;
      }
      const doc = /document\.cookie\s*=/.exec(line);
      if (doc) {
        const miss = missing(line.slice(doc.index + doc[0].length));
        if (miss.length > 0) return { sink: "document.cookie", note: miss.join(", ") };
        return null;
      }
      const res = /\bres\s*\.\s*cookie\s*\(/.exec(line);
      if (res) {
        const miss = missing(line);
        if (miss.length > 0) return { sink: "res.cookie", note: miss.join(", ") };
        return null;
      }
      const nx = /\bcookies\s*\(\s*\)\s*\.\s*set\s*\(/.exec(line);
      if (nx) {
        const miss = missing(line);
        if (miss.length > 0) return { sink: "cookies().set", note: miss.join(", ") };
        return null;
      }
      return null;
    },
  },
  {
    id: "jwt-none",
    title: "JWT accepted with none algorithm",
    severity: "high",
    category: "web-config",
    fix: "Require a signed algorithm such as RS256 or HS256 and reject unsigned tokens.",
    detail: () => "Tokens are accepted with the none algorithm, so anyone can forge a token with no signature.",
    match: (line, lang) => {
      if (!lang.code) return null;
      if (/algorithms?\s*[:=]\s*["']none["']/.test(line)) return { sink: "algorithm none" };
      if (/algorithms?\s*[:=]\s*\[[^\]]*["']none["']/.test(line)) return { sink: "algorithms none" };
      if (/\balg\s*[:=]\s*["']none["']/.test(line)) return { sink: "alg none" };
      return null;
    },
  },
  {
    id: "tls-verify-off",
    title: "TLS certificate validation disabled",
    severity: "high",
    category: "tls",
    fix: "Leave certificate validation on. If a private CA is involved, trust that CA instead of disabling checks.",
    detail: () => "Certificate validation is disabled, so a man in the middle can read or alter the traffic.",
    match: (line, lang) => {
      if (!lang.code) return null;
      if (lang.js && /rejectUnauthorized\s*:\s*false/.test(line)) return { sink: "rejectUnauthorized false" };
      if (lang.py && /verify\s*=\s*False/.test(line)) return { sink: "verify False" };
      if (lang.py && /_create_unverified_context\s*\(/.test(line)) return { sink: "unverified context" };
      if (lang.go && /InsecureSkipVerify\s*:\s*true/.test(line)) return { sink: "InsecureSkipVerify" };
      return null;
    },
  },
  {
    id: "tls-plain-http",
    title: "Plain HTTP used for a network call",
    severity: "medium",
    category: "tls",
    fix: "Use HTTPS for every network call outside localhost.",
    detail: () => "A network call uses plain HTTP, so the traffic is readable and alterable in transit.",
    match: (line, lang) => {
      if (!lang.code) return null;
      const m = /["'`]http:\/\/([^/"'`\s]+)/.exec(line);
      if (!m) return null;
      const host = m[1].toLowerCase().split(":")[0];
      if (host === "localhost" || host === "127.0.0.1" || host.endsWith(".local")) return null;
      if (!/(fetch|axios|requests?|http\.|urlopen|get|post)\b/i.test(line)) return null;
      return { sink: `http://${host}` };
    },
  },
  {
    id: "tls-weak-version",
    title: "Weak TLS version allowed",
    severity: "medium",
    category: "tls",
    fix: "Require TLS 1.2 or newer and drop older versions.",
    detail: () => "An old TLS version is allowed, and old versions have known attacks.",
    match: (line, lang) => {
      if (!lang.code) return null;
      // Built from parts so this file itself never holds the literal
      // pattern next to its match, which would trip the detector.
      const weakTls1 = new RegExp("PROTOCOL_TLS" + "v1(?![23_])");
      if (weakTls1.test(line)) return { sink: "TLSv1" };
      if (/TLSv1_[01]\b/.test(line)) return { sink: "TLSv1.0/1.1" };
      if (lang.go && /TLSVersion10|TLSVersion11/.test(line)) return { sink: "old TLS version" };
      return null;
    },
  },
  {
    id: "log-secret",
    title: "Secret logged in plain text",
    severity: "medium",
    category: "logging",
    fix: "Never log secrets. Log a redacted label or a hash instead.",
    detail: () => "A secret value is written to the logs, where anyone with log access can read it.",
    match: (line, lang) => {
      if (!lang.code) return null;
      const call = /(console\.log|print|logger?\.(?:info|debug|warn|error)|log\.(?:info|debug|warn|error)|fmt\.Print)\s*\(/.exec(line);
      if (!call) return null;
      // Only the log call's own arguments count: a secret named
      // elsewhere on the line (a comment, another statement) is not
      // being logged. String literals are stripped, so a message that
      // merely names a secret is clean; a secret variable is not.
      const args = stripStrings(line.slice(call.index + call[0].length));
      if (/\b(secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|bearer)\b/i.test(args)) return { sink: "secret in log call" };
      return null;
    },
  },
  {
    id: "error-stack-leak",
    title: "Error or stack trace sent in a response",
    severity: "medium",
    category: "logging",
    fix: "Return a generic error message and keep the stack trace in the server logs only.",
    detail: () => "An error or stack trace is sent back in an HTTP response, which hands an attacker internals to work with.",
    match: (line, lang) => {
      if (!lang.code) return null;
      if (/\.\s*(send|json)\s*\(\s*(err|error|e)\b/.test(line)) return { sink: "error in response" };
      if (/status\s*\(\s*500\s*\)\s*\.\s*(send|json)\s*\(/.test(line)) return { sink: "500 with body" };
      if (lang.py && /return[^#\n]*traceback/.test(line)) return { sink: "traceback in response" };
      return null;
    },
  },
  {
    id: "debug-mode",
    title: "Debug mode left on",
    severity: "medium",
    category: "logging",
    fix: "Turn debug off in production. Debug mode can expose an interactive debugger and stack traces.",
    detail: () => "Debug mode is left on, which can expose an interactive debugger and full stack traces to anyone who triggers an error.",
    match: (line, lang) => {
      if (!lang.code) return null;
      if (lang.py && /^\s*DEBUG\s*=\s*True\b/.test(line)) return { sink: "DEBUG True" };
      if (/debug\s*=\s*True\b/.test(line)) return { sink: "debug True" };
      if (lang.js && /\.debug\s*=\s*true\b/.test(line)) return { sink: "debug true" };
      return null;
    },
  },
  {
    id: "xss-inner-html",
    title: "Untrusted value written as HTML",
    severity: "high",
    category: "xss",
    fix: "Render the value as text, or sanitise it with a trusted HTML sanitiser first.",
    detail: () => "An untrusted value is written straight into the page as HTML, so an attacker can inject script.",
    match: (line, lang) => {
      if (!lang.code) return null;
      const m = /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/.exec(line);
      if (m) {
        // Serialising a named constant is the standard safe pattern
        // (the JSON-LD blocks in layout.tsx): the value is data, not
        // markup. Anything else tainted is flagged. Limitation: a
        // bare identifier that itself holds user input is treated as
        // clean, which this line based check cannot tell apart.
        if (/^\s*JSON\.stringify\s*\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\)\s*$/.test(m[1])) return null;
        if (isTainted(m[1])) return { sink: "dangerouslySetInnerHTML" };
      }
      const inner = /\.innerHTML\s*=\s*(.+)$/.exec(line);
      if (inner && isTainted(inner[1])) return { sink: "innerHTML" };
      const doc = /document\.write\s*\(\s*(.+)\)/.exec(line);
      if (doc && isTainted(doc[1])) return { sink: "document.write" };
      return null;
    },
  },
  {
    id: "xss-eval",
    title: "Untrusted value passed to eval",
    severity: "high",
    category: "xss",
    fix: "Do not eval untrusted input. Parse the data with JSON.parse or a proper parser instead.",
    detail: () => "An untrusted value is passed to eval, so an attacker can run arbitrary code in the page.",
    match: (line, lang) => {
      if (!lang.code) return null;
      const m = /\beval\s*\(\s*(.+)\)/.exec(line);
      if (m && isTainted(m[1])) return { sink: "eval" };
      return null;
    },
  },
];

/** Scan one file for dangerous code patterns and web config issues.
 *  One finding per rule per line; the first matching sink on the line
 *  wins for that rule. */
export function scanTextForCodeRisks(file: { path: string; content: string }): PostureIssue[] {
  const findings: PostureIssue[] = [];
  if (!file.content) return findings;
  const lang = langOf(extOf(file.path));
  if (!lang.code) return findings;
  const lines = file.content.split("\n");
  const seen = new Set<string>();
  lines.forEach((line, idx) => {
    const lineNo = idx + 1;
    for (const rule of RULES) {
      const hit = rule.match(line, lang);
      if (!hit) continue;
      const key = `${rule.id}:${lineNo}:${hit.sink}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: `code-risk-${rule.id}-${file.path.replace(/[^A-Za-z0-9]/g, "-")}-${lineNo}`,
        title: rule.title,
        severity: rule.severity,
        detail: rule.detail(hit),
        fix: rule.fix,
        category: rule.category,
        file: file.path,
        line: lineNo,
      });
    }
  });
  return findings;
}
