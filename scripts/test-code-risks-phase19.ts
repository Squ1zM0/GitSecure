// Code risk detectors (Phase 19): planted hits and clean cases for
// every detector. Fixture strings are assembled from fragments at
// runtime so no literal sink plus tainted input ever sits in this
// file itself (the self-scan check at the end proves it).
// Run: npx tsx scripts/test-code-risks-phase19.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { scanTextForCodeRisks } from "../src/lib/code-risks";
import type { PostureIssue } from "../src/lib/types";

// Join fragments: keeps a sink name and its open paren in separate
// string literals, so this file never contains a detector match.
function j(...parts: string[]): string {
  return parts.join("");
}

function scanOne(path: string, content: string): PostureIssue[] {
  return scanTextForCodeRisks({ path, content });
}

const has = (list: PostureIssue[], id: string): boolean =>
  list.some((f) => f.id.startsWith(`code-risk-${id}-`));

let failures = 0;
function check(name: string, ok: boolean, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? ` - ${extra}` : ""}`);
  if (!ok) failures++;
}

// A 40-char hex string assembled at runtime, never written literally.
const FAKE_SHA = "ab12".repeat(10);

// --- Command injection ---
const execVar = scanOne("app.js", j("exec", "(", "cmd", ")"));
check("command injection: bare exec with variable flagged", execVar.length === 1 && execVar[0].severity === "high" && execVar[0].category === "code-risk" && execVar[0].file === "app.js" && execVar[0].line === 1, execVar.map((f) => f.title).join("; "));
check("command injection: child process exec with concat flagged", has(scanOne("app.js", j("child_process.", "exec", "(", '"ls " + ', "dir", ")")), "command-injection"));
check("command injection: execSync with template flagged", has(scanOne("app.js", j("execSync", "(", "`ls ${", "dir", "}`", ")")), "command-injection"));
check("command injection: spawn shell true with variable flagged", has(scanOne("app.js", j("spawn", "(", '"ls " + ', "dir", ", ", "{ shell: true }", ")")), "command-injection"));
check("command injection: spawn shell true with constant is clean", scanOne("app.js", j("spawn", "(", '"ls"', ", ", "{ shell: true }", ")")).length === 0);
check("command injection: spawn without shell is clean", scanOne("app.js", j("spawn", "(", '"git"', ", ", "args", ")")).length === 0);
check("command injection: bare exec with constant is clean", scanOne("app.js", j("exec", "(", '"ls -la"', ")")).length === 0);
check("command injection: exec with constant concat is clean", scanOne("app.js", j("exec", "(", '"ls " + ', '"la"', ")")).length === 0);
check("command injection: os system with variable flagged", has(scanOne("app.py", j("os.", "system", "(", "cmd", ")")), "command-injection"));
check("command injection: os system with constant is clean", scanOne("app.py", j("os.", "system", "(", '"ls -la"', ")")).length === 0);
check("command injection: subprocess shell True with concat flagged", has(scanOne("app.py", j("subprocess.", "Popen", "(", '"ls " + ', "userInput", ", ", "shell=True", ")")), "command-injection"));
check("command injection: subprocess shell True with constant is clean", scanOne("app.py", j("subprocess.", "Popen", "(", '"ls"', ", ", "shell=True", ")")).length === 0);
check("command injection: subprocess without shell is clean", scanOne("app.py", j("subprocess.", "run", "(", "[", '"ls"', ", ", "userInput", "]", ")")).length === 0);
check("command injection: Java runtime exec with concat flagged", has(scanOne("Main.java", j("Runtime.getRuntime().", "exec", "(", '"ls " + ', "cmd", ")")), "command-injection"));
check("command injection: PHP shell exec with variable flagged", has(scanOne("shell.php", j("shell_exec", "(", "$cmd", ")")), "command-injection"));
check("command injection: PHP shell exec with constant is clean", scanOne("shell.php", j("shell_exec", "(", '"ls -la"', ")")).length === 0);
check("command injection: Ruby backticks with interpolation flagged", has(scanOne("run.rb", j("`ls #{", "userInput", "}`")), "command-injection"));
check("command injection: Ruby system with interpolation flagged", has(scanOne("run.rb", j("system", "(", '"ls #{', "dir", '}"', ")")), "command-injection"));
check("command injection: Go shell command flagged", has(scanOne("main.go", j("exec.", "Command", "(", '"sh"', ", ", '"-c"', ", ", '"ls " + ', "cmd", ")")), "command-injection"));
check("command injection: Go exec Command without shell is clean", scanOne("main.go", j("exec.", "Command", "(", '"ls"', ", ", "userInput", ")")).length === 0);
check("command injection: regex exec is not a finding", scanOne("app.js", "const m = /^(a+)$/.exec(text);").length === 0);

// --- SQL injection ---
check("SQL injection: query with concat flagged", has(scanOne("app.js", j("db.", "query", "(", '"SELECT * FROM users WHERE id = " + ', "userId", ")")), "sql-injection"));
check("SQL injection: execute with f-string flagged", has(scanOne("app.py", j("cursor.", "execute", "(", 'f"SELECT * FROM users WHERE id = {', "userId", '}"', ")")), "sql-injection"));
check("SQL injection: query with template flagged", has(scanOne("app.js", j("pool.", "query", "(", "`SELECT * FROM t WHERE id = ${", "userId", "}`", ")")), "sql-injection"));
check("SQL injection: constant query is clean", scanOne("app.js", j("db.", "query", "(", '"SELECT 1"', ")")).length === 0);
check("SQL injection: parameterized query is clean", scanOne("app.py", j("cursor.", "execute", "(", '"SELECT * FROM users WHERE id = %s"', ", ", "(userId,)", ")")).length === 0);
check("SQL injection: percent formatting flagged", has(scanOne("app.py", j("cursor.", "execute", "(", '"SELECT * FROM users WHERE id = %s" % ', "userId", ")")), "sql-injection"));
check("SQL injection: prepareStatement with concat flagged", has(scanOne("Main.java", j("prepareStatement", "(", '"SELECT * FROM t WHERE id = " + ', "id", ")")), "sql-injection"));

// --- Unsafe deserialization ---
check("deserialization: pickle loads with variable flagged", has(scanOne("app.py", j("pickle.", "loads", "(", "data", ")")), "unsafe-deserialization"));
check("deserialization: pickle loads with constant is clean", scanOne("app.py", j("pickle.", "loads", "(", 'b"abc"', ")")).length === 0);
check("deserialization: yaml load with variable flagged", has(scanOne("app.py", j("yaml.", "load", "(", "text", ")")), "unsafe-deserialization"));
check("deserialization: yaml load with SafeLoader is clean", scanOne("app.py", j("yaml.", "load", "(", "text", ", ", "Loader=yaml.SafeLoader", ")")).length === 0);
check("deserialization: yaml safe load is clean", scanOne("app.py", j("yaml.", "safe_load", "(", "text", ")")).length === 0);
check("deserialization: Java readObject flagged", has(scanOne("Main.java", j("in.", "readObject", "(", ")", ";")), "unsafe-deserialization"));
check("deserialization: PHP unserialize with variable flagged", has(scanOne("shell.php", j("unserialize", "(", "$data", ")")), "unsafe-deserialization"));
check("deserialization: Ruby Marshal load with variable flagged", has(scanOne("run.rb", j("Marshal.", "load", "(", "data", ")")), "unsafe-deserialization"));
check("deserialization: JSON parse is never flagged", scanOne("app.js", "const data = JSON.parse(text);").length === 0);

// --- Weak crypto ---
check("weak crypto: hashlib md5 on password flagged", has(scanOne("app.py", j("hashlib.", "md5", "(", "password", ")", ".hexdigest()")), "weak-hash"));
check("weak crypto: createHash md5 flagged", has(scanOne("app.js", j("crypto.", "createHash", "(", '"md5"', ")")), "weak-hash"));
check("weak crypto: createHash sha256 is clean", scanOne("app.js", j("crypto.", "createHash", "(", '"sha256"', ")")).length === 0);
check("weak crypto: md5 checksum is clean", scanOne("app.py", j("hashlib.", "md5", "(", "data", ")", ".hexdigest()  # checksum")).length === 0);
check("weak crypto: Math random token flagged", has(scanOne("app.js", "const token = " + j("Math.", "random", "(", ")", ".toString(36)")), "weak-random-token"));
check("weak crypto: Math random without token context is clean", scanOne("app.js", "const roll = " + j("Math.", "random", "(", ")") + ";").length === 0);
check("weak crypto: random random token flagged", has(scanOne("app.py", "token = " + j("random.", "random", "(", ")")), "weak-random-token"));
check("weak crypto: hardcoded IV flagged", has(scanOne("app.py", j("iv", " = ", '"1234567890123456"')), "hardcoded-iv"));
check("weak crypto: random IV is clean", scanOne("app.py", j("iv", " = ", "os.urandom(16)")).length === 0);
check("weak crypto: DES cipher flagged", has(scanOne("Main.java", j("Cipher.getInstance", "(", '"D', 'ES"', ")")), "broken-cipher"));
check("weak crypto: AES cipher is clean", scanOne("Main.java", j("Cipher.getInstance", "(", '"AES/GCM/NoPadding"', ")")).length === 0);
check("weak crypto: RC4 cipher flagged", has(scanOne("app.js", j("crypto.", "createCipher", "(", '"r', 'c4"', ", ", "key", ")")), "broken-cipher"));

// --- Path traversal ---
check("path traversal: open with user path flagged", has(scanOne("app.py", j("open", "(", "userPath", ")")), "path-traversal"));
check("path traversal: readFile with request params flagged", has(scanOne("app.js", j("fs.", "readFile", "(", "req.params.file", ", ", "cb", ")")), "path-traversal"));
check("path traversal: path join with user input flagged", has(scanOne("app.js", j("path.", "join", "(", "base", ", ", "userInput", ")")), "path-traversal"));
check("path traversal: open with constant is clean", scanOne("app.py", j("open", "(", '"config.json"', ")")).length === 0);
check("path traversal: path join with constants is clean", scanOne("app.js", j("path.", "join", "(", "__dirname", ", ", '"public"', ")")).length === 0);
check("path traversal: readFile with internal path is clean", scanOne("app.js", j("fs.", "readFile", "(", "localPath", ", ", "cb", ")")).length === 0);
check("path traversal: PHP include with GET flagged", has(scanOne("shell.php", j("include ", "$_GET", "[", '"page"', "]", ";")), "path-traversal"));

// --- SSRF ---
check("SSRF: fetch with user input flagged", has(scanOne("app.js", j("fetch", "(", '"https://api.example.com/" + ', "userInput", ")")), "ssrf"));
check("SSRF: requests get with user URL flagged", has(scanOne("app.py", j("requests.", "get", "(", "userUrl", ")")), "ssrf"));
check("SSRF: fetch with constant is clean", scanOne("app.js", j("fetch", "(", '"https://api.example.com/data"', ")")).length === 0);
check("SSRF: fetch with API template and encoded id is clean", scanOne("app.js", j("fetch", "(", "`https://api.osv.dev/v1/vulns/${", "encodeURIComponent(id)", "}`", ")")).length === 0);
check("SSRF: Go http Get with user input flagged", has(scanOne("main.go", j("http.", "Get", "(", "userInput", ")")), "ssrf"));
check("SSRF: axios get with user URL flagged", has(scanOne("app.js", j("axios.", "get", "(", "userUrl", ")")), "ssrf"));

// --- Web config ---
const corsHit = scanOne("app.js", j("Access-Control-Allow-", "Origin", ": ", "*"));
check("web config: CORS header star flagged", corsHit.length === 1 && corsHit[0].severity === "medium" && corsHit[0].category === "web-config", corsHit.map((f) => f.title).join("; "));
check("web config: cors origin star flagged", has(scanOne("app.js", j("cors", "(", "{ origin: ", '"*"', " }", ")")), "cors-open"));
check("web config: cors specific origin is clean", scanOne("app.js", j("cors", "(", "{ origin: ", '"https://example.com"', " }", ")")).length === 0);
check("web config: allow origins star flagged", has(scanOne("app.py", j("allow_origins", "=", "[", '"*"', "]")), "cors-open"));
const cookieHit = scanOne("app.js", j("Set-", "Cookie", ": ", "session=abc123"));
check("web config: cookie header without flags flagged", cookieHit.length === 1 && cookieHit[0].severity === "low" && cookieHit[0].category === "web-config" && /HttpOnly/.test(cookieHit[0].detail), cookieHit.map((f) => f.detail).join("; "));
check("web config: cookie header with all flags is clean", scanOne("app.js", j("Set-", "Cookie", ": ", "session=abc123; HttpOnly; Secure; SameSite=Strict")).length === 0);
check("web config: res cookie without flags flagged", has(scanOne("app.js", j("res.", "cookie", "(", '"session"', ", ", "token", ")")), "cookie-flags"));
check("web config: res cookie with flags is clean", scanOne("app.js", j("res.", "cookie", "(", '"session"', ", ", "token", ", ", "{ httpOnly: true, secure: true, sameSite: 'strict' }", ")")).length === 0);
const jwtHit = scanOne("app.js", j("algorithms", ": ", "[", '"none"', "]"));
check("web config: JWT algorithms none flagged", jwtHit.length === 1 && jwtHit[0].severity === "high" && jwtHit[0].category === "web-config", jwtHit.map((f) => f.title).join("; "));
check("web config: JWT sign with none algorithm flagged", has(scanOne("app.js", j("jwt.", "sign", "(", "payload", ", ", "secret", ", ", "{ algorithm: ", '"none"', " }", ")")), "jwt-none"));
check("web config: JWT sign with RS256 is clean", scanOne("app.js", j("jwt.", "sign", "(", "payload", ", ", "secret", ", ", "{ algorithm: ", '"RS256"', " }", ")")).length === 0);

// --- Other ---
check("other: SHA pinned action is not a code risk finding", scanOne(".github/workflows/ci.yml", "- uses: actions/checkout@" + FAKE_SHA).length === 0);
const thirdLine = scanOne("app.py", "import os\n\n" + j("os.", "system", "(", "cmd", ")"));
check("other: line numbers point at the hit line", thirdLine.length === 1 && thirdLine[0].line === 3, thirdLine.map((f) => String(f.line)).join("; "));
check("other: finding carries file line category severity fix", execVar.length === 1 && execVar[0].detail.length > 0 && execVar[0].fix.length > 0 && !/\u2014/.test(execVar[0].detail + execVar[0].fix));
check("other: empty content has no findings", scanOne("app.js", "").length === 0);
check("other: non-code file has no findings", scanOne("notes.txt", j("exec", "(", "cmd", ")")).length === 0);
const allHits = [
  ...scanOne("app.js", j("exec", "(", "cmd", ")")),
  ...scanOne("app.js", j("db.", "query", "(", '"x" + ', "userId", ")")),
  ...scanOne("app.js", j("fetch", "(", '"https://x/" + ', "userInput", ")")),
  ...scanOne("app.js", j("algorithms", ": ", "[", '"none"', "]")),
];
check("other: no em dash in any finding copy", allHits.length === 4 && allHits.every((f) => !/\u2014/.test(f.title + f.detail + f.fix)), allHits.map((f) => f.title).join("; "));

// --- Self-scan: the detector must stay quiet on its own source and
// on this test file, or the self-scan baseline breaks.
const selfCode = readFileSync(fileURLToPath(new URL("../src/lib/code-risks.ts", import.meta.url)), "utf8");
const selfCodeFindings = scanTextForCodeRisks({ path: "src/lib/code-risks.ts", content: selfCode });
check("self-scan: code-risks source has no findings on itself", selfCodeFindings.length === 0, selfCodeFindings.map((f) => `${f.title}@${f.line}`).join("; "));
const selfTest = readFileSync(fileURLToPath(new URL(import.meta.url)), "utf8");
const selfTestFindings = scanTextForCodeRisks({ path: "scripts/test-code-risks-phase19.ts", content: selfTest });
check("self-scan: this test file has no findings on itself", selfTestFindings.length === 0, selfTestFindings.map((f) => `${f.title}@${f.line}`).join("; "));

console.log(failures === 0 ? "\nAll code risk tests passed." : `\n${failures} test(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
