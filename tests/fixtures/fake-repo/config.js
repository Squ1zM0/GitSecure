// FAKE fixture only — every credential below is a placeholder.
// The test (scripts/test-scanner.ts) substitutes the invented secret
// strings in memory before scanning, so no literal secret-pattern value
// is ever committed to this file. GitHub push protection blocks literal
// secret patterns even when they are fake, so placeholders live here.
// Nothing here is a real secret. Do not "rotate" these; they never worked.
const DISCORD_HOOK = "__SECRET_0__";
const AWS_KEY = "__SECRET_1__";
const GITHUB_TOKEN = "__SECRET_2__";
const STRIPE_KEY = "__SECRET_3__";
const OPENAI_KEY = "__SECRET_4__";
const DB_URL = "__SECRET_5__";
const password = "hunter2hunter2";
const PRIVATE_KEY = "__SECRET_7__";
module.exports = { DISCORD_HOOK, AWS_KEY, GITHUB_TOKEN, STRIPE_KEY, OPENAI_KEY, DB_URL, password, PRIVATE_KEY };
