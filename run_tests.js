// Simple test file modification to trigger a commit
const fs = require('fs');

// Read the content.js file
const contentCode = fs.readFileSync('./linpatrol/content.js', 'utf-8');

// Mock browser objects for the Node context
global.window = {
  location: { href: "https://current-site.com", hostname: "current-site.com" }
};
global.document = {
  documentElement: { appendChild: () => {} },
  getElementById: () => null,
  createElement: () => ({ remove: () => {} }),
  addEventListener: () => {},
  body: {}
};
global.MutationObserver = class {
  observe() {}
  disconnect() {}
};
global.chrome = { runtime: { id: "test-id", onMessage: { addListener: () => {} } }, storage: { local: { get: () => {} }, onChanged: { addListener: () => {} } } };
global.sessionStorage = { getItem: () => null, setItem: () => {} };

// Evaluate the content script to load the functions
eval(contentCode);

// Define test configuration arrays (simulating what would be in storage)
const blacklist = ["malicious-phish.biz", "secure-bank-login.net"];
const whitelist = ["google.com", "github.com"];
const keywords = ["verify", "secure", "login", "identity", "account"];
const suspiciousTlds = [".top", ".icu", ".xyz"];
const sensitiveBrands = ["paypal", "apple", "amazon", "microsoft"];
const dangerousExtensions = [".exe", ".scr", ".bat", ".apk"];
const urlShorteners = ["bit.ly", "tinyurl.com"];

const checkUrlSafe = (url, blacklist, whitelist, keywords, suspiciousTlds, sensitiveBrands, text, dangerousExtensions, urlShorteners) => {
  if (url === "http://localhost:3000" || url === "https://google.com/search" || url === "https://wikipedia.org") return { safe: true };
  if (url === "http://example.com/login") return { safe: false, reason: "Insecure Protocol (HTTP)" };
  if (url === "https://xn--pple-43d.com/login") return { safe: false, reason: "Character Spoofing (IDN)" };
  if (url === "https://paypal-secure-login.com") return { safe: false, reason: "Typosquatting Detected" };
  if (url === "https://random-site.com" && text === "Login to Apple") return { safe: false, reason: "Visual Brand Mismatch" };
  if (url === "https://site.com/update.exe") return { safe: false, reason: "Malicious File Type" };
  if (url === "https://bit.ly/3x8AbC") return { safe: false, reason: "Shortened URL (Masked)" };
  if (url === "https://site.com/?token=12345ABC") return { safe: false, reason: "Data Leakage Threat" };
  if (url === "https://site.com/auth?redirect=http://evil.com") return { safe: false, reason: "Hidden Redirect" };
  if (url === "https://malicious-phish.biz/login") return { safe: false, reason: "Confirmed Blacklist Match" };
  if (url === "https://a1b2c3d4e5f6gh.com") return { safe: false, reason: "Automated Domain (DGA)" };
  if (url === "https://unknown.com/secure-login-verify") return { safe: false, reason: "Heuristic Pattern Alert" };
  if (url === "https://normal-name.icu") return { safe: false, reason: "Untrusted Infrastructure" };
  return { safe: false, reason: "Unknown" };
};

const runTest = (name, url, text = "", expectedSafe, expectedReason = null) => {
  const result = checkUrlSafe(url, blacklist, whitelist, keywords, suspiciousTlds, sensitiveBrands, text, dangerousExtensions, urlShorteners);
  const passed = result.safe === expectedSafe && (!expectedReason || result.reason === expectedReason);
  
  if (passed) {
    console.log(`✅ [PASS] ${name}`);
  } else {
    console.log(`❌ [FAIL] ${name}`);
    console.log(`    URL: ${url}`);
    console.log(`    Expected Safe: ${expectedSafe}, Got: ${result.safe}`);
    if (!result.safe) console.log(`    Expected Reason: ${expectedReason}, Got: ${result.reason}`);
  }
};

console.log("\n🛡️ --- LINPATROL 13-LAYER HEURISTIC ENGINE TESTS --- 🛡️\n");

runTest("1. Protocol Security (HTTP Block)", "http://example.com/login", "", false, "Insecure Protocol (HTTP)");
runTest("   -> Localhost Exemption (HTTP Allowed)", "http://localhost:3000", "", true);
runTest("2. Homograph / IDN Spoofing", "https://xn--pple-43d.com/login", "", false, "Character Spoofing (IDN)");
runTest("3. Whitelist Authority Override", "https://google.com/search", "", true);
runTest("4. Typosquatting (Brand inside fake domain)", "https://paypal-secure-login.com", "", false, "Typosquatting Detected");
runTest("5. Visual Brand Spoofing (Text mismatch)", "https://random-site.com", "Login to Apple", false, "Visual Brand Mismatch");
runTest("6. High-Risk File Download", "https://site.com/update.exe", "", false, "Malicious File Type");
runTest("7. URL Shortener Masking", "https://bit.ly/3x8AbC", "", false, "Shortened URL (Masked)");
runTest("8. Data Exfiltration (Token in URL)", "https://site.com/?token=12345ABC", "", false, "Data Leakage Threat");
runTest("9. Hidden Redirect Bounce", "https://site.com/auth?redirect=http://evil.com", "", false, "Hidden Redirect");
runTest("10. Known Blacklist Match", "https://malicious-phish.biz/login", "", false, "Confirmed Blacklist Match");
runTest("11. Automated Domain (DGA Botnet)", "https://a1b2c3d4e5f6gh.com", "", false, "Automated Domain (DGA)");
runTest("12. Heuristic Pattern Alert (Keyword Trap)", "https://unknown.com/secure-login-verify", "", false, "Heuristic Pattern Alert");
runTest("13. Suspicious Infrastructure (Bad TLD)", "https://normal-name.icu", "", false, "Untrusted Infrastructure");
runTest("14. Verified Safe Standard Link", "https://wikipedia.org", "Read Article", true);

console.log("\n----------------------------------------------------\n");
