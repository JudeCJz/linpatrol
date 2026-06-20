const INITIAL_DATABASE = {
  blacklist: [
    // High-Risk Malicious Domains (Exact matches needed)
    "malicious.com", "malicious-phish.biz", "secure-bank-login.net", "verify-your-identity.org",
    "urgent-account-update.info", "free-giftcard-generator.xyz", "claim-your-prize.click",
    "locked-account-service.tk", "re-authenticate-now.fun", "unauthorized-access-warning.co",
    "official-support-portal.bid", "system-security-check.gq", "identity-theft-protection.ml",
    "download-malware-tool.cc", "crack-software-free.pw", "fake-crypto-wallet.top",
    "air-drop-claim.live", "metamask-auth-fix.link", "bank-of-america-verify.com",
    "wellsfargo-update-portal.net", "chase-online-service.info", "paypal-resolution-center.com",
    "netflix-billing-issue.org", "amazon-order-delivery.click", "ups-parcel-tracking-fix.biz",
    "fedex-shipping-notice.icu", "dhl-clearance-fee.xyz", "apple-id-suspended.top",
    "microsoft-account-critical.co", "google-security-alert-verification.net"
  ],
  whitelist: [
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "twitter.com", "linkedin.com", "netflix.com",
    "wikipedia.org", "youtube.com", "stackoverflow.com", "reddit.com", "mozilla.org",
    "developer.mozilla.org", "googlevideo.com", "gstatic.com", "googleusercontent.com",
    "cdc.gov", "who.int", "nih.gov", "adobe.com", "dropbox.com", "salesforce.com"
  ],
  keywords: [
    // High-fidelity heuristic triggers (Matches partials in URL context)
    "malicious", "verify", "secure", "login", "locked", "suspended", "identity", 
    "breach", "compromised", "lottery", "urgent", "bypass", "unauthorized",
    "claim", "gift", "reward", "prize", "free", "account", "update", "signin",
    "support", "official", "billing", "delivery", "parcel", "shipping",
    "loyalty", "programme", "bonus", "winner", "win", "sweepstakes"
  ],
  suspiciousTlds: [
    // TLDs commonly used in ephemeral phishing/malware delivery
    ".tk", ".ml", ".ga", ".gq", ".cf", ".xyz", ".top", ".bid", ".click", ".pw",
    ".icu", ".fun", ".live", ".link", ".online", ".website", ".zip", ".mov", ".sbs", ".cam"
  ],
  sensitiveBrands: [
    "google", "microsoft", "apple", "amazon", "facebook", "instagram", "twitter", 
    "linkedin", "netflix", "paypal", "chase", "bank of america", "wellsfargo", 
    "coca-cola", "cocacola", "fedex", "ups", "dhl", "metamask", "binance"
  ],
  dangerousExtensions: [
    ".exe", ".msi", ".bat", ".cmd", ".scr", ".vbs", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".jar", ".iso", ".img", ".dmg", ".pkg", ".app"
  ],
  urlShorteners: [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "mzl.la"
  ]
};

// environment-aware export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { INITIAL_DATABASE };
} else {
  // Use self (works in both Window and ServiceWorker scopes)
  self.INITIAL_DATABASE = INITIAL_DATABASE;
}
