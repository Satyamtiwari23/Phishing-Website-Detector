// script.js
// Phishing Website Detector - Heuristic URL Analyzer

const isLoggedIn = localStorage.getItem("demo_token");
if (isLoggedIn) {
  console.log("User logged in");
}

(function () {

  const form = document.getElementById("urlForm");
  const urlInput = document.getElementById("urlInput");
  const inputGroup = document.querySelector(".url-input-group");
  const resultPanel = document.getElementById("resultPanel");
  const riskBadge = document.getElementById("riskBadge");
  const riskScoreEl = document.getElementById("riskScore");
  const riskStatusEl = document.getElementById("riskStatus");
  const reasonList = document.getElementById("reasonList");
  const reportSection = document.getElementById("reportSection");
  const reportBtn = document.getElementById("reportBtn");
  const scanBtn = document.querySelector(".btn-primary");

  /* ======================
     CREATE ERROR TEXT (JS ONLY)
     ====================== */
  const inputError = document.createElement("div");
  inputError.className = "input-error";
  inputError.textContent =
    "Please enter a valid website URL (example: google.com)";
  inputGroup.after(inputError);

  if (!form || !urlInput || !resultPanel) {
    console.error("Required DOM elements not found.");
    return;
  }

  /* ======================
     CONSTANTS
     ====================== */
  const KNOWN_BRANDS = [
    "google.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "paypal.com", "icicibank.com", "hdfcbank.com", "sbi.co.in",
    "amazon.in", "flipkart.com", "paytm.com"
  ];

  const TRUSTED_DOMAINS = [
    "google.com", "accounts.google.com", "facebook.com", "instagram.com",
    "amazon.in", "paypal.com", "sbi.co.in", "icicibank.com", "hdfcbank.com"
  ];

  const SUSPICIOUS_TLDS = [
    ".zip", ".xyz", ".top", ".info", ".work", ".rug", ".gq", ".loan"
  ];

  const SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "confirm", "signin", "support", "security", "billing"
  ];

  const domainPattern =
/^(https?:\/\/)?((localhost)|((([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})|(\d{1,3}(\.\d{1,3}){3})))(:\d{1,5})?([\/?#].*)?$/;


  /* ======================
     LIVE INPUT VALIDATION
     ====================== */
  scanBtn.disabled = true;

  urlInput.addEventListener("input", () => {
    const value = urlInput.value.trim();

    if (!value) {
      inputGroup.classList.remove("invalid");
      inputError.style.display = "none";
      scanBtn.disabled = true;
      return;
    }

    if (!domainPattern.test(value)) {
      inputGroup.classList.add("invalid");
      inputError.style.display = "block";
      scanBtn.disabled = true;
    } else {
      inputGroup.classList.remove("invalid");
      inputError.style.display = "none";
      scanBtn.disabled = false;
    }
  });

  /* ======================
     FORM SUBMIT
     ====================== */
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (scanBtn.disabled) return;

    const analysis = analyzeUrl(urlInput.value.trim());
    renderResult(analysis);
  });

  /* ======================
     URL ANALYSIS
     ====================== */
  function analyzeUrl(rawUrl) {
    let urlString = rawUrl.trim();
    let score = 0;
    const reasons = [];

    if (!domainPattern.test(urlString)) {
      return {
        score: -1,
        reasons: ["Invalid input. Please enter a valid website URL."],
        normalizedUrl: urlString
      };
    }

    if (!/^https?:\/\//i.test(urlString)) {
      urlString = "http://" + urlString;
    }

    const urlObj = new URL(urlString);
    const { href, hostname, protocol, pathname, search } = urlObj;
    const host = hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1") {
        return {
          score: 0,
          reasons: ["Local development URL detected (not a phishing target)."],
          normalizedUrl: href
        };
      }

    if (TRUSTED_DOMAINS.some(d => host === d || host.endsWith("." + d))) {
      return {
        score: 0,
        reasons: ["This URL belongs to a well-known trusted domain."],
        normalizedUrl: href
      };
    }

    if (protocol !== "https:") {
      score += 2;
      reasons.push("The connection is not using HTTPS.");
    }

    if (href.length > 90) {
      score += href.length > 130 ? 4 : 2;
      reasons.push("The URL is unusually long.");
    }

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      score += 5;
      reasons.push("The URL uses a raw IP address.");
    }

    if (host.split(".").length - 1 >= 3) {
      score += 3;
      reasons.push("The domain has many subdomains.");
    }

    if (href.includes("@")) {
      score += 4;
      reasons.push("The URL contains '@'.");
    }
    
      
    if ((host.match(/-/g) || []).length >= 2) {
      score += 2;
      reasons.push("The domain contains multiple hyphens.");
    }

    const tld = host.match(/\.[a-z0-9-]+$/)?.[0];
    if (tld && SUSPICIOUS_TLDS.includes(tld)) {
      score += 3;
      reasons.push(`Suspicious top-level domain used (${tld}).`);
    }

    const combined = `${host} ${pathname} ${search}`;
    let keywordHits = 0;
    SUSPICIOUS_KEYWORDS.forEach(k => {
      if (combined.includes(k)) keywordHits++;
    });

    if (keywordHits > 0) score += 2;
    if (keywordHits >= 3) score += 2;

    if (KNOWN_BRANDS.some(b => host.endsWith(b) && host !== b)) {
      score += 4;
      reasons.push("The domain imitates a well-known brand.");
    }

    if (score === 0) {
      reasons.push("No strong phishing indicators were detected.");
    }

    score = Math.min(score, 10);
    return { score, reasons, normalizedUrl: href };
  }

  /* ======================
     RESULT RENDERING
     ====================== */
  function classifyScore(score) {
    if (score <= 3) return { level: "safe", label: "Likely Safe" };
    if (score <= 8) return { level: "warning", label: "Suspicious" };
    return { level: "danger", label: "Potential Phishing" };
  }

  function renderResult({ score, reasons, normalizedUrl }) {
    resultPanel.classList.remove("hidden", "invalid");
    resetBadge();
    reasonList.innerHTML = "";

    if (score === -1) {
      resultPanel.classList.add("invalid");
      riskScoreEl.textContent = "–";
      riskStatusEl.textContent = "Invalid website URL";
      riskBadge.textContent = "Invalid Input";
      riskBadge.classList.add("badge-invalid");
      reasons.forEach(r => {
        const li = document.createElement("li");
        li.textContent = r;
        reasonList.appendChild(li);
      });
      reportSection.classList.add("hidden");
      return;
    }

    const classification = classifyScore(score);
    riskScoreEl.textContent = score;
    riskStatusEl.textContent =
      `${classification.label} for: ${normalizedUrl}`;

    riskBadge.textContent = classification.label;
    riskBadge.classList.add(`badge-${classification.level}`);

    reasons.forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      reasonList.appendChild(li);
    });

    classification.level !== "safe"
      ? reportSection.classList.remove("hidden")
      : reportSection.classList.add("hidden");
  }

  function resetBadge() {
    riskBadge.className = "badge badge-neutral";
  }

  reportBtn.addEventListener("click", () => {
    alert("Thank you for reporting!\n\nReported URL:\n" + urlInput.value.trim());
  });

})();

/* Account dropdown */
document.addEventListener("DOMContentLoaded", () => {
  const accountBtn = document.getElementById("accountBtn");
  const accountMenu = document.getElementById("accountMenu");

  accountBtn.addEventListener("click", () => {
    accountMenu.classList.toggle("show");
  });

  document.addEventListener("click", (e) => {
    if (!e.target.closest(".account-wrapper")) {
      accountMenu.classList.remove("show");
    }
  });
});
