const urlInput = document.getElementById("urlInput");
const loading = document.getElementById("loading");
const resultCard = document.getElementById("resultCard");
const scanBtn = document.getElementById("scanBtn");

urlInput.addEventListener("keydown", function (event) {
  if (event.key === "Enter") {
    event.preventDefault();
    scanURL();
  }
});

async function scanURL() {
  const url = urlInput.value.trim();

  if (!url) {
    alert("Please enter a URL.");
    return;
  }

  loading.classList.remove("hidden");
  resultCard.classList.add("hidden");
  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning...";

  try {
    const response = await fetch("/scan-api", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: url })
    });

    const data = await response.json();

    loading.classList.add("hidden");
    scanBtn.disabled = false;
    scanBtn.textContent = "Scan Now";

    if (!response.ok) {
      alert(data.error || "Scan failed");
      return;
    }

    showResult(url, data);
  } catch (error) {
    loading.classList.add("hidden");
    scanBtn.disabled = false;
    scanBtn.textContent = "Scan Now";
    alert("Server connection failed");
    console.error(error);
  }
}

function showResult(url, data) {
  resultCard.classList.remove("hidden");

  const score = Number(data.score) || 0;
  const verdict = (data.verdict || "safe").toLowerCase();
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];

  document.getElementById("displayURL").textContent = url;
  document.getElementById("riskScore").textContent = `${score}/10`;
  document.getElementById("verdict").textContent = verdict;
  document.getElementById("meterPercent").textContent = `${score * 10}%`;

  const meterBar = document.getElementById("meterBar");
  const verdictBadge = document.getElementById("verdictBadge");
  const issuesList = document.getElementById("issuesList");

  meterBar.style.width = `${score * 10}%`;

  if (verdict === "safe") {
    meterBar.style.background = "var(--safe)";
    verdictBadge.textContent = "SAFE";
    verdictBadge.style.background = "rgba(34, 197, 94, 0.14)";
    verdictBadge.style.color = "#86efac";
    verdictBadge.style.border = "1px solid rgba(34, 197, 94, 0.2)";
  } else if (verdict === "suspicious") {
    meterBar.style.background = "var(--warn)";
    verdictBadge.textContent = "SUSPICIOUS";
    verdictBadge.style.background = "rgba(245, 158, 11, 0.14)";
    verdictBadge.style.color = "#fcd34d";
    verdictBadge.style.border = "1px solid rgba(245, 158, 11, 0.2)";
  } else {
    meterBar.style.background = "var(--danger)";
    verdictBadge.textContent = "MALICIOUS";
    verdictBadge.style.background = "rgba(239, 68, 68, 0.14)";
    verdictBadge.style.color = "#fca5a5";
    verdictBadge.style.border = "1px solid rgba(239, 68, 68, 0.2)";
  }

  issuesList.innerHTML = "";

  if (reasons.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No major issues found";
    issuesList.appendChild(li);
  } else {
    reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      issuesList.appendChild(li);
    });
  }
}

document.addEventListener("DOMContentLoaded", function () {
  const hamburger = document.getElementById("hamburger");
  const navMenu = document.getElementById("navMenu");

  if (!hamburger || !navMenu) {
    console.log("Hamburger or navMenu not found");
    return;
  }

  hamburger.addEventListener("click", function () {
    navMenu.classList.toggle("open");
    hamburger.classList.toggle("open");
  });

  // Close menu when link clicked
  document.querySelectorAll("#navMenu a").forEach(link => {
    link.addEventListener("click", () => {
      navMenu.classList.remove("open");
      hamburger.classList.remove("open");
    });
  });
});