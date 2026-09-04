/**
 * Customer Web Application - TrustPulse SDK Integration Script
 */

import { TrustPulse } from "/sdk/index.js";

// DOM Elements
const logTerminal = document.getElementById("telemetryLog");
const sdkStatusBadge = document.getElementById("sdkStatusBadge");
const packetCountBadge = document.getElementById("packetCountBadge");
const activeSessionIdEl = document.getElementById("activeSessionId");
const activeInstanceIdEl = document.getElementById("activeInstanceId");

const btnTransfer = document.getElementById("btnTransfer");
const btnFlush = document.getElementById("btnFlush");
const btnToggle = document.getElementById("btnToggle");
const btnRotate = document.getElementById("btnRotate");

let dispatchedBatches = 0;
let currentSessionId = "sess_live_enterprise_8812";

function log(message, type = "info") {
  const line = document.createElement("div");
  line.className = "log-line";
  const time = new Date().toLocaleTimeString();
  line.innerHTML = `<span class="log-time">[${time}]</span> ${message}`;
  logTerminal.appendChild(line);
  logTerminal.scrollTop = logTerminal.scrollHeight;
}

// 1. Initialize TrustPulse SDK
log("Instantiating TrustPulse SDK client...");

const trustpulse = new TrustPulse({
  apiUrl: "http://localhost:8080", // Local mock ingestion endpoint
  publicKey: "pk_live_corporate_bank_us_east",
  sessionId: currentSessionId,
  telemetryIntervalMs: 3000,
  debug: true,
  privacyMode: "standard",
});

// 2. Start continuous telemetry collection
trustpulse.start();

sdkStatusBadge.textContent = `SDK: ${trustpulse.getStatus().toUpperCase()}`;
activeSessionIdEl.textContent = trustpulse.getSessionId();
activeInstanceIdEl.textContent = trustpulse.getSdkInstanceId();

log(`SDK running (v${TrustPulse.version}) with instance ID: ${trustpulse.getSdkInstanceId()}`);
log("Continuous session behavioral observation active.");

// Hook fetch calls to inspect outgoing telemetry in the terminal
const originalFetch = window.fetch;
window.fetch = async function (url, options) {
  if (typeof url === "string" && url.includes("/v1/telemetry") && options && options.body) {
    try {
      const batch = JSON.parse(options.body);
      dispatchedBatches += 1;
      packetCountBadge.textContent = `Dispatched: ${dispatchedBatches} batches`;

      log(`📡 Telemetry batch sent (ID: ${batch.batchId.slice(0, 8)}..., ${batch.packets.length} packets)`);
      batch.packets.forEach((p) => {
        if (p.features.typing) {
          log(`  ⌨️ Typing features: dwell=${p.features.typing.meanDwellTime}ms, flight=${p.features.typing.meanFlightTime}ms, speed=${p.features.typing.typingSpeed} k/s`);
        }
        if (p.features.mouse) {
          log(`  🖱️ Mouse kinematics: velocity=${p.features.mouse.meanVelocity}px/s, accel=${p.features.mouse.meanAcceleration}px/s²`);
        }
        if (p.features.click) {
          log(`  👆 Click dynamics: count=${p.features.click.clickCount}, doubleClick=${p.features.click.doubleClickCount}`);
        }
      });
    } catch {
      // Ignore
    }
  }
  return originalFetch.apply(this, arguments);
};

// UI Interactions
btnFlush.addEventListener("click", async () => {
  log("Manual flush triggered by application...");
  await trustpulse.flush();
});

btnToggle.addEventListener("click", () => {
  if (trustpulse.getStatus() === "running") {
    trustpulse.pause();
    btnToggle.textContent = "Resume SDK";
    sdkStatusBadge.textContent = "SDK: PAUSED";
    log("SDK paused by host application.");
  } else if (trustpulse.getStatus() === "paused") {
    trustpulse.resume();
    btnToggle.textContent = "Pause SDK";
    sdkStatusBadge.textContent = "SDK: RUNNING";
    log("SDK resumed by host application.");
  }
});

btnRotate.addEventListener("click", () => {
  const newSessionId = `sess_live_rotated_${Math.floor(Math.random() * 9000 + 1000)}`;
  trustpulse.updateSession(newSessionId);
  currentSessionId = newSessionId;
  activeSessionIdEl.textContent = newSessionId;
  log(`Session rotated to: ${newSessionId}`);
});

btnTransfer.addEventListener("click", async () => {
  log("Simulating high-value transaction action...");
  log("Note: In production Phase 2, this will query /v1/risk/evaluate asynchronously.");
  await trustpulse.flush();
});
