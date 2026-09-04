/**
 * TrustPulse AI - Reference Ingestion Server (Mock / Local Testing Only)
 *
 * NOTE: This is NOT the TrustPulse backend product. It is a lightweight local HTTP
 * endpoint to verify that @trustpulse/sdk packets, security headers, sequence numbers,
 * and feature payloads are received accurately.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = 8080;

const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-TrustPulse-Public-Key, X-TrustPulse-Session-Id, X-TrustPulse-SDK-Version");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // Handle telemetry ingestion endpoint
  if (req.url === "/v1/telemetry" && req.method === "POST") {
    const publicKey = req.headers["x-trustpulse-public-key"];
    const sessionId = req.headers["x-trustpulse-session-id"];
    const sdkVersion = req.headers["x-trustpulse-sdk-version"];

    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("end", () => {
      try {
        const batch = JSON.parse(body);
        console.log(`\n[TrustPulse Ingestion Mock] Received batch: ${batch.batchId} (${batch.packets?.length || 0} packets)`);
        console.log(`  Headers -> PublicKey: ${publicKey}, SessionId: ${sessionId}, SDKVersion: ${sdkVersion}`);

        if (batch.packets && batch.packets.length > 0) {
          batch.packets.forEach((p, idx) => {
            console.log(`  Packet #${idx + 1}: eventId=${p.eventId}, seq=${p.sequenceNumber}, type=${p.eventType}`);
            if (p.features.typing) {
              console.log(`    Typing Features: dwell=${p.features.typing.meanDwellTime}ms, flight=${p.features.typing.meanFlightTime}ms, speed=${p.features.typing.typingSpeed} keys/s`);
            }
            if (p.features.mouse) {
              console.log(`    Mouse Features: velocity=${p.features.mouse.meanVelocity}px/s, accel=${p.features.mouse.meanAcceleration}px/s², dist=${p.features.mouse.totalDistance}px`);
            }
            if (p.features.click) {
              console.log(`    Click Features: clicks=${p.features.click.clickCount}, doubleClicks=${p.features.click.doubleClickCount}`);
            }
          });
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "accepted", receivedPackets: batch.packets?.length || 0 }));
      } catch (err) {
        console.error("[TrustPulse Ingestion Mock] Error parsing payload:", err);
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON payload" }));
      }
    });
    return;
  }

  // Serve static files
  let filePath = path.join(__dirname, req.url === "/" ? "index.html" : req.url);
  
  // Serve dist files from sdk if requested
  if (req.url.startsWith("/sdk/")) {
    filePath = path.join(__dirname, "../sdk/dist", req.url.replace("/sdk/", ""));
  }

  // Check if file exists, or if appending .js resolves it
  if (!fs.existsSync(filePath) && fs.existsSync(`${filePath}.js`)) {
    filePath = `${filePath}.js`;
  }

  const ext = path.extname(filePath);
  const mimeTypes = {
    ".html": "text/html",
    ".js": "application/javascript",
    ".css": "text/css",
    ".json": "application/json",
  };

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("404 Not Found");
      return;
    }
    res.writeHead(200, { "Content-Type": mimeTypes[ext] || "application/octet-stream" });
    res.end(content);
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`  TrustPulse SDK Reference Integration Test Server`);
    console.log(`  Listening at: http://localhost:${PORT}`);
    console.log(`  Telemetry Ingestion: http://localhost:${PORT}/v1/telemetry`);
    console.log(`======================================================\n`);
  });
}

module.exports = server;
