import express from "express";
import cors from "cors";
import tls from "tls";

const app = express();
app.use(cors());

function cleanDomain(value = "") {
  return value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase();
}

app.get("/api/headers", async (req, res) => {
  const domain = cleanDomain(String(req.query.domain || ""));
  if (!domain || !domain.includes(".")) return res.status(400).json({ error: "Invalid domain" });

  try {
    const response = await fetch(`https://${domain}`, {
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
    });

    const wanted = [
      ["Content-Security-Policy", "content-security-policy"],
      ["Strict-Transport-Security", "strict-transport-security"],
      ["X-Frame-Options", "x-frame-options"],
      ["X-Content-Type-Options", "x-content-type-options"],
    ];

    res.json({
      headers: wanted.map(([name, key]) => ({
        name,
        found: response.headers.has(key),
        value: response.headers.get(key) || "",
      })),
    });
  } catch {
    res.status(502).json({ error: "Could not fetch target website" });
  }
});

app.get("/api/tls", (req, res) => {
  const domain = cleanDomain(String(req.query.domain || ""));
  if (!domain || !domain.includes(".")) return res.status(400).json({ error: "Invalid domain" });

  const socket = tls.connect({
    host: domain,
    port: 443,
    servername: domain,
    rejectUnauthorized: false,
    timeout: 8000,
  }, () => {
    try {
      const cert = socket.getPeerCertificate();
      if (!cert || !cert.valid_to) throw new Error("No certificate");

      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.ceil((validTo.getTime() - Date.now()) / 86400000);

      const result = {
        protocol: socket.getProtocol(),
        subject: cert.subject?.CN || domain,
        issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown issuer",
        validFrom: new Date(cert.valid_from).toISOString(),
        validTo: validTo.toISOString(),
        daysRemaining,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError || "",
      };

      socket.end();
      res.json(result);
    } catch {
      socket.end();
      res.status(502).json({ error: "Could not inspect TLS certificate" });
    }
  });

  socket.on("timeout", () => {
    socket.destroy();
    if (!res.headersSent) res.status(504).json({ error: "TLS connection timed out" });
  });

  socket.on("error", () => {
    if (!res.headersSent) res.status(502).json({ error: "TLS connection failed" });
  });
});

app.get("/api/redirect", async (req, res) => {
  const domain = cleanDomain(String(req.query.domain || ""));
  if (!domain || !domain.includes(".")) return res.status(400).json({ error: "Invalid domain" });

  try {
    const initial = await fetch(`http://${domain}`, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(8000),
    });

    const location = initial.headers.get("location") || "";
    const redirected = [301, 302, 303, 307, 308].includes(initial.status);

    let finalUrl = `http://${domain}`;
    let finalStatus = initial.status;
    let usesHttps = false;

    if (redirected && location) {
      const absolute = new URL(location, `http://${domain}`).toString();

      const finalResponse = await fetch(absolute, {
        method: "GET",
        redirect: "follow",
        signal: AbortSignal.timeout(8000),
      });

      finalUrl = finalResponse.url || absolute;
      finalStatus = finalResponse.status;
      usesHttps = finalUrl.startsWith("https://");
    } else {
      usesHttps = finalUrl.startsWith("https://");
    }

    res.json({
      domain,
      initialStatus: initial.status,
      redirected,
      location,
      finalUrl,
      finalStatus,
      usesHttps,
    });
  } catch {
    res.status(502).json({ error: "Could not check HTTP redirect" });
  }
});

app.listen(3001, () => console.log("StudentScans backend running on http://localhost:3001"));
