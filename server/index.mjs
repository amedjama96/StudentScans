import express from "express";
import cors from "cors";
import tls from "tls";

const app = express();
app.use(cors());

const cleanDomain = (value = "") =>
  value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase();

function analyzeHeaders(headers) {
  const get = (name) => headers.get(name) || "";
  const csp = get("content-security-policy");
  const hsts = get("strict-transport-security");
  const xfo = get("x-frame-options");
  const xcto = get("x-content-type-options");

  const cspFindings = csp ? [
    csp.includes("'unsafe-inline'") ? "Allows 'unsafe-inline'." : "",
    csp.includes("'unsafe-eval'") ? "Allows 'unsafe-eval'." : "",
    !/(^|;)\s*frame-ancestors\b/i.test(csp) ? "No frame-ancestors directive detected." : "",
  ].filter(Boolean) : [];

  const maxAgeMatch = hsts.match(/max-age\s*=\s*(\d+)/i);
  const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : null;
  const hstsFindings = hsts ? [
    maxAge !== null && maxAge < 15552000 ? "HSTS max-age is shorter than 180 days." : "",
    !/includesubdomains/i.test(hsts) ? "includeSubDomains is not enabled." : "",
  ].filter(Boolean) : [];

  const result = [
    {name:"Content-Security-Policy", value:csp, findings:cspFindings},
    {name:"Strict-Transport-Security", value:hsts, findings:hstsFindings},
    {name:"X-Frame-Options", value:xfo, findings:xfo && !["DENY","SAMEORIGIN"].includes(xfo.trim().toUpperCase()) ? ["Unexpected X-Frame-Options value."] : []},
    {name:"X-Content-Type-Options", value:xcto, findings:xcto && xcto.trim().toLowerCase() !== "nosniff" ? ["Expected value: nosniff."] : []},
  ];

  return result.map(h => ({
    ...h,
    found: Boolean(h.value),
    rating: !h.value ? "Missing" : h.findings.length ? "Review" : "Good",
  }));
}

app.get("/api/headers", async (req,res) => {
  const domain = cleanDomain(String(req.query.domain || ""));
  if (!domain || !domain.includes(".")) return res.status(400).json({error:"Invalid domain"});
  try {
    const response = await fetch(`https://${domain}`, {redirect:"follow", signal:AbortSignal.timeout(8000)});
    res.json({headers: analyzeHeaders(response.headers)});
  } catch {
    res.status(502).json({error:"Could not inspect security headers"});
  }
});

app.get("/api/tls", (req,res) => {
  const domain = cleanDomain(String(req.query.domain || ""));
  if (!domain || !domain.includes(".")) return res.status(400).json({error:"Invalid domain"});

  const socket = tls.connect({host:domain,port:443,servername:domain,rejectUnauthorized:false,timeout:8000}, () => {
    try {
      const cert = socket.getPeerCertificate();
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      if (!cert?.valid_to) throw new Error();

      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.ceil((validTo.getTime()-Date.now())/86400000);
      const protocolRating = protocol === "TLSv1.3" ? "Strong" : protocol === "TLSv1.2" ? "Acceptable" : protocol ? "Outdated" : "Unknown";

      res.json({
        protocol, protocolRating,
        cipherName:cipher?.name || "Unknown",
        cipherVersion:cipher?.version || "Unknown",
        cipherStandardName:cipher?.standardName || "",
        subject:cert.subject?.CN || domain,
        issuer:cert.issuer?.O || cert.issuer?.CN || "Unknown issuer",
        validFrom:new Date(cert.valid_from).toISOString(),
        validTo:validTo.toISOString(),
        daysRemaining,
        authorized:socket.authorized,
        authorizationError:socket.authorizationError || ""
      });
      socket.end();
    } catch {
      socket.end();
      if (!res.headersSent) res.status(502).json({error:"Could not inspect TLS configuration"});
    }
  });

  socket.on("timeout",()=>{socket.destroy(); if(!res.headersSent)res.status(504).json({error:"TLS timeout"});});
  socket.on("error",()=>{if(!res.headersSent)res.status(502).json({error:"TLS connection failed"});});
});

app.get("/api/redirect", async (req,res) => {
  const domain = cleanDomain(String(req.query.domain || ""));
  if (!domain || !domain.includes(".")) return res.status(400).json({error:"Invalid domain"});
  try {
    const initial = await fetch(`http://${domain}`, {redirect:"manual",signal:AbortSignal.timeout(8000)});
    const location = initial.headers.get("location") || "";
    const redirected = [301,302,303,307,308].includes(initial.status);
    let finalUrl=`http://${domain}`, finalStatus=initial.status, usesHttps=false;

    if (redirected && location) {
      const absolute = new URL(location, `http://${domain}`).toString();
      const finalResponse = await fetch(absolute,{redirect:"follow",signal:AbortSignal.timeout(8000)});
      finalUrl=finalResponse.url || absolute;
      finalStatus=finalResponse.status;
      usesHttps=finalUrl.startsWith("https://");
    }
    res.json({initialStatus:initial.status,redirected,finalUrl,finalStatus,usesHttps});
  } catch {
    res.status(502).json({error:"Could not check redirect"});
  }
});

app.listen(3001,()=>console.log("StudentScans backend running on http://localhost:3001"));
