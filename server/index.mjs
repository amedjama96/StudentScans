import express from "express";
import cors from "cors";

const app = express();
app.use(cors());

function cleanDomain(value = "") {
  return value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase();
}

app.get("/api/headers", async (req, res) => {
  const domain = cleanDomain(String(req.query.domain || ""));
  if (!domain || !domain.includes(".")) return res.status(400).json({error:"Invalid domain"});

  try {
    const response = await fetch(`https://${domain}`, {
      redirect: "follow",
      signal: AbortSignal.timeout(8000)
    });

    const wanted = [
      ["Content-Security-Policy","content-security-policy"],
      ["Strict-Transport-Security","strict-transport-security"],
      ["X-Frame-Options","x-frame-options"],
      ["X-Content-Type-Options","x-content-type-options"]
    ];

    const headers = wanted.map(([name,key]) => ({
      name,
      found: response.headers.has(key),
      value: response.headers.get(key) || ""
    }));

    res.json({domain, status:response.status, finalUrl:response.url, headers});
  } catch {
    res.status(502).json({error:"Could not fetch target website"});
  }
});

app.listen(3001, () => console.log("StudentScans backend running on http://localhost:3001"));
