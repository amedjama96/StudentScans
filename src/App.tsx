import { useMemo, useState } from "react";

type HeaderResult = { name: string; found: boolean; value: string };

function cleanDomain(value: string) {
  return value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase();
}

async function dnsQuery(domain: string, type: string) {
  const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
  if (!response.ok) throw new Error("DNS lookup failed");
  return response.json();
}

function riskLabel(score: number) {
  if (score >= 80) return "Low";
  if (score >= 50) return "Moderate";
  return "Elevated";
}

function scoreClass(score: number) {
  if (score >= 80) return "score-good";
  if (score >= 50) return "score-medium";
  return "score-low";
}

export default function App() {
  const [domain, setDomain] = useState("");
  const [target, setTarget] = useState("");
  const [message, setMessage] = useState("");
  const [scanning, setScanning] = useState(false);
  const [complete, setComplete] = useState(false);
  const [ips, setIps] = useState<string[]>([]);
  const [spf, setSpf] = useState("");
  const [dmarc, setDmarc] = useState("");
  const [policy, setPolicy] = useState("");
  const [headers, setHeaders] = useState<HeaderResult[]>([]);
  const [backendOk, setBackendOk] = useState(true);
  const [scanTime, setScanTime] = useState("");

  async function scan() {
    const cleaned = cleanDomain(domain);

    if (!cleaned || !cleaned.includes(".")) {
      setMessage("Please enter a valid domain, such as example.com.");
      return;
    }

    setMessage("");
    setTarget(cleaned);
    setScanning(true);
    setComplete(false);
    setHeaders([]);
    setBackendOk(true);

    try {
      const [aData, txtData, dmarcData] = await Promise.all([
        dnsQuery(cleaned, "A"),
        dnsQuery(cleaned, "TXT"),
        dnsQuery(`_dmarc.${cleaned}`, "TXT"),
      ]);

      const foundIps = (aData.Answer ?? [])
        .filter((item: { type: number }) => item.type === 1)
        .map((item: { data: string }) => item.data);

      setIps(foundIps);

      const txtRecords: string[] = (txtData.Answer ?? [])
        .filter((item: { type: number }) => item.type === 16)
        .map((item: { data: string }) => item.data.replace(/^"|"$/g, ""));

      setSpf(txtRecords.find((record) => record.toLowerCase().startsWith("v=spf1")) ?? "");

      const dmarcRecords: string[] = (dmarcData.Answer ?? [])
        .filter((item: { type: number }) => item.type === 16)
        .map((item: { data: string }) => item.data.replace(/^"|"$/g, ""));

      const dmarcRecord = dmarcRecords.find((record) => record.toLowerCase().startsWith("v=dmarc1")) ?? "";
      setDmarc(dmarcRecord);
      setPolicy(dmarcRecord.match(/(?:^|;)\s*p=([^;]+)/i)?.[1]?.trim().toLowerCase() ?? "");
    } catch {
      setIps([]);
      setSpf("");
      setDmarc("");
      setPolicy("");
    }

    try {
      const response = await fetch(`http://localhost:3001/api/headers?domain=${encodeURIComponent(cleaned)}`);
      if (!response.ok) throw new Error("Backend unavailable");
      const data = await response.json();
      setHeaders(data.headers);
    } catch {
      setBackendOk(false);
    }

    setScanTime(new Intl.DateTimeFormat("en-GB", {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(new Date()));

    setScanning(false);
    setComplete(true);
  }

  const foundHeaders = headers.filter((header) => header.found).length;
  const headerPoints = backendOk && headers.length ? Math.round((foundHeaders / headers.length) * 40) : 0;
  const dnsPoints = ips.length ? 15 : 0;
  const spfPoints = spf ? 15 : 0;
  const dmarcPoints = dmarc ? (policy === "reject" ? 30 : policy === "quarantine" ? 25 : 20) : 0;
  const score = Math.min(100, dnsPoints + spfPoints + dmarcPoints + headerPoints);

  const recommendations = useMemo(() => {
    const items: string[] = [];
    if (!spf) items.push("Add an SPF record to define which mail servers may send email for this domain.");
    if (!dmarc) items.push("Add a DMARC record to improve protection against email spoofing.");
    else if (policy === "none") items.push("DMARC is monitoring only. Consider moving toward quarantine or reject after reviewing reports.");

    if (backendOk) {
      headers.filter((header) => !header.found).forEach((header) => {
        if (header.name === "Content-Security-Policy") items.push("Consider adding Content-Security-Policy to reduce the impact of content injection attacks.");
        if (header.name === "Strict-Transport-Security") items.push("Consider enabling HSTS so browsers use HTTPS for future connections.");
        if (header.name === "X-Frame-Options") items.push("Consider clickjacking protection with X-Frame-Options or CSP frame-ancestors.");
        if (header.name === "X-Content-Type-Options") items.push("Consider adding X-Content-Type-Options: nosniff.");
      });
    }
    return items;
  }, [spf, dmarc, policy, backendOk, headers]);

  const completedChecks = [
    ips.length > 0,
    Boolean(spf),
    Boolean(dmarc),
    backendOk && headers.length > 0,
  ].filter(Boolean).length;

  return (
    <main>
      <section className="hero">
        <div className="brand-row">
          <span className="badge">Beta</span>
          <span className="version">v0.12</span>
        </div>

        <h1>StudentScans</h1>
        <p className="lead">
          Basic external security checks with a simple score and practical recommendations.
        </p>

        <div className="form">
          <label htmlFor="domain">Website domain</label>
          <input
            id="domain"
            placeholder="example.com"
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            disabled={scanning}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !scanning) void scan();
            }}
          />
          <button onClick={() => void scan()} disabled={scanning}>
            {scanning ? "Scanning..." : "Start scan"}
          </button>
        </div>

        {message && <p className="error">{message}</p>}

        {scanning && (
          <section className="panel loading-panel">
            <div className="loader" />
            <div>
              <h2>Scanning {target}</h2>
              <p>Checking DNS, email security and HTTP response headers.</p>
            </div>
          </section>
        )}

        {complete && (
          <section className="panel">
            <div className="result-heading">
              <div>
                <p className="eyebrow">SCAN COMPLETE</p>
                <h2>{target}</h2>
                <p className="scan-time">{scanTime}</p>
              </div>

              <div className={`score ${scoreClass(score)}`}>
                <b>{score}</b>
                <span>/100</span>
                <small>Security score</small>
              </div>
            </div>

            <div className="summary-grid">
              <div className="summary-card">
                <span>Risk level</span>
                <strong className={`risk ${scoreClass(score)}`}>{riskLabel(score)}</strong>
              </div>
              <div className="summary-card">
                <span>Checks confirmed</span>
                <strong>{completedChecks}/4</strong>
              </div>
              <div className="summary-card">
                <span>Recommendations</span>
                <strong>{recommendations.length}</strong>
              </div>
            </div>

            <div className="notice">
              This educational score only reflects the checks shown below. It is not a vulnerability assessment and does not prove that a website is secure.
            </div>

            <section className="score-breakdown">
              <div className="section-title">
                <div>
                  <p className="eyebrow">SCORE BREAKDOWN</p>
                  <h2>How the score was calculated</h2>
                </div>
                <strong>{score}/100</strong>
              </div>

              <div className="breakdown-list">
                <div><span>DNS</span><strong>{dnsPoints}/15</strong></div>
                <div><span>SPF</span><strong>{spfPoints}/15</strong></div>
                <div><span>DMARC</span><strong>{dmarcPoints}/30</strong></div>
                <div><span>Security Headers</span><strong>{headerPoints}/40</strong></div>
              </div>
            </section>

            <div className="cards">
              <article>
                <div>
                  <h3>DNS</h3>
                  <p>{ips.length ? `${ips.length} IPv4 record(s) found.` : "No IPv4 records confirmed."}</p>
                </div>
                <span className={ips.length ? "ok" : "fail"}>{ips.length ? "Found" : "Not found"}</span>
              </article>

              <article>
                <div>
                  <h3>SPF</h3>
                  <p>{spf ? "SPF policy found." : "No SPF policy found."}</p>
                </div>
                <span className={spf ? "ok" : "fail"}>{spf ? "Found" : "Not found"}</span>
              </article>

              <article>
                <div>
                  <h3>DMARC</h3>
                  <p>{dmarc ? `DMARC policy: ${policy || "not specified"}.` : "No DMARC policy found."}</p>
                </div>
                <span className={dmarc ? "ok" : "fail"}>{dmarc ? "Found" : "Not found"}</span>
              </article>

              <article>
                <div>
                  <h3>Security Headers</h3>
                  <p>{backendOk ? `${foundHeaders} of ${headers.length} checked headers were found.` : "Backend unavailable."}</p>
                  {headers.length > 0 && (
                    <div className="details">
                      {headers.map((header) => (
                        <p key={header.name}><b>{header.found ? "✓" : "✕"} {header.name}</b></p>
                      ))}
                    </div>
                  )}
                </div>
                <span className={backendOk ? "ok" : "fail"}>{backendOk ? "Inspected" : "Offline"}</span>
              </article>
            </div>

            <section className="recommend">
              <div className="section-title">
                <div>
                  <p className="eyebrow">NEXT STEPS</p>
                  <h2>Recommendations</h2>
                </div>
                <strong>{recommendations.length}</strong>
              </div>

              {recommendations.length ? (
                <div className="rec-list">
                  {recommendations.map((recommendation, index) => (
                    <div className="rec" key={recommendation}>
                      <b>{index + 1}</b>
                      <p>{recommendation}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="all-good">No recommendations generated from the current basic checks.</p>
              )}
            </section>
          </section>
        )}
      </section>
    </main>
  );
}
