import { useState } from "react";

type ScanStatus = "idle" | "scanning" | "complete";
type CheckState = "pending" | "checking" | "success" | "warning";

type DnsResult = {
  ipv4: string[];
  mailServers: string[];
};

function normalizeDomain(value: string): string {
  return value
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .toLowerCase();
}

async function checkHttps(domain: string): Promise<CheckState> {
  try {
    await fetch(`https://${domain}`, {
      method: "GET",
      mode: "no-cors",
      cache: "no-store",
    });
    return "success";
  } catch {
    return "warning";
  }
}

async function queryDns(domain: string, type: "A" | "MX") {
  const response = await fetch(
    `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
  );

  if (!response.ok) {
    throw new Error("DNS request failed");
  }

  return response.json();
}

async function checkDns(domain: string): Promise<DnsResult> {
  const [aData, mxData] = await Promise.all([
    queryDns(domain, "A"),
    queryDns(domain, "MX"),
  ]);

  const ipv4 =
    aData.Answer?.filter((answer: { type: number }) => answer.type === 1).map(
      (answer: { data: string }) => answer.data,
    ) ?? [];

  const mailServers =
    mxData.Answer?.filter((answer: { type: number }) => answer.type === 15).map(
      (answer: { data: string }) => answer.data,
    ) ?? [];

  return { ipv4, mailServers };
}

export default function App() {
  const [domain, setDomain] = useState("");
  const [scannedDomain, setScannedDomain] = useState("");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [progress, setProgress] = useState(0);

  const [httpsStatus, setHttpsStatus] = useState<CheckState>("pending");
  const [dnsStatus, setDnsStatus] = useState<CheckState>("pending");
  const [dnsResult, setDnsResult] = useState<DnsResult>({ ipv4: [], mailServers: [] });

  async function startScan() {
    const cleanedDomain = normalizeDomain(domain);

    if (!cleanedDomain || !cleanedDomain.includes(".")) {
      setMessage("Please enter a valid domain, such as example.com.");
      return;
    }

    setMessage("");
    setScannedDomain(cleanedDomain);
    setStatus("scanning");
    setProgress(10);
    setHttpsStatus("checking");
    setDnsStatus("checking");
    setDnsResult({ ipv4: [], mailServers: [] });

    const httpsPromise = checkHttps(cleanedDomain);
    setProgress(30);

    const dnsPromise = checkDns(cleanedDomain)
      .then((result) => {
        setDnsResult(result);
        setDnsStatus(result.ipv4.length > 0 ? "success" : "warning");
      })
      .catch(() => setDnsStatus("warning"));

    setProgress(55);

    const httpsResult = await httpsPromise;
    setHttpsStatus(httpsResult);
    setProgress(75);

    await dnsPromise;
    setProgress(90);

    window.setTimeout(() => {
      setProgress(100);
      setStatus("complete");
    }, 450);
  }

  function resetScan() {
    setStatus("idle");
    setProgress(0);
    setMessage("");
    setHttpsStatus("pending");
    setDnsStatus("pending");
    setDnsResult({ ipv4: [], mailServers: [] });
    setScannedDomain("");
  }

  function statusLabel(state: CheckState) {
    if (state === "success") return "Found";
    if (state === "warning") return "Could not confirm";
    if (state === "checking") return "Checking";
    return "Pending";
  }

  const checks = [
    {
      name: "HTTPS",
      description:
        httpsStatus === "success"
          ? "The website responded to a basic HTTPS connection attempt."
          : httpsStatus === "warning"
            ? "The browser could not confirm a basic HTTPS connection."
            : "Checking whether the website can be reached over HTTPS.",
      label:
        httpsStatus === "success"
          ? "Reachable"
          : httpsStatus === "warning"
            ? "Could not confirm"
            : statusLabel(httpsStatus),
      className: httpsStatus,
    },
    {
      name: "DNS",
      description:
        dnsStatus === "success"
          ? `${dnsResult.ipv4.length} IPv4 record(s) and ${dnsResult.mailServers.length} mail server record(s) found.`
          : dnsStatus === "warning"
            ? "StudentScans could not confirm public A-records for this domain."
            : "Looking up public DNS records.",
      label: statusLabel(dnsStatus),
      className: dnsStatus,
    },
    {
      name: "Security Headers",
      description: "This check will be connected in a later version.",
      label: "Pending",
      className: "pending",
    },
    {
      name: "SPF",
      description: "This check will be connected in a later version.",
      label: "Pending",
      className: "pending",
    },
    {
      name: "DMARC",
      description: "This check will be connected in a later version.",
      label: "Pending",
      className: "pending",
    },
  ];

  return (
    <main className="page">
      <section className="hero">
        <span className="badge">Beta</span>
        <h1>StudentScans</h1>
        <p className="lead">Enter a website to run a basic external security overview.</p>

        <div className="scan-form">
          <label htmlFor="domain">Website domain</label>
          <input
            id="domain"
            className="domain-input"
            placeholder="example.com"
            value={domain}
            disabled={status === "scanning"}
            onChange={(event) => setDomain(event.target.value)}
          />
          <button
            type="button"
            onClick={() => void startScan()}
            disabled={status === "scanning"}
          >
            {status === "scanning" ? "Scanning..." : "Start scan"}
          </button>
        </div>

        {message && <p className="error-message">{message}</p>}

        {status === "scanning" && (
          <section className="scan-panel">
            <div className="scan-heading">
              <h2>Scanning {scannedDomain}</h2>
              <span>{progress}%</span>
            </div>
            <div className="progress-track">
              <div className="progress-bar" style={{ width: `${progress}%` }} />
            </div>
            <p className="scan-step">
              {progress < 30 && "Starting scan..."}
              {progress >= 30 && progress < 55 && "Checking HTTPS..."}
              {progress >= 55 && progress < 90 && "Looking up DNS records..."}
              {progress >= 90 && "Preparing results..."}
            </p>
          </section>
        )}

        {status === "complete" && (
          <section className="results-panel">
            <div className="results-heading">
              <div>
                <p className="section-label">Scan complete</p>
                <h2>{scannedDomain}</h2>
              </div>
              <button type="button" className="secondary-button" onClick={resetScan}>
                New scan
              </button>
            </div>

            <p className="notice">
              StudentScans currently performs basic HTTPS reachability and public DNS lookups.
            </p>

            <div className="check-list">
              {checks.map((check) => (
                <article className="check-card" key={check.name}>
                  <div>
                    <h3>{check.name}</h3>
                    <p>{check.description}</p>

                    {check.name === "DNS" && dnsResult.ipv4.length > 0 && (
                      <div className="dns-details">
                        <p><strong>IPv4:</strong> {dnsResult.ipv4.join(", ")}</p>
                        {dnsResult.mailServers.length > 0 && (
                          <p><strong>MX:</strong> {dnsResult.mailServers.slice(0, 3).join(", ")}</p>
                        )}
                      </div>
                    )}
                  </div>

                  <span className={`check-status ${check.className}`}>
                    {check.label}
                  </span>
                </article>
              ))}
            </div>
          </section>
        )}
      </section>
    </main>
  );
}
