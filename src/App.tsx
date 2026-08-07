import { useState } from "react";

type ScanStatus = "idle" | "scanning" | "complete";
type HttpsStatus = "pending" | "checking" | "reachable" | "unconfirmed";

function normalizeDomain(value: string): string {
  return value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase();
}

async function checkHttps(domain: string): Promise<HttpsStatus> {
  try {
    await fetch(`https://${domain}`, {
      method: "GET",
      mode: "no-cors",
      cache: "no-store",
    });
    return "reachable";
  } catch {
    return "unconfirmed";
  }
}

export default function App() {
  const [domain, setDomain] = useState("");
  const [scannedDomain, setScannedDomain] = useState("");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [progress, setProgress] = useState(0);
  const [httpsStatus, setHttpsStatus] = useState<HttpsStatus>("pending");

  async function startScan() {
    const cleanedDomain = normalizeDomain(domain);

    if (!cleanedDomain || !cleanedDomain.includes(".")) {
      setMessage("Please enter a valid domain, such as example.com.");
      return;
    }

    setMessage("");
    setScannedDomain(cleanedDomain);
    setStatus("scanning");
    setProgress(15);
    setHttpsStatus("checking");

    window.setTimeout(() => setProgress(40), 350);

    const result = await checkHttps(cleanedDomain);

    setProgress(75);
    setHttpsStatus(result);

    window.setTimeout(() => {
      setProgress(100);
      setStatus("complete");
    }, 500);
  }

  function resetScan() {
    setStatus("idle");
    setProgress(0);
    setMessage("");
    setHttpsStatus("pending");
    setScannedDomain("");
  }

  const httpsLabel =
    httpsStatus === "reachable"
      ? "Reachable"
      : httpsStatus === "unconfirmed"
        ? "Could not confirm"
        : httpsStatus === "checking"
          ? "Checking"
          : "Pending";

  const checks = [
    {
      name: "HTTPS",
      description:
        httpsStatus === "reachable"
          ? "The website responded to a basic HTTPS connection attempt."
          : httpsStatus === "unconfirmed"
            ? "The browser could not confirm a basic HTTPS connection."
            : "Checking whether the website can be reached over HTTPS.",
      status: httpsLabel,
    },
    {
      name: "Security Headers",
      description: "This check will be connected in a later version.",
      status: "Pending",
    },
    {
      name: "DNS",
      description: "This check will be connected in a later version.",
      status: "Pending",
    },
    {
      name: "SPF",
      description: "This check will be connected in a later version.",
      status: "Pending",
    },
    {
      name: "DMARC",
      description: "This check will be connected in a later version.",
      status: "Pending",
    },
  ];

  return (
    <main className="page">
      <section className="hero">
        <span className="badge">Beta</span>
        <h1>StudentScans</h1>
        <p className="lead">
          Enter a website to prepare a basic external security overview.
        </p>

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
              {progress < 40 && "Starting scan..."}
              {progress >= 40 && progress < 75 && "Checking HTTPS reachability..."}
              {progress >= 75 && "Preparing results..."}
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
              StudentScans currently performs a basic HTTPS reachability check.
              It does not inspect certificates, cipher suites, or vulnerabilities.
            </p>

            <div className="check-list">
              {checks.map((check) => (
                <article className="check-card" key={check.name}>
                  <div>
                    <h3>{check.name}</h3>
                    <p>{check.description}</p>
                  </div>
                  <span className={`check-status ${check.status.toLowerCase().replaceAll(" ", "-")}`}>
                    {check.status}
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
