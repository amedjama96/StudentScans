import { useState } from "react";

type ScanStatus = "idle" | "scanning" | "complete";

const checks = ["HTTPS", "Security Headers", "DNS", "SPF", "DMARC"];

export default function App() {
  const [domain, setDomain] = useState("");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [progress, setProgress] = useState(0);

  function startScan() {
    const cleanedDomain = domain.trim();

    if (!cleanedDomain) {
      setMessage("Please enter a domain.");
      return;
    }

    setMessage("");
    setStatus("scanning");
    setProgress(0);

    [20, 40, 60, 80, 100].forEach((value, index) => {
      window.setTimeout(() => {
        setProgress(value);

        if (value === 100) {
          setStatus("complete");
        }
      }, (index + 1) * 450);
    });
  }

  function resetScan() {
    setStatus("idle");
    setProgress(0);
    setMessage("");
  }

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
          <button type="button" onClick={startScan} disabled={status === "scanning"}>
            {status === "scanning" ? "Scanning..." : "Start scan"}
          </button>
        </div>

        {message && <p className="error-message">{message}</p>}

        {status === "scanning" && (
          <section className="scan-panel" aria-live="polite">
            <div className="scan-heading">
              <h2>Scanning {domain.trim()}</h2>
              <span>{progress}%</span>
            </div>
            <div className="progress-track">
              <div className="progress-bar" style={{ width: `${progress}%` }} />
            </div>
            <p className="scan-step">
              {progress < 40 && "Checking connection..."}
              {progress >= 40 && progress < 60 && "Preparing HTTPS check..."}
              {progress >= 60 && progress < 80 && "Preparing DNS checks..."}
              {progress >= 80 && "Preparing results..."}
            </p>
          </section>
        )}

        {status === "complete" && (
          <section className="results-panel">
            <div className="results-heading">
              <div>
                <p className="section-label">Scan complete</p>
                <h2>{domain.trim()}</h2>
              </div>
              <button type="button" className="secondary-button" onClick={resetScan}>
                New scan
              </button>
            </div>

            <div className="check-list">
              {checks.map((check) => (
                <article className="check-card" key={check}>
                  <div>
                    <h3>{check}</h3>
                    <p>Security check will be connected in a later version.</p>
                  </div>
                  <span className="pending-status">Pending</span>
                </article>
              ))}
            </div>
          </section>
        )}
      </section>
    </main>
  );
}
