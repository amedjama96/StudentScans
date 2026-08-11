import { useState } from "react";

type State = "pending" | "checking" | "success" | "warning";

function cleanDomain(value: string) {
  return value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase();
}

async function dnsQuery(domain: string, type: "A" | "MX" | "TXT") {
  const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
  if (!response.ok) throw new Error("DNS lookup failed");
  return response.json();
}

async function httpsCheck(domain: string): Promise<State> {
  try {
    await fetch(`https://${domain}`, { mode: "no-cors", cache: "no-store" });
    return "success";
  } catch {
    return "warning";
  }
}

export default function App() {
  const [domain,setDomain]=useState("");
  const [target,setTarget]=useState("");
  const [message,setMessage]=useState("");
  const [scanning,setScanning]=useState(false);
  const [complete,setComplete]=useState(false);
  const [progress,setProgress]=useState(0);

  const [https,setHttps]=useState<State>("pending");
  const [dns,setDns]=useState<State>("pending");
  const [spf,setSpf]=useState<State>("pending");
  const [dmarc,setDmarc]=useState<State>("pending");

  const [ips,setIps]=useState<string[]>([]);
  const [mx,setMx]=useState<string[]>([]);
  const [spfRecord,setSpfRecord]=useState("");
  const [dmarcRecord,setDmarcRecord]=useState("");
  const [dmarcPolicy,setDmarcPolicy]=useState("");

  async function startScan() {
    const d=cleanDomain(domain);
    if(!d || !d.includes(".")){
      setMessage("Please enter a valid domain, such as example.com.");
      return;
    }

    setMessage(""); setTarget(d); setScanning(true); setComplete(false); setProgress(10);
    setHttps("checking"); setDns("checking"); setSpf("checking"); setDmarc("checking");
    setIps([]); setMx([]); setSpfRecord(""); setDmarcRecord(""); setDmarcPolicy("");

    const hp=httpsCheck(d);
    setProgress(20);

    try {
      const [aData,mxData,txtData,dmarcData]=await Promise.all([
        dnsQuery(d,"A"),
        dnsQuery(d,"MX"),
        dnsQuery(d,"TXT"),
        dnsQuery(`_dmarc.${d}`,"TXT")
      ]);

      const foundIps=(aData.Answer ?? []).filter((x:{type:number})=>x.type===1).map((x:{data:string})=>x.data);
      const foundMx=(mxData.Answer ?? []).filter((x:{type:number})=>x.type===15).map((x:{data:string})=>x.data);
      setIps(foundIps); setMx(foundMx); setDns(foundIps.length ? "success" : "warning");
      setProgress(50);

      const txtRecords:string[]=(txtData.Answer ?? []).filter((x:{type:number})=>x.type===16).map((x:{data:string})=>x.data.replace(/^"|"$/g,""));
      const spfFound=txtRecords.find(x=>x.toLowerCase().startsWith("v=spf1")) ?? "";
      setSpfRecord(spfFound); setSpf(spfFound ? "success" : "warning");
      setProgress(70);

      const dmarcRecords:string[]=(dmarcData.Answer ?? []).filter((x:{type:number})=>x.type===16).map((x:{data:string})=>x.data.replace(/^"|"$/g,""));
      const dmarcFound=dmarcRecords.find(x=>x.toLowerCase().startsWith("v=dmarc1")) ?? "";
      setDmarcRecord(dmarcFound);

      const policy=dmarcFound.match(/(?:^|;)\s*p=([^;]+)/i)?.[1]?.trim().toLowerCase() ?? "";
      setDmarcPolicy(policy);
      setDmarc(dmarcFound ? "success" : "warning");
    } catch {
      setDns("warning"); setSpf("warning"); setDmarc("warning");
    }

    setProgress(85);
    setHttps(await hp);
    setProgress(100);
    setScanning(false);
    setComplete(true);
  }

  function reset() {
    setComplete(false); setProgress(0); setMessage("");
    setHttps("pending"); setDns("pending"); setSpf("pending"); setDmarc("pending");
    setIps([]); setMx([]); setSpfRecord(""); setDmarcRecord(""); setDmarcPolicy("");
  }

  const label=(s:State, ok="Found") =>
    s==="success" ? ok : s==="warning" ? "Not found" : s==="checking" ? "Checking" : "Pending";

  function dmarcText() {
    if (dmarc==="warning") return "No DMARC policy was found for this domain.";
    if (!dmarcRecord) return "Checking the domain's public DMARC record.";
    if (dmarcPolicy==="reject") return "A DMARC record was found with a reject policy.";
    if (dmarcPolicy==="quarantine") return "A DMARC record was found with a quarantine policy.";
    if (dmarcPolicy==="none") return "A DMARC record was found, but the policy is monitoring only.";
    return "A DMARC record was found.";
  }

  return <main className="page"><section className="hero">
    <span className="badge">Beta</span>
    <h1>StudentScans</h1>
    <p className="lead">Enter a website to run a basic external security overview.</p>

    <div className="scan-form">
      <label htmlFor="domain">Website domain</label>
      <input id="domain" className="domain-input" placeholder="example.com" value={domain} disabled={scanning}
        onChange={e=>setDomain(e.target.value)} />
      <button onClick={()=>void startScan()} disabled={scanning}>{scanning ? "Scanning..." : "Start scan"}</button>
    </div>

    {message && <p className="error-message">{message}</p>}

    {scanning && <section className="scan-panel">
      <div className="scan-heading"><h2>Scanning {target}</h2><span>{progress}%</span></div>
      <div className="progress-track"><div className="progress-bar" style={{width:`${progress}%`}} /></div>
      <p className="scan-step">
        {progress<20 ? "Starting scan..." : progress<50 ? "Checking HTTPS and DNS..." :
         progress<70 ? "Checking SPF..." : progress<100 ? "Checking DMARC policy..." : "Preparing results..."}
      </p>
    </section>}

    {complete && <section className="results-panel">
      <div className="results-heading">
        <div><p className="section-label">Scan complete</p><h2>{target}</h2></div>
        <button className="secondary-button" onClick={reset}>New scan</button>
      </div>

      <p className="notice">StudentScans currently performs basic HTTPS reachability and public DNS, MX, SPF and DMARC lookups.</p>

      <div className="check-list">
        <article className="check-card"><div><h3>HTTPS</h3><p>{https==="success" ? "The website responded to a basic HTTPS connection attempt." : "The browser could not confirm a basic HTTPS connection."}</p></div><span className={`check-status ${https}`}>{label(https,"Reachable")}</span></article>

        <article className="check-card"><div><h3>DNS</h3><p>{dns==="success" ? `${ips.length} IPv4 record(s) and ${mx.length} mail server record(s) found.` : "Public A-records could not be confirmed."}</p>
        {ips.length>0 && <div className="record-details"><p><strong>IPv4:</strong> {ips.join(", ")}</p>{mx.length>0 && <p><strong>MX:</strong> {mx.slice(0,3).join(", ")}</p>}</div>}</div><span className={`check-status ${dns}`}>{dns==="warning" ? "Could not confirm" : label(dns)}</span></article>

        <article className="check-card"><div><h3>SPF</h3><p>{spf==="success" ? "An SPF policy was found in the domain's public TXT records." : "No SPF policy was found in the public TXT records."}</p>{spfRecord && <div className="record-details"><p><strong>SPF record:</strong> {spfRecord}</p></div>}</div><span className={`check-status ${spf}`}>{label(spf)}</span></article>

        <article className="check-card"><div><h3>DMARC</h3><p>{dmarcText()}</p>{dmarcRecord && <div className="record-details"><p><strong>Policy:</strong> {dmarcPolicy || "Not specified"}</p><p><strong>DMARC record:</strong> {dmarcRecord}</p></div>}</div><span className={`check-status ${dmarc}`}>{label(dmarc)}</span></article>

        <article className="check-card"><div><h3>Security Headers</h3><p>This check will be connected in a later version.</p></div><span className="check-status pending">Pending</span></article>
      </div>
    </section>}
  </section></main>;
}
