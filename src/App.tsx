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
  const [headers,setHeaders]=useState<State>("pending");
  const [ips,setIps]=useState<string[]>([]);
  const [mx,setMx]=useState<string[]>([]);
  const [spfRecord,setSpfRecord]=useState("");
  const [dmarcRecord,setDmarcRecord]=useState("");
  const [dmarcPolicy,setDmarcPolicy]=useState("");

  async function startScan() {
    const d=cleanDomain(domain);
    if(!d || !d.includes(".")){setMessage("Please enter a valid domain, such as example.com.");return;}

    setMessage(""); setTarget(d); setScanning(true); setComplete(false); setProgress(10);
    setHttps("checking"); setDns("checking"); setSpf("checking"); setDmarc("checking"); setHeaders("checking");
    setIps([]); setMx([]); setSpfRecord(""); setDmarcRecord(""); setDmarcPolicy("");

    const hp=httpsCheck(d);
    setProgress(20);

    try {
      const [a,m,t,dm]=await Promise.all([dnsQuery(d,"A"),dnsQuery(d,"MX"),dnsQuery(d,"TXT"),dnsQuery(`_dmarc.${d}`,"TXT")]);
      const foundIps=(a.Answer??[]).filter((x:{type:number})=>x.type===1).map((x:{data:string})=>x.data);
      const foundMx=(m.Answer??[]).filter((x:{type:number})=>x.type===15).map((x:{data:string})=>x.data);
      setIps(foundIps); setMx(foundMx); setDns(foundIps.length?"success":"warning"); setProgress(45);

      const txt:string[]=(t.Answer??[]).filter((x:{type:number})=>x.type===16).map((x:{data:string})=>x.data.replace(/^"|"$/g,""));
      const sf=txt.find(x=>x.toLowerCase().startsWith("v=spf1"))??"";
      setSpfRecord(sf); setSpf(sf?"success":"warning"); setProgress(60);

      const dr:string[]=(dm.Answer??[]).filter((x:{type:number})=>x.type===16).map((x:{data:string})=>x.data.replace(/^"|"$/g,""));
      const df=dr.find(x=>x.toLowerCase().startsWith("v=dmarc1"))??"";
      const policy=df.match(/(?:^|;)\s*p=([^;]+)/i)?.[1]?.trim().toLowerCase()??"";
      setDmarcRecord(df); setDmarcPolicy(policy); setDmarc(df?"success":"warning");
    } catch {setDns("warning");setSpf("warning");setDmarc("warning");}

    setProgress(75);
    try {
      await fetch(`https://${d}`, {mode:"no-cors",cache:"no-store"});
      setHeaders("success");
    } catch {setHeaders("warning");}

    setProgress(90); setHttps(await hp); setProgress(100); setScanning(false); setComplete(true);
  }

  function reset(){setComplete(false);setProgress(0);setMessage("");setHttps("pending");setDns("pending");setSpf("pending");setDmarc("pending");setHeaders("pending");setIps([]);setMx([]);setSpfRecord("");setDmarcRecord("");setDmarcPolicy("");}

  const label=(s:State,ok="Found")=>s==="success"?ok:s==="warning"?"Not found":s==="checking"?"Checking":"Pending";

  return <main className="page"><section className="hero">
    <span className="badge">Beta</span><h1>StudentScans</h1>
    <p className="lead">Enter a website to run a basic external security overview.</p>
    <div className="scan-form"><label htmlFor="domain">Website domain</label>
      <input id="domain" className="domain-input" placeholder="example.com" value={domain} disabled={scanning} onChange={e=>setDomain(e.target.value)}/>
      <button onClick={()=>void startScan()} disabled={scanning}>{scanning?"Scanning...":"Start scan"}</button>
    </div>
    {message&&<p className="error-message">{message}</p>}
    {scanning&&<section className="scan-panel"><div className="scan-heading"><h2>Scanning {target}</h2><span>{progress}%</span></div><div className="progress-track"><div className="progress-bar" style={{width:`${progress}%`}}/></div><p className="scan-step">{progress<45?"Checking HTTPS and DNS...":progress<60?"Checking SPF...":progress<75?"Checking DMARC...":progress<90?"Preparing Security Headers check...":"Preparing results..."}</p></section>}
    {complete&&<section className="results-panel">
      <div className="results-heading"><div><p className="section-label">Scan complete</p><h2>{target}</h2></div><button className="secondary-button" onClick={reset}>New scan</button></div>
      <p className="notice">StudentScans performs basic public checks. Detailed response-header inspection requires a small backend because browsers restrict cross-origin header access.</p>
      <div className="check-list">
        <article className="check-card"><div><h3>HTTPS</h3><p>{https==="success"?"The website responded to a basic HTTPS connection attempt.":"The browser could not confirm a basic HTTPS connection."}</p></div><span className={`check-status ${https}`}>{label(https,"Reachable")}</span></article>
        <article className="check-card"><div><h3>DNS</h3><p>{dns==="success"?`${ips.length} IPv4 record(s) and ${mx.length} mail server record(s) found.`:"Public A-records could not be confirmed."}</p>{ips.length>0&&<div className="record-details"><p><strong>IPv4:</strong> {ips.join(", ")}</p>{mx.length>0&&<p><strong>MX:</strong> {mx.slice(0,3).join(", ")}</p>}</div>}</div><span className={`check-status ${dns}`}>{dns==="warning"?"Could not confirm":label(dns)}</span></article>
        <article className="check-card"><div><h3>SPF</h3><p>{spf==="success"?"An SPF policy was found in the domain's public TXT records.":"No SPF policy was found in the public TXT records."}</p>{spfRecord&&<div className="record-details"><p><strong>SPF record:</strong> {spfRecord}</p></div>}</div><span className={`check-status ${spf}`}>{label(spf)}</span></article>
        <article className="check-card"><div><h3>DMARC</h3><p>{dmarc==="success"?`A DMARC record was found${dmarcPolicy?` with policy: ${dmarcPolicy}`:""}.`:"No DMARC policy was found for this domain."}</p>{dmarcRecord&&<div className="record-details"><p><strong>DMARC record:</strong> {dmarcRecord}</p></div>}</div><span className={`check-status ${dmarc}`}>{label(dmarc)}</span></article>
        <article className="check-card"><div><h3>Security Headers</h3><p>{headers==="success"?"Target is reachable. Detailed header inspection is prepared for the backend step.":"Target could not be reached for the planned header check."}</p><div className="record-details"><p><strong>Planned checks:</strong></p><p>• Content-Security-Policy</p><p>• Strict-Transport-Security</p><p>• X-Frame-Options</p><p>• X-Content-Type-Options</p></div></div><span className={`check-status ${headers}`}>{headers==="success"?"Prepared":"Could not confirm"}</span></article>
      </div>
    </section>}
  </section></main>;
}
