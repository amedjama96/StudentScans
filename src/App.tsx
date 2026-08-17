import { useMemo, useState } from "react";

type HeaderResult={name:string;found:boolean;value:string};
type TlsResult={protocol:string|null;subject:string;issuer:string;validFrom:string;validTo:string;daysRemaining:number;authorized:boolean;authorizationError:string};

const clean=(v:string)=>v.trim().replace(/^https?:\/\//i,"").replace(/\/.*$/,"").toLowerCase();
const validDomain=(v:string)=>/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(v);

async function dns(domain:string,type:string){
  const r=await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
  if(!r.ok)throw Error();
  return r.json();
}

async function timedFetch(url:string,ms=9000){
  const c=new AbortController();
  const t=window.setTimeout(()=>c.abort(),ms);
  try{return await fetch(url,{signal:c.signal});}
  finally{window.clearTimeout(t);}
}

const scoreClass=(s:number)=>s>=80?"score-good":s>=50?"score-medium":"score-low";
const risk=(s:number)=>s>=80?"Low":s>=50?"Moderate":"Elevated";
const fmt=(v:string)=>new Intl.DateTimeFormat("en-GB",{day:"2-digit",month:"short",year:"numeric"}).format(new Date(v));

export default function App(){
  const[domain,setDomain]=useState(""),[target,setTarget]=useState(""),[msg,setMsg]=useState("");
  const[busy,setBusy]=useState(false),[done,setDone]=useState(false);
  const[ips,setIps]=useState<string[]>([]),[spf,setSpf]=useState(""),[dmarc,setDmarc]=useState(""),[policy,setPolicy]=useState("");
  const[headers,setHeaders]=useState<HeaderResult[]>([]),[backend,setBackend]=useState(true);
  const[tls,setTls]=useState<TlsResult|null>(null),[tlsOk,setTlsOk]=useState(true);
  const[scanTime,setScanTime]=useState(""),[duration,setDuration]=useState(0);

  function reset(){
    setDone(false);setMsg("");setTarget("");setIps([]);setSpf("");setDmarc("");setPolicy("");
    setHeaders([]);setBackend(true);setTls(null);setTlsOk(true);setScanTime("");setDuration(0);
  }

  async function scan(){
    const d=clean(domain);
    if(!validDomain(d)){setMsg("Please enter a valid domain, such as example.com.");return;}
    const started=performance.now();
    setMsg("");setTarget(d);setBusy(true);setDone(false);setHeaders([]);setBackend(true);setTls(null);setTlsOk(true);

    try{
      const[a,t,dm]=await Promise.all([dns(d,"A"),dns(d,"TXT"),dns(`_dmarc.${d}`,"TXT")]);
      setIps((a.Answer??[]).filter((x:any)=>x.type===1).map((x:any)=>x.data));
      const txt:string[]=(t.Answer??[]).filter((x:any)=>x.type===16).map((x:any)=>x.data.replace(/^"|"$/g,""));
      setSpf(txt.find(x=>x.toLowerCase().startsWith("v=spf1"))??"");
      const dr:string[]=(dm.Answer??[]).filter((x:any)=>x.type===16).map((x:any)=>x.data.replace(/^"|"$/g,""));
      const rec=dr.find(x=>x.toLowerCase().startsWith("v=dmarc1"))??"";
      setDmarc(rec);setPolicy(rec.match(/(?:^|;)\s*p=([^;]+)/i)?.[1]?.trim().toLowerCase()??"");
    }catch{setIps([]);setSpf("");setDmarc("");setPolicy("");}

    try{
      const r=await timedFetch(`http://localhost:3001/api/headers?domain=${encodeURIComponent(d)}`);
      if(!r.ok)throw Error(); setHeaders((await r.json()).headers);
    }catch{setBackend(false);}

    try{
      const r=await timedFetch(`http://localhost:3001/api/tls?domain=${encodeURIComponent(d)}`);
      if(!r.ok)throw Error(); setTls(await r.json());
    }catch{setTlsOk(false);}

    setDuration(Number(((performance.now()-started)/1000).toFixed(1)));
    setScanTime(new Intl.DateTimeFormat("en-GB",{dateStyle:"medium",timeStyle:"short"}).format(new Date()));
    setBusy(false);setDone(true);
  }

  const foundHeaders=headers.filter(h=>h.found).length;
  const headerPoints=backend&&headers.length?Math.round(foundHeaders/headers.length*35):0;
  const dnsPoints=ips.length?10:0, spfPoints=spf?10:0;
  const dmarcPoints=dmarc?(policy==="reject"?25:policy==="quarantine"?20:15):0;
  const tlsPoints=tls&&tls.authorized&&tls.daysRemaining>0?(tls.daysRemaining<=30?15:20):0;
  const score=Math.min(100,dnsPoints+spfPoints+dmarcPoints+headerPoints+tlsPoints);

  const recs=useMemo(()=>{
    const r:string[]=[];
    if(!spf)r.push("Add an SPF record to define which mail servers may send email for this domain.");
    if(!dmarc)r.push("Add a DMARC record to improve protection against email spoofing.");
    else if(policy==="none")r.push("DMARC is monitoring only. Consider moving toward quarantine or reject after reviewing reports.");
    if(!backend)r.push("The local backend could not complete HTTP security-header inspection.");
    else headers.filter(h=>!h.found).forEach(h=>{
      if(h.name==="Content-Security-Policy")r.push("Consider adding Content-Security-Policy to reduce the impact of content injection attacks.");
      if(h.name==="Strict-Transport-Security")r.push("Consider enabling HSTS so browsers use HTTPS for future connections.");
      if(h.name==="X-Frame-Options")r.push("Consider clickjacking protection with X-Frame-Options or CSP frame-ancestors.");
      if(h.name==="X-Content-Type-Options")r.push("Consider adding X-Content-Type-Options: nosniff.");
    });
    if(!tlsOk||!tls)r.push("TLS certificate details could not be confirmed.");
    else if(!tls.authorized)r.push("The TLS certificate could not be verified by the local Node.js trust store.");
    else if(tls.daysRemaining<0)r.push("The TLS certificate appears to be expired and should be renewed immediately.");
    else if(tls.daysRemaining<=30)r.push(`The TLS certificate expires in ${tls.daysRemaining} days. Plan certificate renewal.`);
    return r;
  },[spf,dmarc,policy,backend,headers,tlsOk,tls]);

  const completed=[ips.length>0,!!spf,!!dmarc,backend&&headers.length>0,tlsOk&&!!tls].filter(Boolean).length;

  return <main><section className="hero">
    <div className="brand-row"><span className="badge">v1.0</span><span className="version">Student project</span></div>
    <h1>StudentScans</h1>
    <p className="lead">A small external security overview for domains, built to explore DNS, email security, HTTP headers and TLS.</p>

    <div className="form"><label>Website domain</label><input placeholder="example.com" value={domain} onChange={e=>setDomain(e.target.value)} disabled={busy} onKeyDown={e=>{if(e.key==="Enter"&&!busy)void scan();}}/><button onClick={()=>void scan()} disabled={busy}>{busy?"Scanning...":"Start scan"}</button></div>
    {msg&&<p className="error">{msg}</p>}

    {busy&&<section className="panel"><h2>Scanning {target}...</h2><p>Checking DNS, SPF, DMARC, HTTP security headers and TLS certificate details.</p></section>}

    {done&&<section className="panel">
      <div className="top"><div><p className="eyebrow">SCAN COMPLETE</p><h2>{target}</h2><p className="meta">{scanTime} • {duration}s</p></div><div className="actions"><button className="secondary" onClick={reset}>New scan</button><div className={`score ${scoreClass(score)}`}><b>{score}</b><span>/100</span><small>Security score</small></div></div></div>

      <div className="summary"><div><span>Risk level</span><strong className={scoreClass(score)}>{risk(score)}</strong></div><div><span>Check categories completed</span><strong>{completed}/5</strong></div><div><span>Recommendations</span><strong>{recs.length}</strong></div></div>

      <div className="notice">This educational score only reflects the checks shown below. It is not a vulnerability assessment, penetration test, or proof that a website is secure.</div>

      <div className="breakdown"><div>DNS <b>{dnsPoints}/10</b></div><div>SPF <b>{spfPoints}/10</b></div><div>DMARC <b>{dmarcPoints}/25</b></div><div>Headers <b>{headerPoints}/35</b></div><div>TLS <b>{tlsPoints}/20</b></div></div>

      <div className="cards">
        <article><div><h3>DNS</h3><p>{ips.length?`${ips.length} IPv4 record(s) found.`:"No IPv4 records confirmed."}</p></div><span className={ips.length?"ok":"fail"}>{ips.length?"Found":"Not found"}</span></article>
        <article><div><h3>SPF</h3><p>{spf?"SPF policy found.":"No SPF policy found."}</p></div><span className={spf?"ok":"fail"}>{spf?"Found":"Not found"}</span></article>
        <article><div><h3>DMARC</h3><p>{dmarc?`DMARC policy: ${policy||"not specified"}.`:"No DMARC policy found."}</p></div><span className={dmarc?"ok":"fail"}>{dmarc?"Found":"Not found"}</span></article>
        <article><div><h3>Security Headers</h3><p>{backend?`${foundHeaders} of ${headers.length} checked headers were found.`:"The local backend could not complete this check."}</p>{headers.length>0&&<div className="details">{headers.map(h=><p key={h.name}><b>{h.found?"✓":"✕"} {h.name}</b></p>)}</div>}</div><span className={backend?"ok":"fail"}>{backend?"Inspected":"Unavailable"}</span></article>
        <article><div><h3>TLS Certificate</h3>{tls?<><p>{tls.authorized?"Certificate chain verified.":"Certificate chain could not be verified."}</p><div className="details tls"><p><b>Protocol:</b> {tls.protocol||"Unknown"}</p><p><b>Subject:</b> {tls.subject}</p><p><b>Issuer:</b> {tls.issuer}</p><p><b>Valid from:</b> {fmt(tls.validFrom)}</p><p><b>Valid to:</b> {fmt(tls.validTo)}</p><p><b>Days remaining:</b> {tls.daysRemaining}</p></div></>:<p>TLS certificate details could not be confirmed.</p>}</div><span className={tls?.authorized&&tls.daysRemaining>0?"ok":"fail"}>{tls?.authorized&&tls.daysRemaining>0?"Valid":"Check needed"}</span></article>
      </div>

      <section className="recommend"><h2>Recommendations</h2>{recs.length?recs.map((r,i)=><div className="rec" key={r}><b>{i+1}</b><p>{r}</p></div>):<p>No recommendations generated.</p>}</section>
    </section>}
  </section></main>;
}