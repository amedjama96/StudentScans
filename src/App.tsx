import { useState } from "react";
type HeaderResult={name:string;found:boolean;value:string};

function cleanDomain(v:string){return v.trim().replace(/^https?:\/\//i,"").replace(/\/.*$/,"").toLowerCase();}
async function dnsQuery(d:string,t:string){const r=await fetch(`https://dns.google/resolve?name=${encodeURIComponent(d)}&type=${t}`);if(!r.ok)throw new Error();return r.json();}

export default function App(){
 const[domain,setDomain]=useState("");const[target,setTarget]=useState("");const[msg,setMsg]=useState("");
 const[scanning,setScanning]=useState(false);const[complete,setComplete]=useState(false);
 const[ips,setIps]=useState<string[]>([]);const[mx,setMx]=useState<string[]>([]);
 const[spf,setSpf]=useState("");const[dmarc,setDmarc]=useState("");const[policy,setPolicy]=useState("");
 const[headers,setHeaders]=useState<HeaderResult[]>([]);const[backendOk,setBackendOk]=useState(true);

 async function scan(){
  const d=cleanDomain(domain);
  if(!d||!d.includes(".")){setMsg("Please enter a valid domain, such as example.com.");return;}
  setMsg("");setTarget(d);setScanning(true);setComplete(false);setHeaders([]);setBackendOk(true);

  try{
   const[a,m,t,dm]=await Promise.all([dnsQuery(d,"A"),dnsQuery(d,"MX"),dnsQuery(d,"TXT"),dnsQuery(`_dmarc.${d}`,"TXT")]);
   setIps((a.Answer??[]).filter((x:any)=>x.type===1).map((x:any)=>x.data));
   setMx((m.Answer??[]).filter((x:any)=>x.type===15).map((x:any)=>x.data));
   const txt:string[]=(t.Answer??[]).filter((x:any)=>x.type===16).map((x:any)=>x.data.replace(/^"|"$/g,""));
   setSpf(txt.find(x=>x.toLowerCase().startsWith("v=spf1"))??"");
   const dr:string[]=(dm.Answer??[]).filter((x:any)=>x.type===16).map((x:any)=>x.data.replace(/^"|"$/g,""));
   const rec=dr.find(x=>x.toLowerCase().startsWith("v=dmarc1"))??"";
   setDmarc(rec);setPolicy(rec.match(/(?:^|;)\s*p=([^;]+)/i)?.[1]?.trim()??"");
  }catch{setIps([]);setMx([]);setSpf("");setDmarc("");setPolicy("");}

  try{
   const r=await fetch(`http://localhost:3001/api/headers?domain=${encodeURIComponent(d)}`);
   if(!r.ok)throw new Error();
   const data=await r.json();setHeaders(data.headers);
  }catch{setBackendOk(false);}
  setScanning(false);setComplete(true);
 }

 const found=headers.filter(h=>h.found).length;

 return <main className="page"><section className="hero">
  <span className="badge">Beta • Day 10</span><h1>StudentScans</h1>
  <p className="lead">Enter a website to run a basic external security overview.</p>
  <div className="scan-form"><label>Website domain</label><input className="domain-input" placeholder="example.com" value={domain} onChange={e=>setDomain(e.target.value)} disabled={scanning}/><button onClick={()=>void scan()} disabled={scanning}>{scanning?"Scanning...":"Start scan"}</button></div>
  {msg&&<p className="error">{msg}</p>}
  {scanning&&<section className="panel"><h2>Scanning {target}...</h2><p className="muted">DNS, email security and HTTP response headers are being checked.</p></section>}
  {complete&&<section className="panel">
   <p className="complete">SCAN COMPLETE</p><h2>{target}</h2>
   <p className="notice">Day 10 adds a local Node.js backend so StudentScans can inspect HTTP security headers server-side.</p>
   <div className="cards">
    <article><div><h3>DNS</h3><p>{ips.length?`${ips.length} IPv4 record(s) found.`:"No IPv4 records confirmed."}</p>{ips.length>0&&<div className="details"><p><b>IPv4:</b> {ips.join(", ")}</p>{mx.length>0&&<p><b>MX:</b> {mx.slice(0,3).join(", ")}</p>}</div>}</div><span className={ips.length?"good":"bad"}>{ips.length?"Found":"Not found"}</span></article>
    <article><div><h3>SPF</h3><p>{spf?"SPF policy found.":"No SPF policy found."}</p>{spf&&<div className="details">{spf}</div>}</div><span className={spf?"good":"bad"}>{spf?"Found":"Not found"}</span></article>
    <article><div><h3>DMARC</h3><p>{dmarc?`DMARC policy found${policy?`: ${policy}`:""}.`:"No DMARC policy found."}</p>{dmarc&&<div className="details">{dmarc}</div>}</div><span className={dmarc?"good":"bad"}>{dmarc?"Found":"Not found"}</span></article>
    <article><div><h3>Security Headers</h3><p>{backendOk?`${found} of ${headers.length} checked headers were found.`:"Backend unavailable. Start the Day 10 server first."}</p>{headers.length>0&&<div className="details">{headers.map(h=><p key={h.name}><b>{h.found?"✓":"✕"} {h.name}</b>{h.found&&h.value?`: ${h.value}`:""}</p>)}</div>}</div><span className={backendOk?"good":"bad"}>{backendOk?"Inspected":"Backend offline"}</span></article>
   </div>
  </section>}
 </section></main>
}
