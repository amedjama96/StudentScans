import { useState } from "react";
type H={name:string;found:boolean;value:string};
const clean=(v:string)=>v.trim().replace(/^https?:\/\//i,"").replace(/\/.*$/,"").toLowerCase();
async function dns(d:string,t:string){const r=await fetch(`https://dns.google/resolve?name=${encodeURIComponent(d)}&type=${t}`);if(!r.ok)throw Error();return r.json();}
export default function App(){
 const[domain,setDomain]=useState(""),[target,setTarget]=useState(""),[msg,setMsg]=useState("");
 const[busy,setBusy]=useState(false),[done,setDone]=useState(false),[ips,setIps]=useState<string[]>([]);
 const[spf,setSpf]=useState(""),[dmarc,setDmarc]=useState(""),[policy,setPolicy]=useState("");
 const[headers,setHeaders]=useState<H[]>([]),[backend,setBackend]=useState(true);
 async function scan(){
  const d=clean(domain);if(!d||!d.includes(".")){setMsg("Please enter a valid domain, such as example.com.");return;}
  setMsg("");setTarget(d);setBusy(true);setDone(false);setHeaders([]);setBackend(true);
  try{const[a,t,dm]=await Promise.all([dns(d,"A"),dns(d,"TXT"),dns(`_dmarc.${d}`,"TXT")]);
   setIps((a.Answer??[]).filter((x:any)=>x.type===1).map((x:any)=>x.data));
   const tr:string[]=(t.Answer??[]).filter((x:any)=>x.type===16).map((x:any)=>x.data.replace(/^"|"$/g,""));
   setSpf(tr.find(x=>x.toLowerCase().startsWith("v=spf1"))??"");
   const dr:string[]=(dm.Answer??[]).filter((x:any)=>x.type===16).map((x:any)=>x.data.replace(/^"|"$/g,""));
   const rec=dr.find(x=>x.toLowerCase().startsWith("v=dmarc1"))??"";setDmarc(rec);setPolicy(rec.match(/(?:^|;)\s*p=([^;]+)/i)?.[1]?.trim().toLowerCase()??"");
  }catch{setIps([]);setSpf("");setDmarc("");setPolicy("");}
  try{const r=await fetch(`http://localhost:3001/api/headers?domain=${encodeURIComponent(d)}`);if(!r.ok)throw Error();setHeaders((await r.json()).headers);}
  catch{setBackend(false);}
  setBusy(false);setDone(true);
 }
 const found=headers.filter(h=>h.found).length;
 const score=Math.min(100,(ips.length?15:0)+(spf?15:0)+(dmarc?(policy==="reject"?30:policy==="quarantine"?25:20):0)+(backend&&headers.length?Math.round(found/headers.length*40):0));
 const recs:string[]=[];
 if(!spf)recs.push("Add an SPF record to define which mail servers may send email for this domain.");
 if(!dmarc)recs.push("Add a DMARC record to improve protection against email spoofing.");
 else if(policy==="none")recs.push("DMARC is monitoring only. Consider moving toward quarantine or reject after reviewing reports.");
 if(backend)headers.filter(h=>!h.found).forEach(h=>{
  if(h.name==="Content-Security-Policy")recs.push("Consider adding Content-Security-Policy to reduce the impact of content injection attacks.");
  if(h.name==="Strict-Transport-Security")recs.push("Consider enabling HSTS so browsers use HTTPS for future connections.");
  if(h.name==="X-Frame-Options")recs.push("Consider clickjacking protection with X-Frame-Options or CSP frame-ancestors.");
  if(h.name==="X-Content-Type-Options")recs.push("Consider adding X-Content-Type-Options: nosniff.");
 });
 const sc=score>=80?"goodScore":score>=50?"midScore":"lowScore";
 return <main><section className="hero"><span className="badge">Beta • Day 11</span><h1>StudentScans</h1><p className="lead">Basic external security checks with a simple score and recommendations.</p>
 <div className="form"><label>Website domain</label><input placeholder="example.com" value={domain} onChange={e=>setDomain(e.target.value)} disabled={busy}/><button onClick={()=>void scan()} disabled={busy}>{busy?"Scanning...":"Start scan"}</button></div>{msg&&<p className="error">{msg}</p>}
 {busy&&<section className="panel"><h2>Scanning {target}...</h2><p>Checking DNS, email security and HTTP response headers.</p></section>}
 {done&&<section className="panel"><p className="complete">SCAN COMPLETE</p><div className="top"><div><h2>{target}</h2><p>Basic external security overview</p></div><div className={`score ${sc}`}><b>{score}</b><span>/100</span><small>Security score</small></div></div>
 <div className="notice">This educational score only reflects the checks shown here. It is not a vulnerability assessment and does not prove that a website is secure.</div>
 <div className="cards">
 <article><div><h3>DNS</h3><p>{ips.length?`${ips.length} IPv4 record(s) found.`:"No IPv4 records confirmed."}</p></div><span className={ips.length?"ok":"fail"}>{ips.length?"Found":"Not found"}</span></article>
 <article><div><h3>SPF</h3><p>{spf?"SPF policy found.":"No SPF policy found."}</p></div><span className={spf?"ok":"fail"}>{spf?"Found":"Not found"}</span></article>
 <article><div><h3>DMARC</h3><p>{dmarc?`DMARC policy: ${policy||"not specified"}.`:"No DMARC policy found."}</p></div><span className={dmarc?"ok":"fail"}>{dmarc?"Found":"Not found"}</span></article>
 <article><div><h3>Security Headers</h3><p>{backend?`${found} of ${headers.length} checked headers were found.`:"Backend unavailable."}</p>{headers.length>0&&<div className="details">{headers.map(h=><p key={h.name}>{h.found?"✓":"✕"} {h.name}</p>)}</div>}</div><span className={backend?"ok":"fail"}>{backend?"Inspected":"Offline"}</span></article></div>
 <section className="recommend"><div className="recHead"><div><small>NEXT STEPS</small><h2>Recommendations</h2></div><span>{recs.length} items</span></div>
 {recs.length?<div className="recList">{recs.map((r,i)=><div className="rec" key={i}><b>{i+1}</b><p>{r}</p></div>)}</div>:<p className="allgood">No recommendations generated from the current basic checks.</p>}</section>
 </section>}</section></main>;
}