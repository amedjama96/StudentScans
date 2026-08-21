import {useMemo,useState} from "react";
import "./styles.css";

type Header={name:string;value:string;found:boolean;rating:"Good"|"Review"|"Missing";findings:string[]};
type TLS={protocol:string|null;protocolRating:string;cipherName:string;cipherVersion:string;cipherStandardName:string;subject:string;issuer:string;validFrom:string;validTo:string;daysRemaining:number;authorized:boolean};
type Redirect={initialStatus:number;redirected:boolean;finalUrl:string;finalStatus:number;usesHttps:boolean};

const clean=(v:string)=>v.trim().replace(/^https?:\/\//i,"").replace(/\/.*$/,"").toLowerCase();
const valid=(v:string)=>/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(v);
const badge=(r:string)=>r==="Good"?"ok":r==="Review"?"warn":"fail";
const fmt=(v:string)=>new Intl.DateTimeFormat("en-GB",{day:"2-digit",month:"short",year:"numeric"}).format(new Date(v));

async function dns(domain:string,type:string){
 const r=await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
 if(!r.ok)throw Error(); return r.json();
}

export default function App(){
 const[domain,setDomain]=useState(""); const[target,setTarget]=useState(""); const[error,setError]=useState("");
 const[busy,setBusy]=useState(false); const[done,setDone]=useState(false);
 const[ips,setIps]=useState<string[]>([]); const[spf,setSpf]=useState(""); const[dmarc,setDmarc]=useState(""); const[policy,setPolicy]=useState("");
 const[headers,setHeaders]=useState<Header[]>([]); const[headersOk,setHeadersOk]=useState(true);
 const[tls,setTls]=useState<TLS|null>(null); const[redirect,setRedirect]=useState<Redirect|null>(null);

 async function scan(){
   const d=clean(domain);
   if(!valid(d)){setError("Please enter a valid domain, such as example.com.");return;}
   setError("");setBusy(true);setDone(false);setTarget(d);setHeaders([]);setTls(null);setRedirect(null);setHeadersOk(true);

   try{
     const[a,t,dm]=await Promise.all([dns(d,"A"),dns(d,"TXT"),dns(`_dmarc.${d}`,"TXT")]);
     setIps((a.Answer??[]).filter((x:any)=>x.type===1).map((x:any)=>x.data));
     const txt=(t.Answer??[]).filter((x:any)=>x.type===16).map((x:any)=>String(x.data).replace(/^"|"$/g,""));
     setSpf(txt.find((x:string)=>x.toLowerCase().startsWith("v=spf1"))??"");
     const dr=(dm.Answer??[]).filter((x:any)=>x.type===16).map((x:any)=>String(x.data).replace(/^"|"$/g,""));
     const rec=dr.find((x:string)=>x.toLowerCase().startsWith("v=dmarc1"))??"";
     setDmarc(rec); setPolicy(rec.match(/(?:^|;)\s*p=([^;]+)/i)?.[1]?.trim().toLowerCase()??"");
   }catch{setIps([]);setSpf("");setDmarc("");setPolicy("");}

   await Promise.all([
     fetch(`http://localhost:3001/api/headers?domain=${encodeURIComponent(d)}`).then(async r=>{if(!r.ok)throw Error();setHeaders((await r.json()).headers)}).catch(()=>setHeadersOk(false)),
     fetch(`http://localhost:3001/api/tls?domain=${encodeURIComponent(d)}`).then(async r=>{if(!r.ok)throw Error();setTls(await r.json())}).catch(()=>setTls(null)),
     fetch(`http://localhost:3001/api/redirect?domain=${encodeURIComponent(d)}`).then(async r=>{if(!r.ok)throw Error();setRedirect(await r.json())}).catch(()=>setRedirect(null))
   ]);
   setBusy(false);setDone(true);
 }

 const good=headers.filter(h=>h.rating==="Good").length;
 const review=headers.filter(h=>h.rating==="Review").length;
 const missing=headers.filter(h=>h.rating==="Missing").length;
 const headerScore=headersOk&&headers.length?Math.round(((good+review*.5)/headers.length)*30):0;
 const dnsScore=ips.length?10:0,spfScore=spf?10:0,dmarcScore=dmarc?(policy==="reject"?20:policy==="quarantine"?15:10):0;
 const tlsScore=tls&&tls.authorized&&tls.daysRemaining>0?(tls.protocol==="TLSv1.3"?20:tls.protocol==="TLSv1.2"?16:8):0;
 const redirectScore=redirect?.usesHttps?10:0;
 const score=Math.min(100,dnsScore+spfScore+dmarcScore+headerScore+tlsScore+redirectScore);

 const recs=useMemo(()=>{
   const r:string[]=[];
   headers.forEach(h=>{
     if(h.rating==="Missing")r.push(`${h.name} is missing.`);
     if(h.rating==="Review")h.findings.forEach(f=>r.push(`${h.name}: ${f}`));
   });
   if(!redirect?.usesHttps)r.push("HTTP traffic should redirect to HTTPS.");
   return r;
 },[headers,redirect]);

 return <main><section className="shell">
   <div className="tags"><span>Phase 2</span><span>v1.3-dev</span></div>
   <h1>StudentScans</h1>
   <p className="lead">External domain security checks with Security Headers v2.</p>
   <div className="form"><label>Website domain</label><input value={domain} placeholder="example.com" onChange={e=>setDomain(e.target.value)}/><button onClick={scan} disabled={busy}>{busy?"Scanning...":"Start scan"}</button></div>
   {error&&<p className="error">{error}</p>}

   {done&&<section className="results">
     <div className="top"><div><small>SCAN COMPLETE</small><h2>{target}</h2></div><div className={`score ${score>=80?"green":score>=50?"yellow":"red"}`}><b>{score}</b><span>/100</span></div></div>
     <div className="breakdown"><div>DNS<b>{dnsScore}/10</b></div><div>SPF<b>{spfScore}/10</b></div><div>DMARC<b>{dmarcScore}/20</b></div><div>Headers<b>{headerScore}/30</b></div><div>TLS<b>{tlsScore}/20</b></div><div>Redirect<b>{redirectScore}/10</b></div></div>

     <article className="card"><h3>Security Headers v2</h3><p>{headersOk?`${good} good • ${review} review • ${missing} missing`:"Header inspection unavailable."}</p>
       <div className="headergrid">{headers.map(h=><div className="header" key={h.name}>
         <div className="headerline"><b>{h.name}</b><span className={badge(h.rating)}>{h.rating}</span></div>
         <code>{h.value||"Not present"}</code>
         {h.findings.map(f=><p className="finding" key={f}>• {f}</p>)}
       </div>)}</div>
     </article>

     <article className="card"><div className="headerline"><h3>TLS Analysis</h3><span className={tls?.authorized?"ok":"fail"}>{tls?.authorized?"Verified":"Check needed"}</span></div>
       {tls&&<div className="details"><p><b>Protocol:</b> {tls.protocol}</p><p><b>Cipher:</b> {tls.cipherStandardName||tls.cipherName}</p><p><b>Subject:</b> {tls.subject}</p><p><b>Issuer:</b> {tls.issuer}</p><p><b>Valid to:</b> {fmt(tls.validTo)}</p><p><b>Days remaining:</b> {tls.daysRemaining}</p></div>}
     </article>

     <article className="card"><div className="headerline"><h3>HTTPS Redirect</h3><span className={redirect?.usesHttps?"ok":"fail"}>{redirect?.usesHttps?"HTTPS enforced":"Check needed"}</span></div>
       {redirect&&<div className="details"><p><b>Initial status:</b> {redirect.initialStatus}</p><p><b>Redirected:</b> {redirect.redirected?"Yes":"No"}</p><p><b>Final URL:</b> {redirect.finalUrl}</p><p><b>Final status:</b> {redirect.finalStatus}</p></div>}
     </article>

     <article className="card"><h3>Recommendations</h3>{recs.length?recs.map((r,i)=><div className="rec" key={i}><b>{i+1}</b><span>{r}</span></div>):<p>No recommendations generated.</p>}</article>
   </section>}
 </section></main>
}