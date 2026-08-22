import {useMemo,useState} from "react";
import "./styles.css";

type SPF={record:string;rating:string;allPolicy:string;includeCount:number;redirect:string;usesPtr:boolean;findings:string[]};
type DMARC={record:string;rating:string;policy:string;subdomainPolicy:string;pct:number|null;rua:string;ruf:string;adkim:string;aspf:string;findings:string[]};
type Email={spf:SPF;dmarc:DMARC};
type Header={name:string;value:string;rating:string;findings:string[]};
type TLS={protocol:string;cipher:string;subject:string;issuer:string;validTo:string;daysRemaining:number;authorized:boolean};
type Redirect={finalUrl:string;finalStatus:number;usesHttps:boolean};

const clean=(v:string)=>v.trim().replace(/^https?:\/\//i,"").replace(/\/.*$/,"").toLowerCase();
const valid=(v:string)=>/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(v);
const cls=(r:string)=>r==="Good"?"ok":r==="Review"?"warn":"fail";
const fmt=(v:string)=>new Intl.DateTimeFormat("en-GB",{day:"2-digit",month:"short",year:"numeric"}).format(new Date(v));

export default function App(){
 const[domain,setDomain]=useState(""),[target,setTarget]=useState(""),[error,setError]=useState("");
 const[busy,setBusy]=useState(false),[done,setDone]=useState(false);
 const[email,setEmail]=useState<Email|null>(null),[headers,setHeaders]=useState<Header[]>([]);
 const[tls,setTls]=useState<TLS|null>(null),[redirect,setRedirect]=useState<Redirect|null>(null);

 async function scan(){
   const d=clean(domain);
   if(!valid(d)){setError("Please enter a valid domain, such as example.com.");return;}
   setError("");setBusy(true);setDone(false);setTarget(d);
   const base="http://localhost:3001";
   await Promise.all([
     fetch(`${base}/api/email-security?domain=${encodeURIComponent(d)}`).then(r=>r.json()).then(setEmail).catch(()=>setEmail(null)),
     fetch(`${base}/api/headers?domain=${encodeURIComponent(d)}`).then(r=>r.json()).then(x=>setHeaders(x.headers||[])).catch(()=>setHeaders([])),
     fetch(`${base}/api/tls?domain=${encodeURIComponent(d)}`).then(r=>r.json()).then(setTls).catch(()=>setTls(null)),
     fetch(`${base}/api/redirect?domain=${encodeURIComponent(d)}`).then(r=>r.json()).then(setRedirect).catch(()=>setRedirect(null))
   ]);
   setBusy(false);setDone(true);
 }

 const goodHeaders=headers.filter(h=>h.rating==="Good").length;
 const reviewHeaders=headers.filter(h=>h.rating==="Review").length;
 const headerScore=headers.length?Math.round(((goodHeaders+reviewHeaders*.5)/headers.length)*30):0;
 const spfScore=email?.spf.rating==="Good"?10:email?.spf.rating==="Review"?6:0;
 const dmarcScore=email?.dmarc.policy==="reject"?20:email?.dmarc.policy==="quarantine"?14:email?.dmarc.policy==="none"?8:0;
 const tlsScore=tls?.authorized?(tls.protocol==="TLSv1.3"?20:16):0;
 const redirectScore=redirect?.usesHttps?10:0;
 const score=Math.min(100,spfScore+dmarcScore+headerScore+tlsScore+redirectScore+10);

 const recs=useMemo(()=>{
   const r:string[]=[];
   email?.spf.findings.forEach(x=>r.push(`SPF: ${x}`));
   email?.dmarc.findings.forEach(x=>r.push(`DMARC: ${x}`));
   headers.forEach(h=>{if(h.rating==="Missing")r.push(`${h.name} is missing.`);h.findings.forEach(x=>r.push(`${h.name}: ${x}`));});
   if(redirect&&!redirect.usesHttps)r.push("HTTP traffic should redirect to HTTPS.");
   return r;
 },[email,headers,redirect]);

 return <main><section className="shell">
   <div className="tags"><span>Phase 2</span><span>v1.4-dev</span></div>
   <h1>StudentScans</h1>
   <p className="lead">External domain security checks with deeper SPF and DMARC analysis.</p>
   <div className="form"><label>Website domain</label><input value={domain} placeholder="example.com" onChange={e=>setDomain(e.target.value)}/><button onClick={scan} disabled={busy}>{busy?"Scanning...":"Start scan"}</button></div>
   {error&&<p className="error">{error}</p>}

   {done&&<section className="results">
     <div className="top"><div><small>SCAN COMPLETE</small><h2>{target}</h2></div><div className={`score ${score>=80?"green":score>=50?"yellow":"red"}`}><b>{score}</b><span>/100</span></div></div>
     <div className="breakdown"><div>DNS<b>10/10</b></div><div>SPF<b>{spfScore}/10</b></div><div>DMARC<b>{dmarcScore}/20</b></div><div>Headers<b>{headerScore}/30</b></div><div>TLS<b>{tlsScore}/20</b></div><div>Redirect<b>{redirectScore}/10</b></div></div>

     <article className="card">
       <h3>Email Security v2</h3>
       {email?<div className="emailgrid">
         <div className="panel">
           <div className="line"><b>SPF</b><span className={cls(email.spf.rating)}>{email.spf.rating}</span></div>
           <p><b>All policy:</b> {email.spf.allPolicy}</p><p><b>Include count:</b> {email.spf.includeCount}</p><p><b>Redirect:</b> {email.spf.redirect||"None"}</p><p><b>Uses ptr:</b> {email.spf.usesPtr?"Yes":"No"}</p>
           <code>{email.spf.record||"No SPF record found"}</code>
           {email.spf.findings.map(x=><p className="finding" key={x}>• {x}</p>)}
         </div>
         <div className="panel">
           <div className="line"><b>DMARC</b><span className={cls(email.dmarc.rating)}>{email.dmarc.rating}</span></div>
           <p><b>Policy:</b> {email.dmarc.policy}</p><p><b>Subdomain policy:</b> {email.dmarc.subdomainPolicy||"Inherited"}</p><p><b>Percentage:</b> {email.dmarc.pct ?? "Unknown"}%</p><p><b>rua:</b> {email.dmarc.rua||"Not configured"}</p><p><b>DKIM alignment:</b> {email.dmarc.adkim||"r"}</p><p><b>SPF alignment:</b> {email.dmarc.aspf||"r"}</p>
           <code>{email.dmarc.record||"No DMARC record found"}</code>
           {email.dmarc.findings.map(x=><p className="finding" key={x}>• {x}</p>)}
         </div>
       </div>:<p>Email security analysis unavailable.</p>}
     </article>

     <article className="card"><h3>Security Headers v2</h3><p>{goodHeaders} good • {reviewHeaders} review • {headers.filter(h=>h.rating==="Missing").length} missing</p></article>
     <article className="card"><div className="line"><h3>TLS Analysis</h3><span className={tls?.authorized?"ok":"fail"}>{tls?.authorized?"Verified":"Check needed"}</span></div>{tls&&<div className="details"><p><b>Protocol:</b> {tls.protocol}</p><p><b>Cipher:</b> {tls.cipher}</p><p><b>Subject:</b> {tls.subject}</p><p><b>Issuer:</b> {tls.issuer}</p><p><b>Valid to:</b> {fmt(tls.validTo)}</p><p><b>Days remaining:</b> {tls.daysRemaining}</p></div>}</article>
     <article className="card"><div className="line"><h3>HTTPS Redirect</h3><span className={redirect?.usesHttps?"ok":"fail"}>{redirect?.usesHttps?"HTTPS enforced":"Check needed"}</span></div>{redirect&&<div className="details"><p><b>Final URL:</b> {redirect.finalUrl}</p><p><b>Final status:</b> {redirect.finalStatus}</p></div>}</article>

     <article className="card"><h3>Recommendations</h3>{recs.length?recs.map((x,i)=><div className="rec" key={i}><b>{i+1}</b><span>{x}</span></div>):<p>No recommendations generated.</p>}</article>
   </section>}
 </section></main>
}