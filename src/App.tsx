
import { useState } from "react";
export default function App(){
 const [domain,setDomain]=useState("");
 const [message,setMessage]=useState("");
 function startScan(){
  if(!domain.trim()){setMessage("Please enter a domain.");return;}
  setMessage(`Ready to scan ${domain} (coming in Day 4).`);
 }
 return <main className="page"><section className="hero">
 <span className="badge">Student project • Day 3</span>
 <h1>StudentScans</h1>
 <p className="lead">Enter a website to prepare for a basic security scan.</p>
 <input className="domain-input" placeholder="example.com" value={domain} onChange={e=>setDomain(e.target.value)}/>
 <button onClick={startScan}>Start scan</button>
 {message&&<p className="status">{message}</p>}
 </section></main>
}
