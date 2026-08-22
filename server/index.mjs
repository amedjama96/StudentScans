import express from "express";
import cors from "cors";
import tls from "tls";

const app = express();
app.use(cors());

const clean = (v="") => v.trim().replace(/^https?:\/\//i,"").replace(/\/.*$/,"").toLowerCase();

async function doh(name,type){
  const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, {signal:AbortSignal.timeout(8000)});
  if(!r.ok) throw new Error();
  return r.json();
}

function txtRecords(data){
  return (data.Answer ?? []).filter(x=>x.type===16).map(x=>String(x.data).replace(/^"|"$/g,""));
}

function parseSpf(record=""){
  if(!record) return {record:"",rating:"Missing",allPolicy:"Missing",includeCount:0,redirect:"",usesPtr:false,findings:[]};
  const terms=record.trim().split(/\s+/);
  const all=terms.find(t=>/^(?:[+?~-])?all$/i.test(t))||"";
  const includeCount=terms.filter(t=>t.toLowerCase().startsWith("include:")).length;
  const redirect=terms.find(t=>t.toLowerCase().startsWith("redirect="))||"";
  const usesPtr=terms.some(t=>/^(?:[+?~-])?ptr(?::|$)/i.test(t));
  let rating="Review", allPolicy="Unknown"; const findings=[];

  if(all==="-all"){rating="Good";allPolicy="Fail (-all)";}
  else if(all==="~all"){allPolicy="SoftFail (~all)";findings.push("SPF ends with ~all (SoftFail).");}
  else if(all==="?all"){allPolicy="Neutral (?all)";findings.push("SPF ends with ?all (Neutral).");}
  else if(all==="+all"||all==="all"){rating="Weak";allPolicy="Pass all (+all)";findings.push("SPF allows all senders with +all.");}
  else findings.push("No explicit all mechanism detected.");

  if(usesPtr) findings.push("SPF uses the deprecated ptr mechanism.");
  if(includeCount>8) findings.push("Many include mechanisms may approach the SPF DNS lookup limit.");

  return {record,rating,allPolicy,includeCount,redirect,usesPtr,findings};
}

function parseDmarc(record=""){
  if(!record) return {record:"",rating:"Missing",policy:"Missing",subdomainPolicy:"",pct:null,rua:"",ruf:"",adkim:"",aspf:"",findings:[]};

  const tags={};
  for(const part of record.split(";").map(x=>x.trim()).filter(Boolean)){
    const i=part.indexOf("=");
    if(i>0) tags[part.slice(0,i).trim().toLowerCase()]=part.slice(i+1).trim();
  }

  const policy=(tags.p||"").toLowerCase();
  const subdomainPolicy=(tags.sp||"").toLowerCase();
  const pct=tags.pct ? Number(tags.pct) : 100;
  const rua=tags.rua||"", ruf=tags.ruf||"";
  const adkim=(tags.adkim||"r").toLowerCase();
  const aspf=(tags.aspf||"r").toLowerCase();
  let rating="Review"; const findings=[];

  if(policy==="reject") rating="Good";
  else if(policy==="quarantine") findings.push("DMARC uses quarantine rather than reject.");
  else if(policy==="none") findings.push("DMARC is monitoring only with p=none.");
  else findings.push("DMARC policy could not be interpreted.");

  if(pct<100) findings.push(`DMARC applies to only ${pct}% of messages.`);
  if(!rua) findings.push("No aggregate reporting address (rua) found.");
  if(subdomainPolicy==="none") findings.push("Subdomains use p=none.");
  if(adkim==="r") findings.push("DKIM alignment is relaxed (adkim=r).");
  if(aspf==="r") findings.push("SPF alignment is relaxed (aspf=r).");

  return {record,rating,policy,subdomainPolicy,pct,rua,ruf,adkim,aspf,findings};
}

function analyzeHeaders(headers){
  const names=["content-security-policy","strict-transport-security","x-frame-options","x-content-type-options"];
  return names.map(key=>{
    const value=headers.get(key)||"";
    let rating=value?"Good":"Missing"; const findings=[];
    if(key==="content-security-policy"&&value){
      if(value.includes("'unsafe-inline'")) findings.push("Allows 'unsafe-inline'.");
      if(value.includes("'unsafe-eval'")) findings.push("Allows 'unsafe-eval'.");
    }
    if(key==="strict-transport-security"&&value){
      const m=value.match(/max-age\s*=\s*(\d+)/i);
      if(m&&Number(m[1])<15552000) findings.push("HSTS max-age is shorter than 180 days.");
    }
    if(key==="x-frame-options"&&value&&!["DENY","SAMEORIGIN"].includes(value.trim().toUpperCase())) findings.push("Unexpected X-Frame-Options value.");
    if(key==="x-content-type-options"&&value.trim().toLowerCase()!=="nosniff") findings.push("Expected nosniff.");
    if(findings.length) rating="Review";
    return {name:key.split("-").map(x=>x[0].toUpperCase()+x.slice(1)).join("-"),value,found:Boolean(value),rating,findings};
  });
}

app.get("/api/email-security", async (req,res)=>{
  const domain=clean(String(req.query.domain||""));
  if(!domain.includes(".")) return res.status(400).json({error:"Invalid domain"});
  try{
    const [txt,dm]=await Promise.all([doh(domain,"TXT"),doh(`_dmarc.${domain}`,"TXT")]);
    const spfRecord=txtRecords(txt).find(x=>x.toLowerCase().startsWith("v=spf1"))||"";
    const dmarcRecord=txtRecords(dm).find(x=>x.toLowerCase().startsWith("v=dmarc1"))||"";
    res.json({spf:parseSpf(spfRecord),dmarc:parseDmarc(dmarcRecord)});
  }catch{res.status(502).json({error:"Email security analysis failed"});}
});

app.get("/api/headers", async (req,res)=>{
  const domain=clean(String(req.query.domain||""));
  try{
    const r=await fetch(`https://${domain}`,{redirect:"follow",signal:AbortSignal.timeout(8000)});
    res.json({headers:analyzeHeaders(r.headers)});
  }catch{res.status(502).json({error:"Header analysis failed"});}
});

app.get("/api/tls",(req,res)=>{
  const domain=clean(String(req.query.domain||""));
  const socket=tls.connect({host:domain,port:443,servername:domain,rejectUnauthorized:false,timeout:8000},()=>{
    try{
      const cert=socket.getPeerCertificate(), cipher=socket.getCipher(), protocol=socket.getProtocol();
      const validTo=new Date(cert.valid_to);
      res.json({
        protocol,cipher:cipher?.standardName||cipher?.name||"Unknown",
        subject:cert.subject?.CN||domain,issuer:cert.issuer?.O||cert.issuer?.CN||"Unknown",
        validTo:validTo.toISOString(),daysRemaining:Math.ceil((validTo-Date.now())/86400000),
        authorized:socket.authorized
      });
      socket.end();
    }catch{socket.end();res.status(502).json({error:"TLS analysis failed"});}
  });
  socket.on("error",()=>{if(!res.headersSent)res.status(502).json({error:"TLS connection failed"});});
});

app.get("/api/redirect",async(req,res)=>{
  const domain=clean(String(req.query.domain||""));
  try{
    const r=await fetch(`http://${domain}`,{redirect:"follow",signal:AbortSignal.timeout(8000)});
    res.json({finalUrl:r.url,finalStatus:r.status,usesHttps:r.url.startsWith("https://")});
  }catch{res.status(502).json({error:"Redirect analysis failed"});}
});

app.listen(3001,()=>console.log("StudentScans backend running on http://localhost:3001"));
