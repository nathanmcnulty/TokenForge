// Actual HTTP/1.1-over-TLS engine. Only branded loopback fixture contexts work.
// Service execution is unconditionally disabled; no credential/env reader exists.
import https from 'node:https';
import tls from 'node:tls';
import fs from 'node:fs';
import {createHash,X509Certificate} from 'node:crypto';
import {fail,keys} from '../offline/TokenForgeOfflineSchema.mjs';
import {assertWithinDeadline} from '../offline/TokenForgeOfflineClock.mjs';
import {validateRequest} from '../offline/TokenForgeArtifactProtocol.mjs';
const states=new WeakMap();
const hash=b=>createHash('sha256').update(b).digest('hex');
export const APPROVED_LOCAL_RUNTIME=Object.freeze({version:'24.18.1',sha256:'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a'});
const runtime=Object.freeze({version:process.versions.node,sha256:hash(fs.readFileSync(process.execPath))});
const profileHash=hash(Buffer.concat([
  fs.readFileSync(new URL(import.meta.url)),
  fs.readFileSync(new URL('../offline/TokenForgeArtifactProtocol.mjs',import.meta.url)),
  fs.readFileSync(new URL('../offline/TokenForgeOfflineSchema.mjs',import.meta.url)),
]));
export const WIRE_LIMITS=Object.freeze({headerBytes:16384,headerCount:64,headerValue:4096,requestMs:10000});
export function localRuntimeIdentity(){return {...runtime};}
export function createServiceTransport(){fail('ServiceModeDisabled');}
export function createLocalTlsTransport(options) {
  keys(options,['port','ca']);
  if(process.platform!=='linux'||process.arch!=='x64'||runtime.version!==APPROVED_LOCAL_RUNTIME.version||runtime.sha256!==APPROVED_LOCAL_RUNTIME.sha256||!Number.isInteger(options.port)||options.port<1||options.port>65535||!Buffer.isBuffer(options.ca)||!options.ca.length||options.ca.length>16384) fail('LocalTlsContextRefused');
  try{new X509Certificate(options.ca);}catch{fail('LocalTlsContextRefused');}
  const ca=Buffer.from(options.ca),state={port:options.port,ca,log:[],used:new Set(),name:null,busy:false,cancelled:false,abort:null};
  const binding=Object.freeze({kind:'LocalTls',authoritySha256:hash(Buffer.concat([ca,Buffer.from(`127.0.0.1:${state.port}:tokenforge.fixture.invalid`)])),profileSha256:profileHash,runtimeSha256:runtime.sha256});
  state.binding=binding;
  const handle=Object.freeze({kind:'LocalTlsFixtureTransport',transcript:()=>structuredClone(state.log),cancel(){state.cancelled=true;state.abort?.();}});
  states.set(handle,state);return handle;
}
export function localTlsBinding(handle){return states.get(handle)?.binding;}
const DIAGNOSTIC_HEADERS=new Set(['date','connection','server','etag','last-modified','cache-control','vary','strict-transport-security','content-security-policy','referrer-policy','content-md5','x-content-type-options','x-frame-options']);
// Reject ambiguity before projecting explicitly non-authoritative diagnostics.
function selectedHeaders(response,op,cap) {
  const raw=response.rawHeaders;
  if(raw.length>WIRE_LIMITS.headerCount*2) fail('LocalTlsHeadersRefused');
  let bytes=0;const headers={};
  for(let i=0;i<raw.length;i+=2) {
    const name=raw[i].toLowerCase(),value=raw[i+1];bytes+=Buffer.byteLength(raw[i])+Buffer.byteLength(value)+4;
    if(Object.hasOwn(headers,name)||value.length>WIRE_LIMITS.headerValue||/[\r\n\x00]/.test(value)) fail('LocalTlsHeadersRefused');
    headers[name]=value;
  }
  if(bytes>WIRE_LIMITS.headerBytes||headers['content-encoding']&&headers['content-encoding']!=='identity') fail('LocalTlsHeadersRefused');
  if(headers['transfer-encoding']&&(headers['transfer-encoding']!=='chunked'||headers['content-length']!==undefined)) fail('LocalTlsHeadersRefused');
  if(headers['content-length']!==undefined&&(!/^(?:0|[1-9][0-9]*)$/.test(headers['content-length'])||BigInt(headers['content-length'])>BigInt(cap))) fail('LocalTlsBodyRefused');
  const out={};
  for(const [name,value] of Object.entries(headers)) {
    if(['content-length','location','link'].includes(name)) out[name]=value;
    else if(name==='content-type') out[name]=value.split(';')[0].trim().toLowerCase();
    else if(['transfer-encoding','content-encoding'].includes(name)||DIAGNOSTIC_HEADERS.has(name)||/^x-(?:github|ratelimit|ms)-[a-z0-9-]+$/.test(name)||/^access-control-[a-z0-9-]+$/.test(name)) continue;
    else fail('LocalTlsHeadersRefused');
  }
  return out;
}
export async function exchangeLocalTls(handle,request,j,capabilities) {
  const state=states.get(handle);if(!state) fail('LocalTlsContextRefused');
  if(state.busy||state.cancelled) fail('LocalTlsCancelled');
  validateRequest(request,j,capabilities);
  const time=assertWithinDeadline(undefined,j),entry=j.ledger.at(-1),ordinal=j.ledger.length;
  const cap=request.op==='Download'?65536:131072;
  if(!entry||entry.op!==request.op||entry.charge!==request.body.length+cap||ordinal>12||state.used.has(ordinal)||state.name!==null&&state.name!==j.name) fail('LocalTlsChargeRefused');
  state.name=j.name;state.used.add(ordinal);state.busy=true;
  const exchangeWall=Math.min(time.wall+WIRE_LIMITS.requestMs,j.deadline),exchangeMono=Math.min(time.mono+WIRE_LIMITS.requestMs,j.deadlineMono);
  function remainingTime(){const now=assertWithinDeadline(undefined,j),left=Math.min(exchangeWall-now.wall,exchangeMono-now.mono);if(left<=0)fail('LocalTlsExchangeExpired');return left;}
  const u=new URL(request.url),headers={...request.headers,host:u.hostname,connection:'close','accept-encoding':'identity'};
  if(request.credentialRole==='Runtime')headers.authorization='Bearer TF_FIXTURE_RUNTIME_ONLY';
  else if(request.credentialRole==='Read')headers.authorization='Bearer TF_FIXTURE_READ_ONLY';
  // Every call owns a fresh agent and one request. Never use globalAgent,
  // inherited proxy configuration, URL redirects, or any retry/resend path.
  const agent=new https.Agent({keepAlive:false,maxSockets:1,maxTotalSockets:1});
  let req,socket,timer,response,selected,chunks=[],length=0,complete=false,error=false;
  const log={ordinal,op:request.op,method:request.method,credentialRole:request.credentialRole,requestBytes:request.body.length,requestSha256:hash(request.body),outcome:'Unknown'};
  state.log.push(log);
  try {
    return await new Promise((resolve,reject)=>{
      let settled=false,requestClosed=false,socketClosed=false;
      const maybeFinish=()=>{if(!req||requestClosed&&(!socket||socketClosed))finish();};
      const rejectStatic=()=>{if(settled)return;error=true;req?.destroy();socket?.destroy();maybeFinish();};
      function finish(){
        if(settled)return;settled=true;clearTimeout(timer);agent.destroy();state.abort=null;
        if(error||!complete){reject(new Error('LocalTlsExchangeUnknown'));return;}
        try{remainingTime();const bytes=Buffer.concat(chunks,length);selected['content-length']=String(length);log.outcome='Complete';log.responseBytes=length;resolve({status:response.statusCode,headers:selected,body:bytes});}
        catch{reject(new Error('LocalTlsExchangeUnknown'));}
      }
      state.abort=rejectStatic;
      try {
        timer=setTimeout(rejectStatic,remainingTime());
        req=https.request({hostname:'127.0.0.1',port:state.port,servername:'tokenforge.fixture.invalid',method:request.method,path:u.pathname+u.search,
          headers,agent,ca:state.ca,rejectUnauthorized:true,checkServerIdentity:tls.checkServerIdentity,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',
          maxHeaderSize:WIRE_LIMITS.headerBytes,insecureHTTPParser:false,lookup(){throw new Error('LocalTlsDnsRefused');}},res=>{
          response=res;
          try{selected=selectedHeaders(res,request.op,cap);}catch{rejectStatic();return;}
          res.on('data',chunk=>{length+=chunk.length;log.responseEntityBytesObserved=length;if(length>cap){rejectStatic();return;}chunks.push(Buffer.from(chunk));});
          res.on('aborted',rejectStatic);res.on('error',rejectStatic);
          res.on('end',()=>{if(!res.complete||res.rawTrailers.length){rejectStatic();return;}complete=true;});
        });
        req.maxHeadersCount=0;
        req.on('socket',s=>{socket=s;s.once('close',()=>{socketClosed=true;maybeFinish();});});
        req.once('close',()=>{requestClosed=true;maybeFinish();});
        req.once('error',rejectStatic);
        req.end(Buffer.from(request.body));
      } catch {rejectStatic();}
    });
  } finally {clearTimeout(timer);agent.destroy();state.abort=null;state.busy=false;}
}
