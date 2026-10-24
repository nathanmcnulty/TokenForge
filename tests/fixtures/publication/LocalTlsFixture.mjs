// Independent controlled HTTPS backend. Generated private keys stay in test temp.
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
export const CONTEXT={repository:'synthetic/tokenforge',repositoryId:'1',workflowId:'2',runId:'3',attempt:'1',source:'a'.repeat(40)};
export const ARTIFACT_ID='9007199254740993';
const cap=kind=>`https://${kind==='Blob'?'blob':'download'}.fixture.invalid/${kind==='Blob'?'container':'artifact'}/original.zip?sv=2023-11-03&spr=https&sp=${kind==='Blob'?'cw':'r'}&se=2030-01-02T00%3A00%3A00Z&sr=b&sig=fixture%2Bonly%2f%3D%3D`;
const hash=b=>createHash('sha256').update(b).digest('hex');
export function tlsMaterial(parent,name='tokenforge.fixture.invalid') {
  const dir=fs.mkdtempSync(path.join(parent,'tls-'));fs.chmodSync(dir,0o700);
  const key=path.join(dir,'key.pem'),cert=path.join(dir,'cert.pem');
  execFileSync('/bin/openssl',['req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1','-subj',`/CN=${name}`,'-addext',`subjectAltName=DNS:${name}`,'-keyout',key,'-out',cert],{stdio:'ignore',timeout:10000});
  fs.chmodSync(key,0o600);fs.chmodSync(cert,0o600);return {key:fs.readFileSync(key),cert:fs.readFileSync(cert)};
}
export async function startTlsFixture(material,{fault,chunked=false,extras=false,expiryDelayOp=null}={}) {
  const state={records:[],effects:[],violations:[],connections:0,body:null,name:null,finalized:false,requests:0,expiry:Date.now()+1000};
  const sockets=new Set(),ids=new WeakMap();
  const server=https.createServer({...material,minVersion:'TLSv1.3',maxVersion:'TLSv1.3'},(req,res)=>{
    const host=req.headers.host,url=new URL(req.url,'https://'+host);let op;
    if(host==='results.fixture.invalid')op=url.pathname.endsWith('/CreateArtifact')?'Create':url.pathname.endsWith('/FinalizeArtifact')?'Finalize':null;
    else if(host==='blob.fixture.invalid')op=url.searchParams.get('comp')==='block'?'Block':url.searchParams.get('comp')==='blocklist'?'Commit':null;
    else if(host==='download.fixture.invalid')op='Download';
    else if(host==='api.fixture.invalid')op=url.pathname.endsWith('/zip')?'Redirect':url.pathname.endsWith('/artifacts')?'List':url.pathname.includes('/artifacts/')?'Artifact':url.pathname.includes('/runs/')?'Run':'Repository';
    state.requests++;
    const record={op,method:req.method,path:url.pathname,query:url.search,authorization:req.headers.authorization??null,body:null,connection:ids.get(req.socket),tls:req.socket.getProtocol(),remote:req.socket.remoteAddress};state.records.push(record);
    if(!op){state.violations.push('UnknownRoute');req.socket.destroy();return;}
    if(fault?.op===op&&fault.mode==='dropBeforeBody'){req.socket.destroy();return;}
    const chunks=[];req.on('data',b=>chunks.push(Buffer.from(b)));req.on('error',()=>{});
    req.on('end',async()=>{
      const body=Buffer.concat(chunks);record.body=body;
      const wantAuth=['Create','Finalize'].includes(op)?'Bearer TF_FIXTURE_RUNTIME_ONLY':['Repository','Run','Artifact','Redirect','List'].includes(op)?'Bearer TF_FIXTURE_READ_ONLY':null;
      const wantMethod=['Create','Finalize'].includes(op)?'POST':['Block','Commit'].includes(op)?'PUT':'GET';
      if(record.authorization!==wantAuth||req.method!==wantMethod||req.headers.connection!=='close'||req.headers['accept-encoding']!=='identity'||req.headers.cookie||req.headers['proxy-authorization']||Number(req.headers['content-length'])!==body.length){state.violations.push('WirePolicy');res.writeHead(400);res.end();return;}
      let output,wire;
      try{
        if(op==='Create'){
          const m=JSON.parse(body);if(m.version!==4||m.workflow_run_backend_id!=='11111111-1111-4111-8111-111111111111'||m.workflow_job_run_backend_id!=='22222222-2222-4222-8222-222222222222')throw Error();
          state.name=m.name;state.effects.push(op);output={ok:true,signed_upload_url:cap('Blob')};
        }else if(op==='Block'){state.body=Buffer.from(body);state.effects.push(op);}
        else if(op==='Commit'){
          const expected=`<?xml version="1.0" encoding="utf-8"?><BlockList><Uncommitted>${Buffer.from(state.name).toString('base64')}</Uncommitted></BlockList>`;
          if(body.toString()!==expected)throw Error();state.effects.push(op);
        }else if(op==='Finalize'){
          const m=JSON.parse(body);if(m.name!==state.name||m.size!==String(state.body.length)||m.hash!=='sha256:'+hash(state.body))throw Error();state.finalized=true;state.effects.push(op);output={ok:true,artifact_id:ARTIFACT_ID};
        }
        const artifact=`{"id":${ARTIFACT_ID},"name":${JSON.stringify(state.name)},"size_in_bytes":${state.body?.length??0},"digest":"sha256:${hash(state.body??Buffer.alloc(0))}","expired":false,${expiryDelayOp?`"expires_at":"${new Date(state.expiry).toISOString()}",`:""}"workflow_run":{"id":3,"repository_id":1,"head_sha":"${CONTEXT.source}"${extras?',"head_branch":"synthetic","head_repository_id":1':''}}${extras?',"node_id":"synthetic","created_at":"2026-01-01T00:00:00Z","url":"https://ignored.invalid"':''}}`;
        if(op==='Repository')wire=`{"id":1,"full_name":"synthetic/tokenforge"${extras?',"private":false,"description":"synthetic fixture"':''}}`;
        else if(op==='Run')wire=`{"id":3,"run_attempt":1,"workflow_id":2,"head_sha":"${CONTEXT.source}","repository":{"id":1,"full_name":"synthetic/tokenforge"${extras?',"private":false':''}}${extras?',"status":"in_progress","event":"workflow_dispatch"':''}}`;
        else if(op==='Artifact')wire=artifact;
        else if(op==='List')wire=`{"total_count":${state.finalized?1:0},"artifacts":[${state.finalized?artifact:''}]}`;
        else if(output)wire=JSON.stringify(output);
      }catch{state.violations.push('BodyPolicy');res.writeHead(400);res.end();return;}
      if(fault?.op===op){
        const mode=fault.mode;
        if(mode==='dropAck'){req.socket.destroy();return;}
        if(mode==='holdHeaders')return;
        if(mode==='headerOverflow'){req.socket.end('HTTP/1.1 200 OK\r\nX-Ms-Request-Id: '+ 'x'.repeat(17000)+'\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');return;}
        if(mode==='duplicateLength'||mode==='ambiguousLength'){req.socket.end(`HTTP/1.1 200 OK\r\nContent-Length: 2\r\n${mode==='duplicateLength'?'Content-Length: 2':'Transfer-Encoding: chunked'}\r\nConnection: close\r\n\r\n{}`);return;}
        if(mode==='duplicateLocation'){req.socket.end('HTTP/1.1 302 Found\r\nLocation: '+cap('Download')+'\r\nLocation: https://unapproved.invalid\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');return;}
        if(mode==='oversizeDeclared'){res.writeHead(200,{'content-type':'application/json','content-length':'131073'});res.flushHeaders();return;}
        if(mode==='oversizeChunked'){res.writeHead(200,{'content-type':'application/json'});res.end(Buffer.alloc(131073));return;}
        if(mode==='partial'){res.writeHead(200,{'content-type':'application/json','content-length':String(Buffer.byteLength(wire)+10)});res.end(wire);return;}
        if(mode==='holdBody'){res.writeHead(200,{'content-type':'application/json','content-length':String(Buffer.byteLength(wire))});res.write(wire.slice(0,1));return;}
        if(mode==='encoding'){res.writeHead(200,{'content-type':'application/json','content-encoding':'gzip'});res.end(wire);return;}
        if(mode==='badJson'){res.writeHead(200,{'content-type':'application/json'});res.end('{"secret":"SYNTHETIC_RESPONSE_SECRET\\q"}');return;}
        if(mode==='redirect'){res.writeHead(302,{location:cap('Download'),'content-length':'0'});res.end();return;}
        if(mode==='foreignRedirect'){res.writeHead(302,{location:'https://unapproved.invalid/SYNTHETIC_RESPONSE_SECRET','content-length':'0'});res.end();return;}
      }
      if(expiryDelayOp===op&&(op!=='Run'||state.records.filter(x=>x.op==='Run').length===2))await new Promise(r=>setTimeout(r,Math.max(0,state.expiry-Date.now()+100)));
      if(op==='Block'||op==='Commit'){res.writeHead(201,{'content-length':'0','x-ms-request-id':'synthetic'});res.end();}
      else if(op==='Redirect'){res.writeHead(302,{location:cap('Download'),'content-length':'0'});res.end();}
      else if(op==='Download'){res.writeHead(200,{'content-type':'application/octet-stream',...(chunked?{}:{'content-length':String(state.body.length)})});res.end(state.body);}
      else {res.writeHead(200,{'content-type':'application/json; charset=utf-8',...(chunked?{}:{'content-length':String(Buffer.byteLength(wire))}),'cache-control':'no-store','x-github-request-id':'synthetic'});res.end(wire);}
    });
  });
  server.on('secureConnection',socket=>{state.connections++;ids.set(socket,state.connections);});
  server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  server.on('tlsClientError',()=>{});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  return {port:server.address().port,state,async close(){for(const s of sockets)s.destroy();await new Promise(resolve=>server.close(resolve));}};
}
