// Linux-only bounded core: recording fake or branded dummy-only loopback TLS.
// No runner credentials, external service, signing or policy emission.
import fs from 'node:fs';
import path from 'node:path';
import {createHash, randomBytes} from 'node:crypto';
import {object, fail, keys, id, context, strictJson} from './TokenForgeOfflineSchema.mjs';
import {createFakeClock, clockNow, assertWithinDeadline} from './TokenForgeOfflineClock.mjs';
export {createFakeClock};
import {localTlsBinding,localRuntimeIdentity,exchangeLocalTls} from '../transport/TokenForgeLocalTlsTransport.mjs';
import {PROTOCOL, ROLES, requestBody, buildRequest, validateRequest, parseResponse, fixtureCapability} from './TokenForgeArtifactProtocol.mjs';

const PROFILE = 'CanonicalStoredOriginalZipV1';
const NAMES = ['coverage.json','flows.json','manifest.json','recipe.json','review.md','scopes.json','validation.json'];
export const LIMITS = Object.freeze({archive:65536, attempts:12, mutations:4, reads:8,
  totalBytes:2097152, controlRequest:8192, controlResponse:131072, deadlineMs:180000, requestMs:10000});
const MUTATIONS = ['Create','Block','Commit','Finalize'];
const READS = ['Repository','Run','Artifact','Redirect','Download','List'];
const ROLE=ROLES;
const INTENT = {Create:'CreateIntent',Block:'BlockIntent',Commit:'CommitIntent',Finalize:'FinalizeIntent'};
const ACK = {Create:'Created',Block:'BlockAck',Commit:'Committed',Finalize:'Finalized'};
const UNKNOWN = {Create:'CreateUnknown',Block:'UploadUnknown',Commit:'UploadUnknown',Finalize:'FinalizeUnknown'};
const STATES = ['Prepared',...Object.values(INTENT),...Object.values(ACK),'CreateUnknown','UploadUnknown',
  'FinalizeUnknown','ObserveIntent','ObservationUnknown','Observed','Refused'];
const transports = new WeakMap();
const hash = b => createHash('sha256').update(b).digest('hex');
const engineSha256=hash(Buffer.concat([fs.readFileSync(new URL(import.meta.url)),fs.readFileSync(new URL('./TokenForgeOfflineClock.mjs',import.meta.url)),fs.readFileSync(new URL('./TokenForgeArtifactProtocol.mjs',import.meta.url)),fs.readFileSync(new URL('./TokenForgeOfflineSchema.mjs',import.meta.url))]));

function crc32(bytes) {let c=0xffffffff;for(const b of bytes){c^=b;for(let j=0;j<8;j++) c=(c>>>1)^((c&1)?0xedb88320:0);}return (c^0xffffffff)>>>0;}
// Read-only structural profile check. No archive formatter/replacement path.
// Business schemas/privacy/semantic approval remain the existing sealer's job.
export function assertCanonicalOriginal(input) {
  if(!Buffer.isBuffer(input) || input.length<22 || input.length>LIMITS.archive) fail('ArchiveRefused');
  const b=Buffer.from(input), records=[]; let p=0;
  const u16=()=>{if(p+2>b.length) fail('ArchiveRefused');const n=b.readUInt16LE(p);p+=2;return n;};
  const u32=()=>{if(p+4>b.length) fail('ArchiveRefused');const n=b.readUInt32LE(p);p+=4;return n;};
  const expect=(n,v)=>{if(n!==v) fail('ArchiveRefused');};
  const name=(n,s)=>{const v=Buffer.from(s,'ascii');expect(n,v.length);if(!b.subarray(p,p+n).equals(v)) fail('ArchiveRefused');p+=n;};
  try {
    for(const n of NAMES) {
      const offset=p;expect(u32(),0x04034b50);for(const v of [20,2048,0,0,33]) expect(u16(),v);
      const crc=u32(),size=u32();expect(u32(),size);const length=u16();expect(u16(),0);name(length,n);
      if(!size || p+size>b.length) fail('ArchiveRefused');const bytes=b.subarray(p,p+size);p+=size;expect(crc32(bytes),crc);
      const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
      if(n.endsWith('.json')) strictJson(bytes);
      records.push({n,crc,size,offset});
    }
    const central=p;
    for(const r of records) {
      expect(u32(),0x02014b50);for(const v of [788,20,2048,0,0,33]) expect(u16(),v);
      expect(u32(),r.crc);expect(u32(),r.size);expect(u32(),r.size);const length=u16();
      for(let j=0;j<4;j++) expect(u16(),0);expect(u32(),0);expect(u32(),r.offset);name(length,r.n);
    }
    const centralSize=p-central;expect(u32(),0x06054b50);
    for(const v of [0,0,7,7]) expect(u16(),v);expect(u32(),centralSize);expect(u32(),central);expect(u16(),0);expect(p,b.length);
  } catch {fail('ArchiveRefused');}
  return PROFILE;
}

// Deliberately abstract messages, not production HTTP/protocol serialization.
// The fixed fixture credentials are opaque object identities, never strings/JWTs.
export function createFakeTransport(options={}, clock) {
  if(clock!==undefined && !isFakeClock(clock)) fail('ClockRefused');
  const allowed=['faults','transform','metadataChange','listMode','credentialFault','delayMs','responseOversize','serializationFault','responseFault'];
  if(!object(options)||Object.keys(options).some(k=>!allowed.includes(k))) fail('FakeConfigurationRefused');
  let o;try{o=structuredClone(options);}catch{fail('FakeConfigurationRefused');}
  if(o.delayMs!==undefined && (!Number.isSafeInteger(o.delayMs)||o.delayMs<0||!clock)) fail('FakeConfigurationRefused');
  const faults=o.faults??{};
  for(const [op,v] of Object.entries(faults)) if(!ROLE[op] || !['before','after','interruptBefore','interruptAfter','cancelBefore','cancelAfter'].includes(v)) fail('FakeConfigurationRefused');
  if(o.transform && !['header','trailer','wrapper'].includes(o.transform)) fail('FakeConfigurationRefused');
  if(o.listMode && !['zero','multiple','paginated'].includes(o.listMode)) fail('FakeConfigurationRefused');
  for(const f of ['serializationFault','responseFault']) if(o[f]) {keys(o[f],['op','kind']);if(!Object.hasOwn(ROLE,o[f].op)||typeof o[f].kind!=='string') fail('FakeConfigurationRefused');}
  const state={options:o,clock,credentials:Object.fromEntries(['Runtime','Blob','Read','Download'].map(r=>[r,Object.freeze({})])),log:[],calls:{},candidate:null,block:null,committed:false,artifact:false};
  const handle=Object.freeze({kind:'NetworkDisabledFakeTransport',
    transcript:()=>structuredClone(state.log), archivedBytes:()=>state.candidate?Buffer.from(state.candidate):null});
  transports.set(handle,state);return handle;
}
class Interrupted extends Error {}
function fakeExchange(state,request,credential,transaction) {
  const {op,body}=request;
  validateRequest(request,transaction,{original:op==='Block'?state.expectedOriginal:undefined,uploadUrl:fixtureCapability('Blob'),downloadUrl:fixtureCapability('Download')});
  const role=Object.keys(state.credentials).find(r=>state.credentials[r]===credential);
  const parsedUrl=new URL(request.url);
  const entry={op,credentialRole:role??'Invalid',method:request.method,origin:parsedUrl.origin,path:parsedUrl.pathname,requestBytes:body.length,requestSha256:hash(body)};
  assertWithinDeadline(state.clock,transaction);
  state.calls[op]=(state.calls[op]??0)+1;state.log.push(entry);
  if(role!==ROLE[op]) fail('CredentialRefused');
  if(state.options.delayMs) state.clock.advance(state.options.delayMs);
  const fault=state.options.faults?.[op];
  if(fault==='interruptBefore') throw new Interrupted();
  if(fault==='before'||fault==='cancelBefore') fail('SYNTHETIC_SECRET_ERROR');
  const info=()=>({id:PROTOCOL.artifactId,name:state.origin.name,context:structuredClone(state.origin.context),
    size:state.origin.size,digest:`sha256:${state.origin.hash}`,expired:false});
  let response;
  switch(op) {
    case 'Create': {
      if(state.created) fail('FakeReservationExists');const data=strictJson(body);
      keys(data,['workflow_run_backend_id','workflow_job_run_backend_id','name','version']);
      if(data.workflow_run_backend_id!==PROTOCOL.runBackend||data.workflow_job_run_backend_id!==PROTOCOL.jobBackend||data.name!==transaction.name||data.version!==4) fail('FakeWireRefused');
      state.origin=structuredClone({name:data.name,context:transaction.context,size:transaction.size,hash:transaction.hash});state.created=true;response={ok:true,signed_upload_url:fixtureCapability('Blob')};break;
    }
    case 'Block':if(!state.created) fail('FakeSequence');state.block=Buffer.from(body);response={ok:true};break;
    case 'Commit':if(!state.block) fail('FakeSequence');state.committed=true;response={ok:true};break;
    case 'Finalize': {
      if(!state.committed) fail('FakeSequence');const data=strictJson(body);
      keys(data,['workflow_run_backend_id','workflow_job_run_backend_id','name','size','hash']);
      if(data.name!==state.origin.name||data.workflow_run_backend_id!==PROTOCOL.runBackend||data.workflow_job_run_backend_id!==PROTOCOL.jobBackend||data.size!==String(state.block.length)||data.hash!==`sha256:${hash(state.block)}`) fail('FakeWireRefused');
      state.candidate=Buffer.from(state.block);
      if(state.options.transform==='header') state.candidate[10]^=1;
      if(state.options.transform==='trailer') state.candidate=Buffer.concat([state.candidate,Buffer.from('extra')]);
      if(state.options.transform==='wrapper') state.candidate=Buffer.concat([Buffer.from('wrapper'),state.candidate]);
      state.artifact=true;response={ok:true,artifact_id:info().id};break;
    }
    case 'Repository':response={repository:state.origin.context.repository,id:state.origin.context.repositoryId};break;
    case 'Run':response=structuredClone(state.origin.context);break;
    case 'Artifact':if(!state.artifact) fail('NotFound');response=info();
      if(state.options.metadataChange && state.calls.Artifact>1) response={...response,...state.options.metadataChange};break;
    case 'Redirect':response={capability:fixtureCapability('Download')};break;
    case 'Download':if(!state.artifact) fail('NotFound');response=Buffer.from(state.candidate);break;
    case 'List':response={items:!state.artifact||state.options.listMode==='zero'?[]:[info()],hasMore:state.options.listMode==='paginated'};
      if(state.options.listMode==='multiple') response.items.push(info());break;
    default:fail('OperationRefused');
  }
  if(fault==='interruptAfter') throw new Interrupted();
  if(fault==='after'||fault==='cancelAfter') fail('SYNTHETIC_SECRET_ERROR');
  let envelope;
  if(op==='Block'||op==='Commit') envelope={status:201,headers:{'content-length':'0'},body:Buffer.alloc(0)};
  else if(op==='Redirect') envelope={status:302,headers:{location:response.capability,'content-length':'0'},body:Buffer.alloc(0)};
  else if(op==='Download') envelope={status:200,headers:{'content-type':'application/zip','content-length':String(response.length)},body:response};
  else {
    const wireArtifact=m=>({id:BigInt(m.id),name:m.name,size_in_bytes:BigInt(m.size),digest:m.digest,expired:m.expired,workflow_run:{id:BigInt(m.context.runId),repository_id:BigInt(m.context.repositoryId),head_sha:m.context.source}});
    if(op==='Repository') response={id:BigInt(response.id),full_name:response.repository};
    if(op==='Run') response={id:BigInt(response.runId),run_attempt:BigInt(response.attempt),workflow_id:BigInt(response.workflowId),head_sha:response.source,repository:{id:BigInt(response.repositoryId),full_name:response.repository}};
    if(op==='Artifact') response=wireArtifact(response);
    if(op==='List') response={total_count:BigInt(response.items.length+(response.hasMore?1:0)),artifacts:response.items.map(wireArtifact)};
    const encoded=Buffer.from(wireJson(response));
    envelope={status:200,headers:{'content-type':'application/json','content-length':String(encoded.length)},body:encoded};
  }
  if(state.options.responseOversize===op) envelope.body=Buffer.alloc(131073);
  if(state.options.responseFault?.op===op&&(!state.options.responseFault.kind.endsWith('After')||state.calls[op]>1)) envelope=corruptResponse(envelope,state.options.responseFault.kind);
  return envelope;
}
function wireJson(x) {
  if(typeof x==='bigint') return x.toString();
  if(Array.isArray(x)) return '['+x.map(wireJson).join(',')+']';
  if(x!==null&&typeof x==='object') return '{'+Object.entries(x).map(([k,v])=>JSON.stringify(k)+':'+wireJson(v)).join(',')+'}';
  return JSON.stringify(x);
}
function corruptResponse(r,kind) {
  if(kind==='status') r.status=307;
  else if(kind==='encoding') r.headers['content-encoding']='gzip';
  else if(kind==='redirectOrigin') r.headers.location='https://unapproved.invalid/file';
  else if(kind==='badJson') r.body=Buffer.from('{"secret":"SYNTHETIC_ERROR"');
  else if(kind==='duplicate') r.body=Buffer.from('{"ok":false,"ok":true,"artifact_id":"9007199254740993"}');
  else if(kind==='unsafeInteger') r.body=Buffer.from('{"ok":true,"artifact_id":9007199254740993}');
  else if(kind==='runAttemptAfter'||kind==='runWorkflowAfter'){const m=strictJson(r.body,true);if(kind==='runAttemptAfter')m.run_attempt=2n;else m.workflow_id=9n;r.body=Buffer.from(wireJson(m));}
  else if(kind==='aliasConflict') r.body=Buffer.from('{"ok":true,"artifact_id":"9007199254740993","artifactId":"9007199254740993"}');
  else fail('FakeConfigurationRefused');
  r.headers['content-length']=String(r.body.length);return r;
}
function corruptRequest(r,kind) {
  if(kind==='method') r.method='DELETE';
  else if(kind==='origin') r.url='https://unapproved.invalid/no';
  else if(kind==='path') r.url+='/extra';
  else if(kind==='credential') r.credentialRole='Runtime';
  else if(kind==='json') r.body=Buffer.from('{');
  else if(kind==='original'){r.body=Buffer.from(r.body);r.body[0]^=1;}
  else if(kind==='query') r.url+='&sig=changed';
  else fail('FakeConfigurationRefused');
  return r;
}

function transportBinding(handle) {
  const local=localTlsBinding(handle);
  if(local) return {...local,engineSha256};
  if(transports.has(handle))return {kind:'RecordingFake',authoritySha256:'None',profileSha256:engineSha256,runtimeSha256:localRuntimeIdentity().sha256,engineSha256};
  fail('FixtureTransportRequired');
}
function assertClockBinding(transport,clock) {
  transportBinding(transport);
  if(transports.has(transport)?transports.get(transport).clock!==clock:clock!==undefined)fail('ClockBindingRefused');
}

function safeDirectory(dir) {
  if(process.platform!=='linux' || !path.isAbsolute(dir)) fail('PrivateStoreRefused');
  let cursor=dir;
  for(;;) {const s=fs.lstatSync(cursor);if(!s.isDirectory()||s.isSymbolicLink()) fail('PrivateStoreRefused');const parent=path.dirname(cursor);if(parent===cursor) break;cursor=parent;}
  const s=fs.lstatSync(dir);if((s.mode&0o777)!==0o700 || s.uid!==process.getuid()) fail('PrivateStoreRefused');
}
function syncDirectory(dir) {const fd=fs.openSync(dir,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function readPrivate(file,max) {
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try {const s=fs.fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.size>max) fail('PrivateStoreRefused');return fs.readFileSync(fd);}
  finally {fs.closeSync(fd);}
}
function writePrivate(file,bytes,mode=0o600) {const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,mode);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function validateJournal(j,expected,binding) {
  keys(j,['version','kind','binding','state','context','name','hash','size','created','deadline','lastWall','createdMono','deadlineMono','lastMono','boot','ledger','artifactId','metadataExpiry','reconciliationUsed','priorUnknown']);
  if(j.version!==3 || j.kind!=='OfflineTlsCapableArtifactTransaction' || !STATES.includes(j.state)) fail('JournalRefused');
  keys(j.binding,Object.keys(binding));if(JSON.stringify(j.binding)!==JSON.stringify(binding))fail('TransportBindingRefused');
  context(j.context);if(JSON.stringify(j.context)!==JSON.stringify(context(expected))) fail('ContextChanged');
  if(typeof j.name!=='string'||typeof j.hash!=='string'||!/^tf-offline-[0-9a-f]{32}$/.test(j.name)||!/^[0-9a-f]{64}$/.test(j.hash)||!Number.isSafeInteger(j.size)||j.size<1||j.size>LIMITS.archive) fail('JournalRefused');
  for(const n of [j.created,j.deadline,j.lastWall,j.createdMono,j.deadlineMono,j.lastMono]) if(!Number.isSafeInteger(n)||n<0) fail('JournalRefused');
  if(typeof j.boot!=='string'||!/^[-0-9a-f]{32,36}$/.test(j.boot)||j.deadlineMono!==j.createdMono+LIMITS.deadlineMs||j.lastMono<j.createdMono||j.deadline!==j.created+LIMITS.deadlineMs||j.lastWall<j.created||typeof j.reconciliationUsed!=='boolean'||!['','CreateUnknown','UploadUnknown','FinalizeUnknown'].includes(j.priorUnknown)) fail('JournalRefused');
  if(j.metadataExpiry!=='Unobserved'&&j.metadataExpiry!==null&&(!Number.isSafeInteger(j.metadataExpiry)||j.metadataExpiry<0))fail('JournalRefused');
  if(j.state==='Observed'&&j.metadataExpiry==='Unobserved')fail('JournalRefused');
  if(j.artifactId!==null) id(j.artifactId);
  if(['Finalized','Observed','ObserveIntent'].includes(j.state)&&j.artifactId===null) fail('JournalRefused');
  if(!Array.isArray(j.ledger)||j.ledger.length>LIMITS.attempts) fail('JournalRefused');
  let mutations=0,reads=0,bytes=0,last=j.created;const seen=new Set();
  for(const e of j.ledger) {
    keys(e,['op','charge','at']);if(!ROLE[e.op]||!Number.isSafeInteger(e.charge)||e.charge<1||e.charge>LIMITS.archive+LIMITS.controlResponse||!Number.isSafeInteger(e.at)||e.at<last||e.at>=j.deadline) fail('JournalRefused');
    last=e.at;bytes+=e.charge;
    if(e.charge!==requestBody(e.op,j).length+(e.op==='Download'?LIMITS.archive:LIMITS.controlResponse)) fail('JournalRefused');
    if(MUTATIONS.includes(e.op)){if(seen.has(e.op)) fail('JournalRefused');seen.add(e.op);mutations++;}else reads++;
  }
  const sequence=j.ledger.filter(e=>MUTATIONS.includes(e.op)).map(e=>e.op);
  if(sequence.some((op,i)=>op!==MUTATIONS[i])) fail('JournalRefused');
  const readOps=j.ledger.filter(e=>!MUTATIONS.includes(e.op)).map(e=>e.op);
  const observation=['Repository','Run','Artifact','Redirect','Download','Artifact','Run'];
  const readPlan=j.reconciliationUsed?['List',...observation]:observation;
  if(readOps.some((op,i)=>op!==readPlan[i])||j.ledger.slice(0,mutations).some(e=>!MUTATIONS.includes(e.op))) fail('JournalRefused');
  const stableCount={Prepared:0,Created:1,BlockAck:2,Committed:3};
  if(j.state in stableCount&&(mutations!==stableCount[j.state]||reads||j.artifactId!==null||j.priorUnknown||j.reconciliationUsed)) fail('JournalRefused');
  for(const [op,state] of Object.entries(INTENT)) if(j.state===state&&(reads||j.artifactId!==null||j.priorUnknown||j.reconciliationUsed||![MUTATIONS.indexOf(op),MUTATIONS.indexOf(op)+1].includes(mutations))) fail('JournalRefused');
  if(j.state==='CreateUnknown'&&(mutations>1||reads>1||j.priorUnknown!=='CreateUnknown')) fail('JournalRefused');
  if(j.state==='UploadUnknown'&&(mutations<1||mutations>3||reads||j.priorUnknown!=='UploadUnknown')) fail('JournalRefused');
  if(j.state==='FinalizeUnknown'&&(mutations<3||reads>1||j.priorUnknown!=='FinalizeUnknown')) fail('JournalRefused');
  if(j.priorUnknown==='CreateUnknown'&&mutations>1 || j.priorUnknown==='UploadUnknown'&&(mutations<1||mutations>3) || j.priorUnknown==='FinalizeUnknown'&&(mutations<3||mutations>4)) fail('JournalRefused');
  if(['Finalized','ObserveIntent','Observed'].includes(j.state)) {
    if(!j.reconciliationUsed&&j.priorUnknown!=='') fail('JournalRefused');
    if(mutations!==4&&!(mutations===1&&j.reconciliationUsed&&j.priorUnknown==='CreateUnknown')) fail('JournalRefused');
    if(j.state==='Observed'&&reads!==readPlan.length) fail('JournalRefused');
    if(j.state==='Finalized'&&reads!==(j.reconciliationUsed?1:0)) fail('JournalRefused');
  }
  if(j.state==='Refused'&&(reads||mutations>3)) fail('JournalRefused');
  if(j.state==='ObservationUnknown'&&mutations!==4&&!j.reconciliationUsed) fail('JournalRefused');
  if(j.reconciliationUsed&&!['CreateUnknown','FinalizeUnknown'].includes(j.priorUnknown)) fail('JournalRefused');
  if(mutations>4||reads>8||bytes>LIMITS.totalBytes||last>j.lastWall) fail('JournalRefused');
}

export class OfflineArtifactTransaction {
  #dir;#journal;#archive;#transport;#clock;#local=false;#lock;#closed=false;#blob=false;#download;#busy=false;
  constructor(secret) {if(secret!==transports) fail('UseOfflineFactory');}
  static prepare(options) {
    keys(options, ['parent','original','context','transport',...('clock' in options?['clock']:[])]);
    const {parent,original,context:identity,transport,clock}=options;
    assertClockBinding(transport,clock);
    const ctx=context(identity);assertCanonicalOriginal(original);const time=clockNow(clock);
    // mkdtemp's 0700 child is created before resolving any output file paths.
    const dir=fs.mkdtempSync(path.join(parent,'tf-offline-'));fs.chmodSync(dir,0o700);safeDirectory(dir);
    const j={version:3,kind:'OfflineTlsCapableArtifactTransaction',binding:transportBinding(transport),state:'Prepared',context:ctx,name:`tf-offline-${randomBytes(16).toString('hex')}`,
      hash:hash(original),size:original.length,created:time.wall,deadline:time.wall+LIMITS.deadlineMs,lastWall:time.wall,createdMono:time.mono,deadlineMono:time.mono+LIMITS.deadlineMs,lastMono:time.mono,boot:time.boot,ledger:[],artifactId:null,metadataExpiry:'Unobserved',reconciliationUsed:false,priorUnknown:''};
    writePrivate(path.join(dir,'original.zip'),original,0o400);
    writePrivate(path.join(dir,'journal.json'),Buffer.from(JSON.stringify(j)));syncDirectory(dir);
    return OfflineArtifactTransaction.open({directory:dir,context:ctx,transport,clock});
  }
  static open(options) {
    keys(options, ['directory','context','transport',...('clock' in options?['clock']:[])]);
    const {directory,context:identity,transport,clock}=options;
    assertClockBinding(transport,clock);safeDirectory(directory);
    const x=new OfflineArtifactTransaction(transports);x.#dir=directory;x.#local=!!localTlsBinding(transport);x.#transport=x.#local?transport:transports.get(transport);x.#clock=clock;
    // A killed process leaves this sentinel. Refuse it; automatic stale-lock
    // deletion/recovery is deliberately not implemented or claimed.
    x.#lock=fs.openSync(path.join(directory,'lock'),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    try {
      x.#journal=strictJson(readPrivate(path.join(directory,'journal.json'),16384));validateJournal(x.#journal,identity,transportBinding(transport));
      x.#archive=readPrivate(path.join(directory,'original.zip'),LIMITS.archive);x.#checkArchive();x.#checkTime();
      const s=x.#journal.state;
      if(Object.values(INTENT).includes(s)){const op=Object.keys(INTENT).find(k=>INTENT[k]===s);x.#journal.state=UNKNOWN[op];x.#journal.priorUnknown=UNKNOWN[op];x.#save();}
      else if(['Created','BlockAck','Committed'].includes(s)){x.#journal.state='UploadUnknown';x.#journal.priorUnknown='UploadUnknown';x.#save();}
      else if(s==='ObserveIntent'){x.#journal.state='ObservationUnknown';x.#save();}
      return x;
    } catch {x.close();fail('OfflineResumeRefused');}
  }
  get directory(){return this.#dir;}
  snapshot(){return structuredClone(this.#journal);}
  close(){if(this.#busy)fail('TransactionBusy');if(!this.#closed){this.#closed=true;if(this.#lock!==undefined){fs.closeSync(this.#lock);fs.unlinkSync(path.join(this.#dir,'lock'));syncDirectory(this.#dir);}}}
  #save() {
    const t=clockNow(this.#clock), j=this.#journal;
    // Never overwrite a previously observed timing watermark with a rollback.
    if(t.boot===j.boot && t.wall>=j.lastWall && t.mono>=j.lastMono) {
      j.lastWall=t.wall; j.lastMono=t.mono;
    }
    const name=path.join(this.#dir,`journal-${randomBytes(8).toString('hex')}.tmp`);
    writePrivate(name,Buffer.from(JSON.stringify(j)));
    fs.renameSync(name,path.join(this.#dir,'journal.json'));
    syncDirectory(this.#dir);
  }
  #checkArchive() {
    const b=readPrivate(path.join(this.#dir,'original.zip'),LIMITS.archive);
    if(b.length!==this.#journal.size || hash(b)!==this.#journal.hash || !b.equals(this.#archive)) fail('OriginalChanged');
    assertCanonicalOriginal(b);
  }
  #checkTime() {return assertWithinDeadline(this.#clock,this.#journal);}
  async #request(op,body=Buffer.alloc(0)) {
    if(this.#closed) fail('Closed');this.#checkArchive();const time=this.#checkTime(),j=this.#journal;
    const mutation=MUTATIONS.includes(op);if(!ROLE[op]||(!mutation&&!READS.includes(op))) fail('OperationRefused');
    const responseMax=op==='Download'?LIMITS.archive:LIMITS.controlResponse;
    if(body.length>(op==='Block'?LIMITS.archive:LIMITS.controlRequest)) fail('RequestBound');
    const charge=body.length+responseMax;
    if(j.ledger.length>=12||j.ledger.filter(e=>MUTATIONS.includes(e.op)===mutation).length>=(mutation?4:8)||j.ledger.reduce((n,e)=>n+e.charge,0)+charge>LIMITS.totalBytes||mutation&&j.ledger.some(e=>e.op===op)) fail('BudgetRefused');
    j.lastWall=time.wall;j.ledger.push({op,charge,at:time.wall});this.#save();
    // Persistence itself can consume the remaining deadline. A charged intent
    // is never permission to dispatch after expiration.
    this.#checkTime();
    const role=this.#transport.options?.credentialFault===op?(ROLE[op]==='Read'?'Runtime':'Read'):ROLE[op];
    const capabilities={original:this.#archive,uploadUrl:this.#blob,downloadUrl:this.#download};
    let request=buildRequest(op,j,capabilities);
    if(!request.body.equals(body)) fail('ProtocolChargeRefused');
    if(this.#transport.options?.serializationFault?.op===op) request=corruptRequest(request,this.#transport.options.serializationFault.kind);
    validateRequest(request,j,capabilities);
    if(!this.#local)this.#transport.expectedOriginal=Buffer.from(this.#archive);
    this.#checkTime();
    const before=clockNow(this.#clock);
    const response=this.#local?await exchangeLocalTls(this.#transport,request,j,capabilities):fakeExchange(this.#transport,request,this.#transport.credentials[role],j);
    const after=clockNow(this.#clock);this.#checkTime();
    if(after.wall-before.wall>=LIMITS.requestMs||after.mono-before.mono>=LIMITS.requestMs||response.body.length>responseMax) fail('ResponseBound');
    const parsed=parseResponse(op,response,j);
    const parsedAt=this.#checkTime();
    if(parsedAt.wall-before.wall>=LIMITS.requestMs||parsedAt.mono-before.mono>=LIMITS.requestMs) fail('ResponseBound');
    return parsed;
  }
  #expiryCurrent(){const e=this.#journal.metadataExpiry;return e===null||e==='Unobserved'||clockNow(this.#clock).wall<e;}
  #result(){return {kind:this.#local?'LocalTlsTransactionObservation':'OfflineFakeTransactionObservation',state:this.#journal.state==='Observed'&&!this.#expiryCurrent()?'SavedObservationExpired':this.#journal.state,originalSha256:this.#journal.hash,
    originalBytes:this.#journal.size,artifactId:this.#journal.artifactId,attempts:this.#journal.ledger.length,
    priorUnknown:this.#journal.priorUnknown,networkEnabled:this.#local,externalHttpsEnabled:false,localTlsOnly:this.#local,serviceInteroperabilityProven:false,
    operationalPolicyEmissionAllowed:false,contentPrivacyApproval:false,artifactOwnAttemptObserved:false,artifactOwnWorkflowIdObserved:false};}
  async advance() {
    if(this.#busy||this.#closed) fail('TransactionUnavailable');this.#busy=true;
    try {
      const op={Prepared:'Create',Created:'Block',BlockAck:'Commit',Committed:'Finalize'}[this.#journal.state];
      if(!op) return this.#result();
      this.#checkArchive();this.#checkTime();
      if(['Block','Commit'].includes(op)&&!this.#blob) fail('CapabilityUnavailable');
      this.#journal.state=INTENT[op];this.#save();
      try {
        const body=op==='Block'?Buffer.from(this.#archive):requestBody(op,this.#journal);
        const r=await this.#request(op,body);
        if(op==='Create'){keys(r,['reservation']);this.#blob=r.reservation;}
        else if(op==='Finalize'){keys(r,['id']);this.#journal.artifactId=id(r.id);}
        else {keys(r,['ok']);if(r.ok!==true) fail('ResponseRefused');}
        this.#journal.state=ACK[op];this.#save();
      } catch(e) {
        if(e instanceof Interrupted) return {...this.#result(),interrupted:true};
        this.#journal.state=UNKNOWN[op];this.#journal.priorUnknown=UNKNOWN[op];this.#save();
      }
      return this.#result();
    } catch {this.#journal.state='Refused';this.#save();return this.#result();}
    finally {this.#busy=false;}
  }
  #artifact(m) {
    keys(m,['id','name','observedContext','size','digest','expired','expiresAt']);id(m.id);keys(m.observedContext,['repositoryId','runId','source']);
    if(m.id!==this.#journal.artifactId||m.name!==this.#journal.name||m.observedContext.repositoryId!==this.#journal.context.repositoryId||m.observedContext.runId!==this.#journal.context.runId||m.observedContext.source!==this.#journal.context.source||m.size!==this.#journal.size||m.digest!==`sha256:${this.#journal.hash}`||m.expired!==false) fail('ArtifactMismatch');
    const j=this.#journal;if(j.metadataExpiry==='Unobserved'){j.metadataExpiry=m.expiresAt;this.#save();}
    if(j.metadataExpiry!==m.expiresAt||!this.#expiryCurrent())fail('ArtifactExpiredOrChanged');
  }
  async observe() {
    if(this.#busy||this.#closed) fail('TransactionUnavailable');this.#busy=true;
    try {
      const j=this.#journal;
      if(['CreateUnknown','FinalizeUnknown'].includes(j.state)&&!j.reconciliationUsed) {
        j.reconciliationUsed=true;this.#save();
        const r=await this.#request('List');keys(r,['items','hasMore']);
        if(r.hasMore!==false||!Array.isArray(r.items)||r.items.length!==1) return this.#result();
        j.artifactId=id(r.items[0].id);this.#artifact(r.items[0]);j.state='Finalized';this.#save();
      }
      if(j.state!=='Finalized') return this.#result();
      j.state='ObserveIntent';this.#save();
      const repo=await this.#request('Repository');keys(repo,['repository','id']);if(repo.repository!==j.context.repository||repo.id!==j.context.repositoryId) fail('RepositoryMismatch');
      const run=await this.#request('Run');context(run);if(JSON.stringify(context(run))!==JSON.stringify(j.context)) fail('RunMismatch');
      const first=await this.#request('Artifact');this.#artifact(first);
      const redirect=await this.#request('Redirect');keys(redirect,['capability']);this.#download=redirect.capability;
      const raw=await this.#request('Download');
      if(raw.length!==j.size||hash(raw)!==j.hash||!raw.equals(this.#archive)) fail('OriginalMismatch');assertCanonicalOriginal(raw);
      this.#artifact(await this.#request('Artifact'));
      const runAfter=await this.#request('Run');context(runAfter);if(JSON.stringify(context(runAfter))!==JSON.stringify(j.context)) fail('RunMismatch');
      this.#checkArchive();this.#checkTime();if(!this.#expiryCurrent())fail('ArtifactExpiredOrChanged');j.state='Observed';this.#save();return this.#result();
    } catch(e) {if(!(e instanceof Interrupted)){this.#journal.state='ObservationUnknown';this.#save();}return {...this.#result(),...(e instanceof Interrupted?{interrupted:true}:{})};}
    finally {this.#busy=false;}
  }
}
