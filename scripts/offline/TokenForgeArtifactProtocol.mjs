// Pure OFFLINE request/response profile. Reserved .invalid origins and opaque
// credential slots only. No dispatcher, environment, action or network imports.
import {createHash} from 'node:crypto';
import {fail, keys, id, context, strictJson} from './TokenForgeOfflineSchema.mjs';
export const PROTOCOL = Object.freeze({
  results:'https://results.fixture.invalid',api:'https://api.fixture.invalid',
  blob:'https://blob.fixture.invalid',download:'https://download.fixture.invalid',
  runBackend:'11111111-1111-4111-8111-111111111111',jobBackend:'22222222-2222-4222-8222-222222222222',
  storageVersion:'2023-11-03',restVersion:'2022-11-28',artifactId:'9007199254740993',
});
export const ROLES=Object.freeze({Create:'Runtime',Block:'Blob',Commit:'Blob',Finalize:'Runtime',
  Repository:'Read',Run:'Read',Artifact:'Read',Redirect:'Read',Download:'Download',List:'Read'});
const service='/twirp/github.actions.results.api.v1.ArtifactService/';
const hash=b=>createHash('sha256').update(b).digest('hex');
const json=x=>Buffer.from(JSON.stringify(x));
const signedId=x=>{id(x);if(BigInt(x)>9223372036854775807n) fail('ProtocolIdentityRefused');return x;};
const restInteger=x=>{if(typeof x!=='bigint'||x<0n||x>9223372036854775807n) fail('ProtocolIntegerRefused');return x.toString();};
const restId=x=>signedId(restInteger(x));
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const decimal=x=>{if(typeof x!=='string'||!/^(?:0|[1-9][0-9]*)$/.test(x)||BigInt(x)>9223372036854775807n) fail('ProtocolIntegerRefused');return x;};
function tx(t) {
  context(t.context);
  if(typeof t.name!=='string'||!/^tf-offline-[0-9a-f]{32}$/.test(t.name)||typeof t.hash!=='string'||!/^[a-f0-9]{64}$/.test(t.hash)||!Number.isSafeInteger(t.size)||t.size<1||t.size>65536) fail('ProtocolContextRefused');
}
function safeUrl(raw,origin,pathname) {
  if(typeof raw!=='string'||raw.length>4096||/[\x00-\x20\x7f\\]/.test(raw)||/%(?![a-fA-F0-9]{2})/.test(raw)) fail('ProtocolOriginRefused');
  let u;try{u=new URL(raw);}catch{fail('ProtocolOriginRefused');}
  // Comparing raw spelling also refuses default-port, dot-segment, host casing
  // and percent-normalization tricks; query octets are never reserialized.
  if(u.origin!==origin||u.username||u.password||u.hash||u.href!==raw||u.pathname!==pathname) fail('ProtocolOriginRefused');
  return u;
}
export function signedCapability(raw,kind) {
  const origin=kind==='Blob'?PROTOCOL.blob:kind==='Download'?PROTOCOL.download:fail('ProtocolCapabilityRefused');
  const u=safeUrl(raw,origin,kind==='Blob'?'/container/original.zip':'/artifact/original.zip');
  const names=[...u.searchParams.keys()];
  if(u.search.slice(1).split('&').some((part,i)=>part.split('=')[0]!==names[i])) fail('ProtocolQueryRefused');const allowed=['sv','spr','sp','se','sr','sig'];
  if(names.length!==allowed.length||names.some(n=>!allowed.includes(n))||new Set(names).size!==names.length) fail('ProtocolQueryRefused');
  if(u.searchParams.get('sv')!==PROTOCOL.storageVersion||u.searchParams.get('spr')!=='https'||u.searchParams.get('sp')!==(kind==='Blob'?'cw':'r')||u.searchParams.get('sr')!=='b'||u.searchParams.get('se')!=='2030-01-02T00:00:00Z'||u.searchParams.get('sig')!=='fixture+only/==') fail('ProtocolCapabilityRefused');
  // These exact dummy capabilities are NOT credentials or production SAS policy.
  return raw;
}
export function fixtureCapability(kind) {
  return `${kind==='Blob'?PROTOCOL.blob:PROTOCOL.download}${kind==='Blob'?'/container/original.zip':'/artifact/original.zip'}?sv=${PROTOCOL.storageVersion}&spr=https&sp=${kind==='Blob'?'cw':'r'}&se=2030-01-02T00%3A00%3A00Z&sr=b&sig=fixture%2Bonly%2f%3D%3D`;
}
const blockId=t=>Buffer.from(t.name,'ascii').toString('base64');
export function requestBody(op,t,original) {
  tx(t);
  if(op==='Block') {
    if(original===undefined) return Buffer.alloc(t.size); // reservation length only
    if(!Buffer.isBuffer(original)||original.length!==t.size||hash(original)!==t.hash) fail('ProtocolOriginalRefused');
    return Buffer.from(original);
  }
  if(op==='Commit') return Buffer.from(`<?xml version="1.0" encoding="utf-8"?><BlockList><Uncommitted>${blockId(t)}</Uncommitted></BlockList>`);
  const routing={workflow_run_backend_id:PROTOCOL.runBackend,workflow_job_run_backend_id:PROTOCOL.jobBackend,name:t.name};
  if(op==='Create') return json({...routing,version:4}); // omit optional retention timestamp
  if(op==='Finalize') return json({...routing,size:String(t.size),hash:`sha256:${t.hash}`});
  if(!Object.hasOwn(ROLES,op)) fail('ProtocolOperationRefused');
  return Buffer.alloc(0);
}
export function buildRequest(op,t,options={}) {
  if(!options||typeof options!=='object'||Object.keys(options).some(k=>!['original','uploadUrl','downloadUrl'].includes(k))) fail('ProtocolOptionsRefused');
  const {original,uploadUrl,downloadUrl}=options;
  if(op==='Block'&&!Buffer.isBuffer(original)) fail('ProtocolOriginalRefused');
  tx(t);if(!Object.hasOwn(ROLES,op)) fail('ProtocolOperationRefused');
  let method='GET',url,headers={};const body=requestBody(op,t,original);
  if(op==='Create'||op==='Finalize') {
    method='POST';url=PROTOCOL.results+service+op+'Artifact';headers={'content-type':'application/json'};
  } else if(op==='Block'||op==='Commit') {
    method='PUT';url=signedCapability(uploadUrl,'Blob')+(op==='Block'?`&comp=block&blockid=${encodeURIComponent(blockId(t))}`:'&comp=blocklist');
    headers={'content-type':op==='Block'?'application/octet-stream':'application/xml','x-ms-version':PROTOCOL.storageVersion};
  } else if(op==='Download') url=signedCapability(downloadUrl,'Download');
  else {
    headers={accept:'application/vnd.github+json','x-github-api-version':PROTOCOL.restVersion};
    const base=PROTOCOL.api+'/repos/'+t.context.repository;
    const routes={Repository:'',Run:'/actions/runs/'+t.context.runId,List:'/actions/runs/'+t.context.runId+'/artifacts?name='+t.name+'&per_page=100&page=1'};
    if(op==='Artifact'||op==='Redirect') url=base+'/actions/artifacts/'+signedId(t.artifactId)+(op==='Redirect'?'/zip':'');
    else url=base+routes[op];
  }
  if(body.length>(op==='Block'?65536:8192)) fail('ProtocolBodyRefused');
  headers['content-length']=String(body.length);
  return {op,method,url,headers,credentialRole:ROLES[op],credentialPlacement:['Runtime','Read'].includes(ROLES[op])?'AuthorizationBearer':'UrlCapability',body};
}
export function validateRequest(request,t,capabilities={}) {
  keys(request,['op','method','url','headers','credentialRole','credentialPlacement','body']);
  const expected=buildRequest(request.op,t,capabilities);
  keys(request.headers,Object.keys(expected.headers));
  if(!same(request.headers,expected.headers)||request.method!==expected.method||request.url!==expected.url||request.credentialRole!==expected.credentialRole||request.credentialPlacement!==expected.credentialPlacement||!Buffer.isBuffer(request.body)||!request.body.equals(expected.body)) fail('ProtocolRequestRefused');
  return request;
}
function responseHeaders(r) {
  keys(r,['status','headers','body']);
  if(!Number.isInteger(r.status)||!Buffer.isBuffer(r.body)||!r.headers||typeof r.headers!=='object'||Array.isArray(r.headers)) fail('ProtocolResponseRefused');
  const allowed=['content-type','content-length','location','link'];
  for(const [k,v] of Object.entries(r.headers)) if(!allowed.includes(k)||typeof v!=='string'||v.length>4096||/[\r\n]/.test(v)) fail('ProtocolResponseRefused');
  if(r.headers['content-length']!==undefined&&r.headers['content-length']!==String(r.body.length)) fail('ProtocolResponseRefused');
}
function alias(x,a,b) {
  if(Object.hasOwn(x,a)===Object.hasOwn(x,b)) fail('ProtocolAliasRefused');
  return Object.hasOwn(x,a)?x[a]:x[b];
}
function artifact(m,t) {
  keys(m,['id','name','size_in_bytes','digest','expired','workflow_run']);
  keys(m.workflow_run,['id','repository_id','head_sha']);
  const artifactId=restId(m.id),size=restInteger(m.size_in_bytes),runId=restId(m.workflow_run.id),repositoryId=restId(m.workflow_run.repository_id);
  if(typeof m.name!=='string'||typeof m.digest!=='string'||!/^sha256:[0-9a-f]{64}$/.test(m.digest)||typeof m.expired!=='boolean'||typeof m.workflow_run.head_sha!=='string'||!/^[a-f0-9]{40}$/.test(m.workflow_run.head_sha)||BigInt(size)>65536n) fail('ProtocolArtifactRefused');
  return {id:artifactId,name:m.name,size:Number(size),digest:m.digest,expired:m.expired,
    observedContext:{repositoryId,runId,source:m.workflow_run.head_sha}};
}
// Returns the core's normalized objects only after bounded wire validation.
// REST integer tokens become BigInt, never an unsafe JavaScript Number.
export function parseResponse(op,r,t) {
  tx(t);responseHeaders(r);const cap=op==='Download'?65536:131072;
  if(!Object.hasOwn(ROLES,op)||r.body.length>cap) fail('ProtocolResponseRefused');
  const expected=op==='Redirect'?302:['Block','Commit'].includes(op)?201:200;
  if(r.status!==expected) fail('ProtocolStatusRefused');
  if(op==='Redirect') {
    keys(r.headers,['location','content-length']);if(r.body.length) fail('ProtocolResponseRefused');
    return {capability:signedCapability(r.headers.location,'Download')};
  }
  if(op==='Download') {
    keys(r.headers,['content-type','content-length']);if(r.headers['content-type']!=='application/zip') fail('ProtocolResponseRefused');return Buffer.from(r.body);
  }
  if(op==='Block'||op==='Commit') {
    keys(r.headers,['content-length']);if(r.body.length) fail('ProtocolResponseRefused');return {ok:true};
  }
  if(r.headers['content-type']!=='application/json') fail('ProtocolResponseRefused');
  keys(r.headers,op==='List'&&Object.hasOwn(r.headers,'link')?['content-type','content-length','link']:['content-type','content-length']);
  const m=strictJson(r.body,!['Create','Finalize'].includes(op));
  switch(op) {
    case 'Create': {
      const url=alias(m,'signed_upload_url','signedUploadUrl');keys(m,['ok',Object.hasOwn(m,'signed_upload_url')?'signed_upload_url':'signedUploadUrl']);
      if(m.ok!==true) fail('ProtocolResponseRefused');return {reservation:signedCapability(url,'Blob')};
    }
    case 'Finalize': {
      const value=alias(m,'artifact_id','artifactId');keys(m,['ok',Object.hasOwn(m,'artifact_id')?'artifact_id':'artifactId']);if(m.ok!==true) fail('ProtocolResponseRefused');return {id:signedId(value)};
    }
    case 'Repository':keys(m,['id','full_name']);const repoId=restId(m.id);if(typeof m.full_name!=='string') fail('ProtocolResponseRefused');return {repository:m.full_name,id:repoId};
    case 'Run':keys(m,['id','run_attempt','workflow_id','head_sha','repository']);keys(m.repository,['id','full_name']);return context({repository:m.repository.full_name,repositoryId:restId(m.repository.id),workflowId:restId(m.workflow_id),runId:restId(m.id),attempt:restId(m.run_attempt),source:m.head_sha});
    case 'Artifact':return artifact(m,t);
    case 'List': {
      keys(m,['total_count','artifacts']);const total=restInteger(m.total_count);
      if(!Array.isArray(m.artifacts)||m.artifacts.length>100||BigInt(total)<BigInt(m.artifacts.length)) fail('ProtocolResponseRefused');
      // No arbitrary Link URL is followed. Any Link header is conservative paging.
      return {items:m.artifacts.map(x=>artifact(x,t)),hasMore:!!r.headers.link||BigInt(total)>BigInt(m.artifacts.length)};
    }
    default:fail('ProtocolOperationRefused');
  }
}
