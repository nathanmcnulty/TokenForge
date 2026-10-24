// Source-only preflight/profile. Never reads an environment or credential.
import {fail,keys,context} from '../offline/TokenForgeOfflineSchema.mjs';
export const SERVICE_PROFILE=Object.freeze({resultsOrigin:'https://results-receiver.actions.githubusercontent.com',apiOrigin:'https://api.github.com',storageSuffix:'.blob.core.windows.net',storageVersion:'2023-11-03',restVersion:'2022-11-28'});
export function serviceModeGate(){fail('ServiceModeDisabled');}
export function validatePublicContext(actual,approved) {
  const fields=['repository','repositoryId','workflowId','source','runId','attempt','runnerOs','runnerArch','nodeVersion','nodeSha256','runnerSource','workflowSha256','actionSha256','sourceRef','resultsOrigin','nodeOptions','execArgv'];
  keys(actual,fields);keys(approved,fields.filter(x=>!['runId','attempt','nodeOptions','execArgv'].includes(x)));
  context({repository:actual.repository,repositoryId:actual.repositoryId,workflowId:actual.workflowId,source:actual.source,runId:actual.runId,attempt:actual.attempt});
  if(actual.runnerOs!=='Linux'||actual.runnerArch!=='X64'||actual.nodeVersion!=='24.18.1'||actual.resultsOrigin!==SERVICE_PROFILE.resultsOrigin||actual.nodeOptions!==''||!Array.isArray(actual.execArgv)||actual.execArgv.length)fail('PublicContextRefused');
  for(const key of ['nodeSha256','workflowSha256','actionSha256'])if(typeof actual[key]!=='string'||!/^[0-9a-f]{64}$/.test(actual[key]))fail('PublicContextRefused');
  if(typeof actual.runnerSource!=='string'||!/^[0-9a-f]{40}$/.test(actual.runnerSource)||typeof actual.sourceRef!=='string'||!/^codex\/goal6-canary-[a-z0-9-]{1,64}$/.test(actual.sourceRef))fail('PublicContextRefused');
  if(Object.keys(approved).some(key=>actual[key]!==approved[key]))fail('PublicContextRefused');
  return {publicContextMatchesPlan:true,selectedRunnerProven:false,credentialAccessAllowed:false,serviceExecutionAllowed:false};
}
// Future service capability profile only. This does not establish issuer trust;
// only a separately approved verified TLS response could supply these values.
export function validateServiceCapability(raw,role,nowMs) {
  if(!['Blob','Download'].includes(role)||typeof raw!=='string'||raw.length>4096||/[\x00-\x20\x7f\\]/.test(raw)||/%(?![0-9a-fA-F]{2})/.test(raw)||!Number.isSafeInteger(nowMs))fail('ServiceCapabilityRefused');
  let u;try{u=new URL(raw);}catch{fail('ServiceCapabilityRefused');}
  if(u.protocol!=='https:'||u.port||u.username||u.password||u.hash||u.href!==raw||! /^[a-z0-9]{3,24}\.blob\.core\.windows\.net$/.test(u.hostname)||!/^\/[a-z0-9-]{3,63}\/[A-Za-z0-9._/%-]+$/.test(u.pathname)||/%(?:2e|2f|5c)/i.test(u.pathname))fail('ServiceCapabilityRefused');
  const required=['sv','spr','sp','se','sr','sig'],optional=['st','skoid','sktid','skt','ske','sks','skv'],names=[...u.searchParams.keys()];
  if(required.some(k=>!names.includes(k))||new Set(names).size!==names.length||names.some(k=>!required.includes(k)&&!optional.includes(k))||u.search.slice(1).split('&').some((v,i)=>v.split('=')[0]!==names[i]))fail('ServiceCapabilityRefused');
  if(u.searchParams.get('sv')!==SERVICE_PROFILE.storageVersion||u.searchParams.get('spr')!=='https'||u.searchParams.get('sr')!=='b'||!(role==='Blob'?/^(?:cw|w)$/:/^r$/).test(u.searchParams.get('sp'))||!/^[A-Za-z0-9+/]{16,}={0,2}$/.test(u.searchParams.get('sig')))fail('ServiceCapabilityRefused');
  const expiry=Date.parse(u.searchParams.get('se'));if(!Number.isFinite(expiry)||expiry<=nowMs||expiry>nowMs+86400000)fail('ServiceCapabilityRefused');
  if(u.searchParams.has('st')&&(!Number.isFinite(Date.parse(u.searchParams.get('st')))||Date.parse(u.searchParams.get('st'))>nowMs+300000))fail('ServiceCapabilityRefused');
  const delegation=['skoid','sktid','skt','ske','sks','skv'];if(delegation.some(k=>names.includes(k))&&!delegation.every(k=>names.includes(k)))fail('ServiceCapabilityRefused');
  if(delegation.every(k=>names.includes(k))) {
    for(const k of ['skoid','sktid'])if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(u.searchParams.get(k)))fail('ServiceCapabilityRefused');
    const start=Date.parse(u.searchParams.get('skt')),end=Date.parse(u.searchParams.get('ske'));
    if(!Number.isFinite(start)||!Number.isFinite(end)||start>nowMs||end<expiry||end<=start||u.searchParams.get('sks')!=='b'||u.searchParams.get('skv')!==SERVICE_PROFILE.storageVersion)fail('ServiceCapabilityRefused');
  }
  return {capabilityShapeAccepted:true,credentialRole:role,issuerAuthorityEstablished:false,serviceExecutionAllowed:false};
}
