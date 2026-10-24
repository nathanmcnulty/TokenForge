import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {validatePublicContext,validateServiceCapability,serviceModeGate} from '../scripts/transport/TokenForgeCanaryPreflight.mjs';
import {executeCanaryControl,planRestoration,controlProcedure,CONTROL_LIMITS} from '../scripts/transport/TokenForgeCanaryControl.mjs';
import {runDormantCanaryAction} from '../.github/actions/tokenforge-canary/index.mjs';
import {APPROVED_LOCAL_RUNTIME,localRuntimeIdentity} from '../scripts/transport/TokenForgeLocalTlsTransport.mjs';
const actual={repository:'nathanmcnulty/TokenForge',repositoryId:'1402673320',workflowId:'373691621',source:'a'.repeat(40),runId:'3',attempt:'1',runnerOs:'Linux',runnerArch:'X64',nodeVersion:'24.18.1',nodeSha256:APPROVED_LOCAL_RUNTIME.sha256,runnerSource:'b'.repeat(40),workflowSha256:'c'.repeat(64),actionSha256:'d'.repeat(64),sourceRef:'codex/goal6-canary-synthetic',resultsOrigin:'https://results-receiver.actions.githubusercontent.com',nodeOptions:'',execArgv:[]};
const approved=Object.fromEntries(Object.entries(actual).filter(([k])=>!['runId','attempt','nodeOptions','execArgv'].includes(k)));
test('selected local executable matches explicit reviewed pin',()=>assert.deepEqual(localRuntimeIdentity(),APPROVED_LOCAL_RUNTIME));
test('pure public context match grants neither credentials nor service execution',()=>assert.deepEqual(validatePublicContext(actual,approved),{publicContextMatchesPlan:true,selectedRunnerProven:false,credentialAccessAllowed:false,serviceExecutionAllowed:false}));
for(const [k,v] of Object.entries({repositoryId:'7',workflowId:'4',source:'f'.repeat(40),runnerOs:'Windows',runnerArch:'ARM64',nodeVersion:'24.19.0',nodeSha256:'f'.repeat(64),runnerSource:'f'.repeat(40),workflowSha256:'f'.repeat(64),actionSha256:'f'.repeat(64),sourceRef:'main',resultsOrigin:'https://unapproved.invalid',nodeOptions:'--import=bad',execArgv:['--inspect'],runId:'0',attempt:'0'}))test(`unapproved ${k} fails closed`,()=>assert.throws(()=>validatePublicContext({...actual,[k]:v},approved)));
test('missing or additional context fails closed',()=>{const x={...actual};delete x.runnerSource;assert.throws(()=>validatePublicContext(x,approved));assert.throws(()=>validatePublicContext({...actual,token:'dummy'},approved));});
test('service/action/controller gates do not inspect supplied context or credentials',async()=>{
 let reads=0;const trapped=new Proxy({},{get(){reads++;throw Error('SecretRead');},ownKeys(){reads++;throw Error('SecretRead');}});
 assert.throws(()=>serviceModeGate(trapped),/ServiceModeDisabled/);assert.throws(()=>executeCanaryControl(trapped),/ServiceModeDisabled/);await assert.rejects(runDormantCanaryAction(trapped),/ServiceModeDisabled/);assert.equal(reads,0);
 for(const script of ['scripts/Invoke-TokenForgeCanaryControl.mjs','.github/actions/tokenforge-canary/index.mjs']){
  const r=spawnSync(process.execPath,[script],{cwd:new URL('..',import.meta.url),env:{PATH:'/usr/bin:/bin',ACTIONS_RUNTIME_TOKEN:'SYNTHETIC_NO_USE',GITHUB_TOKEN:'SYNTHETIC_NO_USE',TF_CANARY_READ_TOKEN:'SYNTHETIC_NO_USE'},encoding:'utf8',timeout:3000});assert.equal(r.status,1);assert.equal(r.stdout,'');assert.equal(r.stderr,'TokenForgeServiceModeDisabled\n');
 }
});
const now=Date.parse('2026-10-24T00:00:00Z');
const sas=(sp='cw')=>'https://fixtureaccount.blob.core.windows.net/fixture/original.zip?sv=2023-11-03&spr=https&sp='+sp+'&se=2026-10-24T01%3A00%3A00Z&sr=b&sig=AAAAAAAAAAAAAAAAAAAAAA%3D%3D';
test('real-origin capability profile accepts only shape, preserves original query and confers no issuer authority',()=>{
 for(const [role,sp] of [['Blob','cw'],['Blob','w'],['Download','r']]){const raw=sas(sp),before=raw;const r=validateServiceCapability(raw,role,now);assert.equal(raw,before);assert.equal(r.issuerAuthorityEstablished,false);assert.equal(r.serviceExecutionAllowed,false);}
});
for(const [label,change] of Object.entries({http:s=>s.replace('https:','http:'),foreign:s=>s.replace('blob.core.windows.net','evil.invalid'),port:s=>s.replace('.net/','.net:444/'),fragment:s=>s+'#secret',extra:s=>s+'&comp=block',duplicate:s=>s+'&sp=cw',encodedKey:s=>s.replace('&sp=','&%73p='),expired:s=>s.replace('T01%3A','T00%3A'),overlong:s=>s.replace('24T01','26T01'),permission:s=>s.replace('sp=cw','sp=rwd'),version:s=>s.replace('2023-11-03','2020-01-01'),path:s=>s.replace('original.zip','%2e%2e/other'),partialDelegation:s=>s+'&sks=b'}))test(`SAS ${label} refused`,()=>assert.throws(()=>validateServiceCapability(change(sas()),'Blob',now)));
test('delegation fields require complete coherent bounded key dates and IDs',()=>{
 const raw=sas()+'&skoid=11111111-1111-4111-8111-111111111111&sktid=22222222-2222-4222-8222-222222222222&skt=2026-10-23T23%3A00%3A00Z&ske=2026-10-24T02%3A00%3A00Z&sks=b&skv=2023-11-03';assert.equal(validateServiceCapability(raw,'Blob',now).capabilityShapeAccepted,true);
 for(const bad of [raw.replace('sks=b','sks=f'),raw.replace('ske=2026-10-24T02','ske=2026-10-24T00'),raw.replace('skoid=111','skoid=xxx')])assert.throws(()=>validateServiceCapability(bad,'Blob',now));
});
const state={repositoryId:'1402673320',workflowId:'373691621',enabled:false,allowedActions:'selected',shaPinningRequired:true,workflowState:'disabled_manually'};
const applied={...state,enabled:true,workflowState:'active'};
test('restoration requires exclusive custody and unchanged last-applied state',()=>{
 const options={original:state,lastApplied:applied,current:applied,exclusiveCustody:true};const p=planRestoration(options);assert.equal(p.executable,false);assert.equal(p.casSupportEstablished,false);assert.deepEqual(p.operations.map(x=>x.body),[null,{enabled:false}]);
 for(const change of [{exclusiveCustody:false},{current:{...applied,allowedActions:'all'}},{current:{...applied,enabled:false}},{original:{...state,repositoryId:'1'}},{original:{...state,workflowId:'2'}}])assert.throws(()=>planRestoration({...options,...change}));
});
test('controller procedure has fixed caps, no redispatch slot and no live execution',()=>{const p=controlProcedure();assert.equal(p.reduce((n,x)=>n+x.maxUses,0),29);assert.ok(29<=CONTROL_LIMITS.attempts);assert.equal(p.find(x=>x.phase==='DispatchOnce').maxUses,1);assert.equal(CONTROL_LIMITS.mutations,6);assert.equal(CONTROL_LIMITS.totalMs,480000);});
test('public entrypoint and controller sources contain no credential environment or network reader',()=>{
 for(const file of ['.github/actions/tokenforge-canary/index.mjs','scripts/Invoke-TokenForgeCanaryControl.mjs','scripts/transport/TokenForgeCanaryControl.mjs','scripts/transport/TokenForgeCanaryPreflight.mjs'])assert.doesNotMatch(fs.readFileSync(new URL('../'+file,import.meta.url),'utf8'),/process\.env|fetch\(|https\.request|execFile/);
 const action=fs.readFileSync(new URL('../.github/actions/tokenforge-canary/action.yml',import.meta.url),'utf8');assert.match(action,/using: node24/);assert.doesNotMatch(action,/inputs:|outputs:/);
});
