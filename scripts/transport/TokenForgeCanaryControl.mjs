// Bounded controller candidate. Every external entrypoint is still gated.
// The executable closure owns a branded, network-free recording backend.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {keys,fail,id,strictJson} from '../offline/TokenForgeOfflineSchema.mjs';
import {serviceModeGate} from './TokenForgeCanaryPreflight.mjs';
import {APPROVED_LOCAL_RUNTIME,localRuntimeIdentity} from './TokenForgeLocalTlsTransport.mjs';

export const CONTROL_LIMITS=Object.freeze({attempts:30,mutations:6,totalMs:480000,perRequestMs:10000,bodyBytes:1048576,dispatches:1,runLookups:1,statusReads:10,cancelAttempts:1});
export const CONTROL_BLOCKERS=Object.freeze(['GitHubRefAndSettingsExclusiveCustodyNotEstablished','GitHubConditionalSettingsMutationNotEstablished']);
const REPO='nathanmcnulty/TokenForge',REPOSITORY_ID='1402673320',WORKFLOW_ID='373691621',BASE='/repos/'+REPO;
const bindings=['repository','repositoryId','workflowId','workflowPath','defaultBranch','source','sourceRef','workflowSha256','activationSha256','actor','actorId','nonce'];
const fixtures=new WeakMap(),hash=b=>createHash('sha256').update(b).digest('hex'),copy=x=>structuredClone(x);
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const operations=Object.freeze({
  Repository:['GET',BASE,80000],Workflow:['GET',BASE+'/actions/workflows/'+WORKFLOW_ID,80000],
  Ref:['GET',null,80000],Settings:['GET',BASE+'/actions/permissions',80000],
  EnableRepository:['PUT',BASE+'/actions/permissions',80000],EnableWorkflow:['PUT',BASE+'/actions/workflows/'+WORKFLOW_ID+'/enable',80000],
  VerifyWorkflow:['GET',BASE+'/actions/workflows/'+WORKFLOW_ID,80000],VerifyRef:['GET',null,80000],
  DispatchOnce:['POST',BASE+'/actions/workflows/'+WORKFLOW_ID+'/dispatches',100000],DiscoverRunOnce:['GET',null,100000],
  ObserveRunStatus:['GET',null,350000],CancelKnownRun:['POST',null,380000],ObserveCancellation:['GET',null,380000],
  BeforeRestoreWorkflow:['GET',BASE+'/actions/workflows/'+WORKFLOW_ID,440000],BeforeRestoreSettings:['GET',BASE+'/actions/permissions',440000],
  RestoreWorkflow:['PUT',null,440000],RestoreRepository:['PUT',BASE+'/actions/permissions',440000],
  VerifyRestoredWorkflow:['GET',BASE+'/actions/workflows/'+WORKFLOW_ID,440000],VerifyRestoredSettings:['GET',BASE+'/actions/permissions',440000],
});
const maxUses=op=>op==='ObserveRunStatus'?10:op==='ObserveCancellation'?2:1;
const isWrite=op=>operations[op]?.[0]!=='GET';
class Interrupted extends Error {}
export function executeCanaryControl(){serviceModeGate();}
export function controlProcedure() {
  return [
    ['RepositoryAndWorkflowAndRefAndSettings',4],['EnableRepositoryAndWorkflowIfNeeded',2],['VerifyWorkflowAndExclusiveRef',2],
    ['DispatchOnce',1],['DiscoverRunOnceBySourceRefNonceActor',1],['ObserveRunStatus',10],['CancelKnownRunOnDeadline',1],['ObserveCancellation',2],
    ['ReadWorkflowAndSettingsBeforeRestore',2],['RestoreOnlyOriginalEnablementBitsWithExclusiveCustody',2],['VerifyOriginalWorkflowAndRepositoryState',2],
  ].map(([phase,maxUses])=>({phase,maxUses}));
}
export function planRestoration({original,lastApplied,current,exclusiveCustody}) {
  if(exclusiveCustody!==true)fail('RestorationCustodyUnproven');
  for(const x of [original,lastApplied,current]) validateState(x);
  if(!equal(lastApplied,current)||original.allowedActions!==current.allowedActions||original.shaPinningRequired!==current.shaPinningRequired)fail('RestorationConflict');
  return {kind:'DormantRestorationPlan',executable:false,casSupportEstablished:false,requiresExclusiveCustody:true,
    operations:[{method:'PUT',path:BASE+'/actions/workflows/'+original.workflowId+'/'+(original.workflowState==='active'?'enable':'disable'),body:null},
      {method:'PUT',path:BASE+'/actions/permissions',body:{enabled:original.enabled}}]};
}
function validateState(x) {
  keys(x,['repositoryId','workflowId','enabled','allowedActions','shaPinningRequired','workflowState']);id(x.repositoryId);id(x.workflowId);
  if(x.repositoryId!==REPOSITORY_ID||x.workflowId!==WORKFLOW_ID||typeof x.enabled!=='boolean'||typeof x.shaPinningRequired!=='boolean'||!['all','local_only','selected'].includes(x.allowedActions)||!['active','disabled_manually'].includes(x.workflowState))fail('RestorationStateRefused');
}
function validateBinding(b) {
  keys(b,bindings);id(b.repositoryId);id(b.workflowId);id(b.actorId);
  if(b.repository!==REPO||b.repositoryId!==REPOSITORY_ID||b.workflowId!==WORKFLOW_ID||b.workflowPath!=='.github/workflows/ci.yml'||b.defaultBranch!=='main'||typeof b.actor!=='string'||!/^[-a-zA-Z0-9]{1,39}$/.test(b.actor)||typeof b.nonce!=='string'||!/^[-a-z0-9]{1,64}$/.test(b.nonce)||b.sourceRef!=='codex/goal6-canary-'+b.nonce||typeof b.source!=='string'||!/^[0-9a-f]{40}$/.test(b.source)||![b.workflowSha256,b.activationSha256].every(x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x)))fail('ControlBindingRefused');
  return copy(b);
}
export function assertApprovedControlRuntime() {
  const r=localRuntimeIdentity();if(process.platform!=='linux'||process.arch!=='x64'||!equal(r,APPROVED_LOCAL_RUNTIME))fail('ControlRuntimeRefused');return r;
}
// Read only fixed, bounded journal/source paths; never discover state or secrets.
function bytesAt(file,cap=131072,privateFile=false) {
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try {
    const s=fs.fstatSync(fd);if(!s.isFile()||s.nlink!==1||s.size>cap||privateFile&&(s.mode&0o077||s.uid!==process.getuid()))fail('ControlStoreRefused');
    const b=Buffer.alloc(s.size);let p=0;while(p<b.length){const n=fs.readSync(fd,b,p,b.length-p,p);if(!n)fail('ControlStoreRefused');p+=n;}return b;
  }finally{fs.closeSync(fd);}
}
const engineSha256=hash(Buffer.concat(['./TokenForgeCanaryControl.mjs','./TokenForgeCanaryPreflight.mjs','./TokenForgeLocalTlsTransport.mjs','../offline/TokenForgeOfflineSchema.mjs','../offline/TokenForgeOfflineClock.mjs','../offline/TokenForgeArtifactProtocol.mjs'].map(p=>bytesAt(new URL(p,import.meta.url),1048576))));
function assertDirectory(dir) {
  if(typeof dir!=='string'||!path.isAbsolute(dir)||path.resolve(dir)!==dir||fs.realpathSync(dir)!==dir)fail('ControlStoreRefused');
  const s=fs.lstatSync(dir);if(!s.isDirectory()||s.mode&0o077||s.uid!==process.getuid())fail('ControlStoreRefused');
}
function syncDirectory(dir){const fd=fs.openSync(dir,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function save(s,j) {
  const target=path.join(s.directory,'journal.json'),next=target+'.next',data=Buffer.from(JSON.stringify(j)+'\n');
  if(data.length>131072)fail('ControlStoreRefused');const fd=fs.openSync(next,fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW,0o600);
  try{let p=0;while(p<data.length)p+=fs.writeSync(fd,data,p,data.length-p);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  fs.renameSync(next,target);syncDirectory(s.directory);s.journalDigest=hash(data);
}
function clock(s){return {wall:s.wall+Date.now()-s.realWall,mono:s.mono+Number(process.hrtime.bigint()/1000000n)-s.realMono};}
function elapsed(s,j) {
  const n=clock(s);if(n.wall<j.lastWall||n.mono<j.lastMono)fail('ControlClockRefused');
  j.lastWall=n.wall;j.lastMono=n.mono;return Math.max(n.wall-j.startWall,n.mono-j.startMono);
}
function incident(j,code){if(!j.incidents.includes(code))j.incidents.push(code);}
function custody(s,j) {
  if(!s.custodyHeld||s.epoch!==j.custodyEpoch||s.ref!==j.binding.source||!equal(s.policy,j.policy))fail('ControlCustodyLost');
}
function request(op,j) {
  let [method,route]=operations[op],body=null;const b=j.binding;
  if(op==='Ref'||op==='VerifyRef')route=BASE+'/git/ref/heads/'+b.sourceRef;
  if(op==='DiscoverRunOnce')route=BASE+'/actions/workflows/'+WORKFLOW_ID+'/runs?actor='+encodeURIComponent(b.actor)+'&branch='+encodeURIComponent(b.sourceRef)+'&event=workflow_dispatch&head_sha='+b.source+'&per_page=100&page=1';
  if(['ObserveRunStatus','ObserveCancellation','CancelKnownRun'].includes(op))route=BASE+'/actions/runs/'+id(j.runId)+(op==='CancelKnownRun'?'/cancel':'');
  if(op==='EnableRepository')body={enabled:true};
  if(op==='RestoreRepository')body={enabled:j.original.enabled};
  if(op==='DispatchOnce')body={ref:b.sourceRef,inputs:{nonce:b.nonce}};
  if(op==='RestoreWorkflow')route=BASE+'/actions/workflows/'+WORKFLOW_ID+'/'+(j.original.workflowState==='active'?'enable':'disable');
  return {op,method,path:route,body:body===null?Buffer.alloc(0):Buffer.from(JSON.stringify(body)),apiVersion:'2022-11-28',credentialRole:'DummyControlFixtureOnly'};
}
function numeric(x){if(typeof x==='bigint')return id(x.toString());fail('ControlResponseRefused');}
function workflow(raw,b) {
  if(numeric(raw.id)!==b.workflowId||raw.path!==b.workflowPath||!['active','disabled_manually'].includes(raw.state))fail('ControlResponseRefused');return raw.state;
}
function settings(raw) {
  keys(raw,['enabled','allowed_actions','sha_pinning_required']);
  if(typeof raw.enabled!=='boolean'||!['all','local_only','selected'].includes(raw.allowed_actions)||typeof raw.sha_pinning_required!=='boolean')fail('ControlResponseRefused');
  return {enabled:raw.enabled,allowedActions:raw.allowed_actions,shaPinningRequired:raw.sha_pinning_required};
}
function ref(raw,b) {if(raw.ref!=='refs/heads/'+b.sourceRef||raw.object?.type!=='commit'||raw.object.sha!==b.source)fail('ControlResponseRefused');}
function selectedRun(raw,b,runId) {
  const value=numeric(raw.id);
  if(runId&&value!==runId||numeric(raw.workflow_id)!==b.workflowId||numeric(raw.run_attempt)!=='1'||raw.head_sha!==b.source||raw.head_branch!==b.sourceRef||raw.event!=='workflow_dispatch'||raw.display_title!=='TokenForge canary '+b.nonce||raw.actor?.login!==b.actor||numeric(raw.actor?.id)!==b.actorId||numeric(raw.repository?.id)!==b.repositoryId||raw.repository?.full_name!==b.repository||!['queued','in_progress','waiting','requested','pending','completed'].includes(raw.status))fail('ControlRunBindingRefused');
  if(raw.status==='completed'&&!['success','failure','cancelled','timed_out','action_required','neutral','skipped','stale','startup_failure'].includes(raw.conclusion))fail('ControlResponseRefused');
  return {id:value,status:raw.status,conclusion:raw.status==='completed'?raw.conclusion:null};
}
function runBody(s,j,status='completed',conclusion='success') {
  const b=j.binding;return {id:7001,workflow_id:Number(b.workflowId),run_attempt:1,head_sha:b.source,head_branch:b.sourceRef,event:'workflow_dispatch',display_title:'TokenForge canary '+b.nonce,actor:{login:b.actor,id:Number(b.actorId)},repository:{id:Number(b.repositoryId),full_name:b.repository},status,conclusion:status==='completed'?conclusion:null};
}

// This factory cannot accept a transport, network address, credential or callback.
// Its private backend actually excludes other writers to ref AND settings. That
// authority exists only inside this recording fixture; no GitHub CAS is implied.
export function createControlRecordingFixture(options) {
  assertApprovedControlRuntime();
  const allowed=['binding','initial','faults','requestMs','statuses','discovery','responseFault','custody','loseCustodyAt'];
  if(!options||Object.keys(options).some(k=>!allowed.includes(k)))fail('ControlFixtureRefused');
  let o;try{o=copy(options);}catch{fail('ControlFixtureRefused');}const binding=validateBinding(o.binding);
  validateState(o.initial);
  if(o.custody!==undefined&&!['exclusive','unavailable','boolean-only'].includes(o.custody)||o.discovery!==undefined&&!['unique','zero','multiple','paginated','missing'].includes(o.discovery))fail('ControlFixtureRefused');
  for(const [op,value] of Object.entries(o.faults??{}))if(!operations[op]||!['before','after','interruptBefore','interruptAfter'].includes(value))fail('ControlFixtureRefused');
  if(o.requestMs!==undefined&&(!Number.isSafeInteger(o.requestMs)||o.requestMs<0||o.requestMs>480001))fail('ControlFixtureRefused');
  if(o.statuses!==undefined&&(!Array.isArray(o.statuses)||o.statuses.length>10||o.statuses.some(x=>!['queued','in_progress','completed'].includes(x))))fail('ControlFixtureRefused');
  if(o.responseFault!==undefined){keys(o.responseFault,['op','kind']);if(!operations[o.responseFault.op]||!['oversize','json','identity','policy','redirect','extraPolicy','runSource','runRef','runNonce','runWorkflow','runActor','runActorId','runRepository','runAttempt','runEvent','runId','runMissing'].includes(o.responseFault.kind))fail('ControlFixtureRefused');}
  if(o.loseCustodyAt!==undefined&&!operations[o.loseCustodyAt])fail('ControlFixtureRefused');
  const s={options:o,binding,authority:randomBytes(24).toString('hex'),wall:1792800000000,mono:0,realWall:Date.now(),realMono:Number(process.hrtime.bigint()/1000000n),epoch:1,custodyHeld:!o.custody||o.custody==='exclusive',ref:binding.source,
    policy:{allowedActions:o.initial.allowedActions,shaPinningRequired:o.initial.shaPinningRequired},enabled:o.initial.enabled,workflowState:o.initial.workflowState,log:[],effects:[],directory:null,journalDigest:null,busy:false,dispatchCount:0,statusIndex:0,cancelled:false};
  const handle=Object.freeze({kind:'NetworkDisabledControlRecordingFixture',transcript:()=>copy(s.log),effects:()=>copy(s.effects),
    snapshot:()=>({enabled:s.enabled,workflowState:s.workflowState,ref:s.ref,custodyHeld:s.custodyHeld}),
    competingWrite(change){if(!['ref','settings','workflow'].includes(change))fail('ControlFixtureRefused');if(s.custodyHeld)return false;s.epoch++;if(change==='ref')s.ref='f'.repeat(40);else if(change==='settings')s.policy.allowedActions='all';else s.workflowState='disabled_manually';return true;},
    revokeCustody(){s.custodyHeld=false;s.epoch++;},
    advance(ms){if(!Number.isSafeInteger(ms)||ms<0)fail('ControlFixtureRefused');s.wall+=ms;s.mono+=ms;},
  });fixtures.set(handle,s);return handle;
}
function recordingExchange(s,r,j) {
  // Independently fixed route oracle: never route by suffix/substring matching.
  const b=s.binding,workflowPath=BASE+'/actions/workflows/'+WORKFLOW_ID,runPath=BASE+'/actions/runs/7001';
  const oracle={Repository:['GET',BASE],Workflow:['GET',workflowPath],Ref:['GET',BASE+'/git/ref/heads/'+b.sourceRef],Settings:['GET',BASE+'/actions/permissions'],
    EnableRepository:['PUT',BASE+'/actions/permissions'],EnableWorkflow:['PUT',workflowPath+'/enable'],VerifyWorkflow:['GET',workflowPath],VerifyRef:['GET',BASE+'/git/ref/heads/'+b.sourceRef],
    DispatchOnce:['POST',workflowPath+'/dispatches'],DiscoverRunOnce:['GET',workflowPath+'/runs?actor='+encodeURIComponent(b.actor)+'&branch='+encodeURIComponent(b.sourceRef)+'&event=workflow_dispatch&head_sha='+b.source+'&per_page=100&page=1'],
    ObserveRunStatus:['GET',runPath],CancelKnownRun:['POST',runPath+'/cancel'],ObserveCancellation:['GET',runPath],BeforeRestoreWorkflow:['GET',workflowPath],BeforeRestoreSettings:['GET',BASE+'/actions/permissions'],
    RestoreWorkflow:['PUT',workflowPath+'/'+(s.options.initial.workflowState==='active'?'enable':'disable')],RestoreRepository:['PUT',BASE+'/actions/permissions'],VerifyRestoredWorkflow:['GET',workflowPath],VerifyRestoredSettings:['GET',BASE+'/actions/permissions']};
  if(!equal(oracle[r.op],[r.method,r.path])||r.apiVersion!=='2022-11-28'||r.credentialRole!=='DummyControlFixtureOnly')fail('ControlFixtureWireRefused');
  const expectedBody=r.op==='DispatchOnce'?{ref:b.sourceRef,inputs:{nonce:b.nonce}}:r.op==='EnableRepository'?{enabled:true}:r.op==='RestoreRepository'?{enabled:s.options.initial.enabled}:null;
  if(!r.body.equals(expectedBody===null?Buffer.alloc(0):Buffer.from(JSON.stringify(expectedBody))))fail('ControlFixtureWireRefused');
  const durableBytes=bytesAt(path.join(s.directory,'journal.json'),131072,true),durable=strictJson(durableBytes),entry=durable.ledger.at(-1);
  if(hash(durableBytes)!==s.journalDigest||durable.authority!==s.authority||entry?.op!==r.op||entry.outcome!=='Intent'||entry.requestSha256!==hash(r.body)||entry.responseReservation!==CONTROL_LIMITS.bodyBytes||durable.mutations!==j.mutations)fail('ControlFixtureIntentNotDurable');
  const log={op:r.op,method:r.method,path:r.path,requestBytes:r.body.length,requestSha256:hash(r.body),intentDurable:true};s.log.push(log);
  const fault=s.options.faults?.[r.op];if(fault==='interruptBefore')throw new Interrupted();if(fault==='before')fail('ControlExchangeUnknown');
  if(s.options.loseCustodyAt===r.op){s.custodyHeld=false;s.epoch++;fail('ControlCustodyLost');}
  const dur=s.options.requestMs??1;s.wall+=dur;s.mono+=dur;
  let body,status=200;
  if(r.op==='Repository')body={id:Number(b.repositoryId),full_name:b.repository,default_branch:b.defaultBranch};
  else if(['Ref','VerifyRef'].includes(r.op))body={ref:'refs/heads/'+b.sourceRef,object:{type:'commit',sha:s.ref}};
  else if(['Workflow','VerifyWorkflow','BeforeRestoreWorkflow','VerifyRestoredWorkflow'].includes(r.op))body={id:Number(b.workflowId),path:b.workflowPath,state:s.workflowState};
  else if(['Settings','BeforeRestoreSettings','VerifyRestoredSettings'].includes(r.op))body={enabled:s.enabled,allowed_actions:s.policy.allowedActions,sha_pinning_required:s.policy.shaPinningRequired};
  else if(r.op==='EnableRepository'||r.op==='RestoreRepository'){s.enabled=r.op==='EnableRepository'?true:s.options.initial.enabled;status=204;s.effects.push(r.op);}
  else if(r.op==='EnableWorkflow'||r.op==='RestoreWorkflow'){s.workflowState=r.op==='EnableWorkflow'?'active':s.options.initial.workflowState;status=204;s.effects.push(r.op);}
  else if(r.op==='DispatchOnce'){if(++s.dispatchCount!==1||!s.enabled||s.workflowState!=='active')fail('ControlFixtureSequenceRefused');status=204;s.effects.push(r.op);}
  else if(r.op==='DiscoverRunOnce'){
    const mode=s.options.discovery??'unique',runs=mode==='zero'||mode==='missing'?[]:[runBody(s,j,'queued')];if(mode==='multiple')runs.push({...runs[0],id:7002});
    body=mode==='missing'?{}:{total_count:runs.length,workflow_runs:runs};
  }else if(r.op==='ObserveRunStatus'){body=runBody(s,j,s.options.statuses?.[s.statusIndex++]??'completed');}
  else if(r.op==='CancelKnownRun'){s.cancelled=true;status=202;s.effects.push(r.op);}
  else if(r.op==='ObserveCancellation')body=runBody(s,j,s.cancelled?'completed':'in_progress','cancelled');
  const f=s.options.responseFault;if(f?.op===r.op){if(f.kind==='identity'){if(body?.head_sha)body.head_sha='f'.repeat(40);else if(body?.object)body.object.sha='f'.repeat(40);else if(body)body.id=1;}else if(f.kind==='policy')body.allowed_actions='all';else if(f.kind==='extraPolicy')body.extra_policy=true;
    const run=body?.workflow_runs?.[0]??body;
    if(f.kind==='runSource')run.head_sha='f'.repeat(40);else if(f.kind==='runRef')run.head_branch='main';else if(f.kind==='runNonce')run.display_title+='-suffix';else if(f.kind==='runWorkflow')run.workflow_id=1;else if(f.kind==='runActor')run.actor.login='other';else if(f.kind==='runActorId')run.actor.id=1;else if(f.kind==='runRepository')run.repository.id=1;else if(f.kind==='runAttempt')run.run_attempt=2;else if(f.kind==='runEvent')run.event='push';else if(f.kind==='runId')run.id=7002;else if(f.kind==='runMissing')delete run.head_branch;
  }
  if(fault==='interruptAfter')throw new Interrupted();if(fault==='after')fail('ControlExchangeUnknown');
  const bytes=f?.op===r.op&&f.kind==='oversize'?Buffer.alloc(CONTROL_LIMITS.bodyBytes+1):f?.op===r.op&&f.kind==='json'?Buffer.from('{"SYNTHETIC_RESPONSE_SECRET":'):body===undefined?Buffer.alloc(0):Buffer.from(JSON.stringify(body));
  return {status:f?.op===r.op&&f.kind==='redirect'?302:status,link:s.options.discovery==='paginated'&&r.op==='DiscoverRunOnce',body:bytes};
}
function exchange(s,j,op) {
  custody(s,j);const used=j.ledger.filter(x=>x.op===op).length,when=elapsed(s,j),phaseEnd=operations[op][2];
  if(used>=maxUses(op)||j.ledger.length>=CONTROL_LIMITS.attempts||isWrite(op)&&j.mutations>=CONTROL_LIMITS.mutations||when+CONTROL_LIMITS.perRequestMs>phaseEnd||when+CONTROL_LIMITS.perRequestMs>CONTROL_LIMITS.totalMs)fail('ControlBudgetRefused');
  const r=request(op,j);if(r.body.length>CONTROL_LIMITS.bodyBytes)fail('ControlBodyRefused');
  const now=clock(s),entry={ordinal:j.ledger.length+1,op,write:isWrite(op),requestBytes:r.body.length,responseReservation:CONTROL_LIMITS.bodyBytes,requestSha256:hash(r.body),startedWall:now.wall,startedMono:now.mono,outcome:'Intent'};
  j.ledger.push(entry);if(entry.write)j.mutations++;j.reservedEntityBytes+=r.body.length+CONTROL_LIMITS.bodyBytes;j.state=op+'Intent';save(s,j);
  try {
    const beforeSend=elapsed(s,j);custody(s,j);
    if(j.lastWall>=entry.startedWall+CONTROL_LIMITS.perRequestMs||j.lastMono>=entry.startedMono+CONTROL_LIMITS.perRequestMs||beforeSend+CONTROL_LIMITS.perRequestMs>phaseEnd)fail('ControlExchangeUnknown');
    const response=recordingExchange(s,r,j),after=elapsed(s,j);
    custody(s,j);
    if(j.lastWall>=entry.startedWall+CONTROL_LIMITS.perRequestMs||j.lastMono>=entry.startedMono+CONTROL_LIMITS.perRequestMs||after>phaseEnd||response.body.length>CONTROL_LIMITS.bodyBytes||response.link)fail('ControlExchangeUnknown');
    const want=op==='CancelKnownRun'?202:entry.write?204:200;if(response.status!==want||entry.write&&response.body.length)fail('ControlResponseRefused');
    const result=entry.write?null:strictJson(response.body,true),afterParse=elapsed(s,j);
    if(j.lastWall>=entry.startedWall+CONTROL_LIMITS.perRequestMs||j.lastMono>=entry.startedMono+CONTROL_LIMITS.perRequestMs||afterParse>phaseEnd)fail('ControlExchangeUnknown');
    entry.outcome='Acknowledged';j.state=op+'Acknowledged';save(s,j);return result;
  } catch(e) {
    if(e instanceof Interrupted)throw e;entry.outcome='Unknown';j.state=op+'Unknown';save(s,j);throw new Error('ControlExchangeUnknown');
  }
}
function attempt(s,j,op) {try{return {ok:true,value:exchange(s,j,op)};}catch(e){if(e instanceof Interrupted)throw e;incident(j,op+'Unknown');save(s,j);return {ok:false};}}
function updateEnable(s,j,op,field,value) {
  j.expected[field]=value;save(s,j);const r=attempt(s,j,op);if(!r.ok){j.unknownEnable.push(field);save(s,j);return false;}return true;
}
function observeRun(s,j,op) {
  const r=attempt(s,j,op);if(!r.ok)return false;
  try{const run=selectedRun(r.value,j.binding,j.runId);j.runState=run.status==='completed'?'Completed':'Running';j.runConclusion=run.conclusion;save(s,j);return true;}
  catch{incident(j,'SelectedRunIdentityUnknown');j.runState='Unknown';save(s,j);return false;}
}
function cancel(s,j) {
  if(!j.runId||j.runState==='Completed')return;
  if(j.ledger.some(x=>x.op==='CancelKnownRun')){j.runState='Unknown';incident(j,'InterruptedCancellationRequiresNamedOperator');save(s,j);return;}
  const r=attempt(s,j,'CancelKnownRun');j.runState=r.ok?'CancellationRequested':'CancelUnknown';save(s,j);
  for(let i=0;i<2&&j.runState!=='Completed';i++)if(!observeRun(s,j,'ObserveCancellation'))break;
  if(j.runState!=='Completed'){j.runState='Unknown';incident(j,'SelectedRunCompletionUnknownRequiresNamedOperator');save(s,j);}
}
function restore(s,j) {
  if(!j.original){j.restoration='NotRequired';return;}
  if(j.restorationStarted){j.restoration='Unresolved';incident(j,'InterruptedRestorationRequiresNamedOperator');return;}
  j.restorationStarted=true;j.restoration='Unresolved';save(s,j);
  try {
    custody(s,j);
    const w=workflow(exchange(s,j,'BeforeRestoreWorkflow'),j.binding),p=settings(exchange(s,j,'BeforeRestoreSettings'));
    const current={repositoryId:REPOSITORY_ID,workflowId:WORKFLOW_ID,...p,workflowState:w};
    for(const k of ['enabled','workflowState'])if(current[k]!==j.expected[k]&&!(j.unknownEnable.includes(k)&&current[k]===j.original[k]))fail('RestorationConflict');
    if(current.allowedActions!==j.original.allowedActions||current.shaPinningRequired!==j.original.shaPinningRequired)fail('RestorationConflict');
    j.expected=current;save(s,j);
    // The local backend custody is checked before EACH settings mutation.
    // A boolean or read-then-write over GitHub is never this authority.
    if(current.workflowState!==j.original.workflowState)attempt(s,j,'RestoreWorkflow');
    if(current.enabled!==j.original.enabled)attempt(s,j,'RestoreRepository');
    const finalWorkflow=workflow(exchange(s,j,'VerifyRestoredWorkflow'),j.binding),finalPolicy=settings(exchange(s,j,'VerifyRestoredSettings'));
    if(!equal({repositoryId:REPOSITORY_ID,workflowId:WORKFLOW_ID,...finalPolicy,workflowState:finalWorkflow},j.original))fail('RestorationVerificationFailed');
    if(elapsed(s,j)>440000)fail('RestorationVerificationLate');
    j.restoration='Verified';
  }catch(e){if(e instanceof Interrupted)throw e;incident(j,'RestorationUnresolvedRequiresNamedOperator');}
  save(s,j);
}
function summary(j) {
  return {kind:'LocalRecordingControlResult',state:j.state,runState:j.runState,runId:j.runId,runConclusion:j.runConclusion,restoration:j.restoration,recoveryOwner:j.recoveryOwner,
    incidents:copy(j.incidents),attempts:j.ledger.length,mutations:j.mutations,reservedEntityBytes:j.reservedEntityBytes,elapsedMs:Math.max(j.lastWall-j.startWall,j.lastMono-j.startMono),ledger:copy(j.ledger),
    recoveryRequired:j.restoration==='Unresolved'||!['NotDispatched','Completed'].includes(j.runState),clockKind:'WallAndMonotonicWithRecordingOnlyAdvances',
    controllerExecutionEnabled:false,externalControlEnabled:false,localFixtureOnly:true,custodyAuthority:'ExclusiveLocalRecordingBackendOnly',githubCasEstablished:false,liveBlockers:[...CONTROL_BLOCKERS]};
}
export async function runLocalCanaryControl(handle,options) {
  const s=fixtures.get(handle);if(!s)fail('ControlFixtureAuthorityRequired');assertApprovedControlRuntime();
  keys(options,['directory','binding','recoveryOwner']);const b=validateBinding(options.binding);
  if(!equal(b,s.binding)||typeof options.recoveryOwner!=='string'||!/^[-A-Za-z0-9_.@]{1,80}$/.test(options.recoveryOwner))fail('ControlBindingRefused');
  assertDirectory(options.directory);if(s.busy)fail('ControlBusy');if(s.directory&&s.directory!==options.directory)fail('ControlStoreBindingRefused');
  const lock=path.join(options.directory,'control.lock');let fd;
  try{fd=fs.openSync(lock,fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW,0o600);}catch{fail('ControlStoreLockedRequiresNamedOperator');}
  s.busy=true;s.directory=options.directory;let j;
  try {
    const file=path.join(s.directory,'journal.json'),exists=fs.existsSync(file);
    if(exists){
      const bytes=bytesAt(file,131072,true);if(hash(bytes)!==s.journalDigest)fail('ControlJournalBindingRefused');j=strictJson(bytes);
      if(j.version!==1||j.authority!==s.authority||j.engineSha256!==engineSha256||j.runtimeSha256!==APPROVED_LOCAL_RUNTIME.sha256||!equal(j.binding,b)||j.recoveryOwner!==options.recoveryOwner)fail('ControlJournalBindingRefused');
      if(j.terminal)return summary(j);
      for(const entry of j.ledger)if(entry.outcome==='Intent')entry.outcome='Unknown';
      for(const [op,field] of [['EnableRepository','enabled'],['EnableWorkflow','workflowState']])if(j.ledger.some(x=>x.op===op&&x.outcome==='Unknown')&&!j.unknownEnable.includes(field))j.unknownEnable.push(field);
      incident(j,'InterruptedExecutionRecoveryOnly');save(s,j);
      // No restart/re-enable/redispatch. A discovered run may be cancelled once;
      // the named operator must identify any undiscovered run.
      if(j.ledger.some(x=>x.op==='DispatchOnce')&&!j.runId){j.runState='Unknown';incident(j,'UndiscoveredDispatchRequiresNamedOperator');}
      cancel(s,j);restore(s,j);
    }else{
      if(s.journalDigest!==null)fail('ControlJournalMissing');
      const start=clock(s);j={version:1,authority:s.authority,engineSha256,runtimeSha256:APPROVED_LOCAL_RUNTIME.sha256,binding:b,recoveryOwner:options.recoveryOwner,
        startWall:start.wall,startMono:start.mono,lastWall:start.wall,lastMono:start.mono,custodyEpoch:s.epoch,policy:copy(s.policy),state:'Prepared',runState:'NotDispatched',runId:null,runConclusion:null,
        original:null,expected:null,unknownEnable:[],restoration:'NotRequired',restorationStarted:false,ledger:[],mutations:0,reservedEntityBytes:0,incidents:[],terminal:false};save(s,j);
      try {
        custody(s,j);
        const repository=exchange(s,j,'Repository');if(numeric(repository.id)!==b.repositoryId||repository.full_name!==b.repository||repository.default_branch!==b.defaultBranch)fail('ControlRepositoryRefused');
        const w=workflow(exchange(s,j,'Workflow'),b);ref(exchange(s,j,'Ref'),b);const p=settings(exchange(s,j,'Settings'));
        j.original={repositoryId:REPOSITORY_ID,workflowId:WORKFLOW_ID,...p,workflowState:w};validateState(j.original);j.expected=copy(j.original);save(s,j);
        if(!p.enabled&&!updateEnable(s,j,'EnableRepository','enabled',true))fail('ControlEnableUnknown');
        if(w!=='active'&&!updateEnable(s,j,'EnableWorkflow','workflowState','active'))fail('ControlEnableUnknown');
        if(workflow(exchange(s,j,'VerifyWorkflow'),b)!=='active')fail('ControlWorkflowNotActive');ref(exchange(s,j,'VerifyRef'),b);
        const dispatch=attempt(s,j,'DispatchOnce');j.runState=dispatch.ok?'Dispatched':'DispatchUnknown';save(s,j);
        const discovered=attempt(s,j,'DiscoverRunOnce');
        if(!discovered.ok)fail('ControlDiscoveryUnknown');
        const list=discovered.value;if(!Array.isArray(list.workflow_runs)||list.workflow_runs.length>100||typeof list.total_count!=='bigint'||list.total_count!==BigInt(list.workflow_runs.length))fail('ControlDiscoveryUnknown');
        // No substring nonce matches, partial candidates, pagination or guessed IDs.
        const runs=list.workflow_runs.map(x=>selectedRun(x,b));if(runs.length!==1)fail('ControlDiscoveryUnknown');
        j.runId=runs[0].id;j.runState='Running';save(s,j);
        for(let i=0;i<CONTROL_LIMITS.statusReads&&j.runState!=='Completed';i++){
          if(!observeRun(s,j,'ObserveRunStatus'))break;
          if(j.runState!=='Completed'&&i<CONTROL_LIMITS.statusReads-1){const left=350000-elapsed(s,j)-CONTROL_LIMITS.perRequestMs;if(left<=0)break;const wait=Math.min(25000,left);s.wall+=wait;s.mono+=wait;}
        }
      }catch(e){if(e instanceof Interrupted)throw e;incident(j,'ControllerExecutionUnknown');if(j.ledger.some(x=>x.op==='DispatchOnce')&&!j.runId){j.runState='Unknown';incident(j,'UndiscoveredDispatchRequiresNamedOperator');}}
      cancel(s,j);restore(s,j);
    }
    try{if(elapsed(s,j)>=CONTROL_LIMITS.totalMs){j.restoration='Unresolved';incident(j,'ControllerDeadlineExceededRequiresNamedOperator');}}
    catch{j.restoration='Unresolved';incident(j,'ControllerClockRefusedRequiresNamedOperator');}
    j.state=j.restoration==='Verified'?'Restored':j.restoration==='NotRequired'?'BlockedWithoutSettingsMutation':'RecoveryRequired';j.terminal=true;save(s,j);return summary(j);
  }finally{s.busy=false;fs.closeSync(fd);fs.unlinkSync(lock);syncDirectory(s.directory);}
}
