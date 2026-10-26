import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createControlRecordingFixture,runLocalCanaryControl,executeCanaryControl,assertApprovedControlRuntime,CONTROL_LIMITS,CONTROL_BLOCKERS} from '../scripts/transport/TokenForgeCanaryControl.mjs';

// The approved executable is checked BEFORE any temporary directory or fixture.
assert.deepEqual(assertApprovedControlRuntime(),{version:'24.18.1',sha256:'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a'});
const binding={repository:'nathanmcnulty/TokenForge',repositoryId:'1402673320',workflowId:'373691621',workflowPath:'.github/workflows/ci.yml',defaultBranch:'main',source:'a'.repeat(40),sourceRef:'codex/goal6-canary-synthetic',workflowSha256:'b'.repeat(64),activationSha256:'c'.repeat(64),actor:'synthetic-operator',actorId:'4242',nonce:'synthetic'};
const initial={repositoryId:'1402673320',workflowId:'373691621',enabled:false,allowedActions:'selected',shaPinningRequired:true,workflowState:'disabled_manually'};
let root;
before(()=>{root=fs.mkdtempSync(path.join(os.tmpdir(),'tf-control-'));fs.chmodSync(root,0o700);});
after(()=>{if(root)fs.rmSync(root,{recursive:true,force:true});});
function fixture(options={}) {
 const handle=createControlRecordingFixture({binding,initial,...options}),directory=fs.mkdtempSync(path.join(root,'run-'));fs.chmodSync(directory,0o700);
 const args={directory,binding,recoveryOwner:'synthetic-recovery-owner'};
 return {handle,directory,args,run:()=>runLocalCanaryControl(handle,args),journal:()=>JSON.parse(fs.readFileSync(path.join(directory,'journal.json'),'utf8'))};
}
function count(handle,op){return handle.transcript().filter(x=>x.op===op).length;}
function bounded(r) {
 assert.ok(r.attempts<=29);assert.ok(r.attempts<=CONTROL_LIMITS.attempts);assert.ok(r.mutations<=6);assert.ok(r.elapsedMs<=CONTROL_LIMITS.totalMs);
 assert.equal(r.ledger.filter(x=>x.write).length,r.mutations);
 assert.equal(r.reservedEntityBytes,r.ledger.reduce((n,x)=>n+x.requestBytes+x.responseReservation,0));
 for(const entry of r.ledger){assert.equal(entry.responseReservation,1048576);assert.ok(entry.requestBytes<=1048576);}
 assert.ok(r.ledger.filter(x=>x.op==='DispatchOnce').length<=1);assert.ok(r.ledger.filter(x=>x.op==='DiscoverRunOnce').length<=1);assert.ok(r.ledger.filter(x=>x.op==='CancelKnownRun').length<=1);
}

test('local controller executes exact fixed routes and restores only original enablement bits',async()=>{
 const f=fixture(),r=await f.run();bounded(r);
 assert.equal(r.restoration,'Verified');assert.equal(r.state,'Restored');assert.equal(r.runState,'Completed');assert.equal(r.runConclusion,'success');assert.equal(r.runId,'7001');
 assert.deepEqual(r.incidents,[]);assert.equal(r.controllerExecutionEnabled,false);assert.equal(r.externalControlEnabled,false);assert.equal(r.localFixtureOnly,true);assert.equal(r.githubCasEstablished,false);assert.deepEqual(r.liveBlockers,CONTROL_BLOCKERS);
 assert.deepEqual(f.handle.effects(),['EnableRepository','EnableWorkflow','DispatchOnce','RestoreWorkflow','RestoreRepository']);
 assert.deepEqual(f.handle.snapshot(),{enabled:false,workflowState:'disabled_manually',ref:binding.source,custodyHeld:true});
 const records=f.handle.transcript();assert.ok(records.every(x=>x.intentDurable));assert.equal(r.attempts,17);assert.equal(r.mutations,5);
 assert.deepEqual(records.find(x=>x.op==='DispatchOnce'),{op:'DispatchOnce',method:'POST',path:'/repos/nathanmcnulty/TokenForge/actions/workflows/373691621/dispatches',requestBytes:Buffer.byteLength(JSON.stringify({ref:binding.sourceRef,inputs:{nonce:binding.nonce}})),requestSha256:r.ledger.find(x=>x.op==='DispatchOnce').requestSha256,intentDurable:true});
 assert.equal(records.find(x=>x.op==='DiscoverRunOnce').path,'/repos/nathanmcnulty/TokenForge/actions/workflows/373691621/runs?actor=synthetic-operator&branch=codex%2Fgoal6-canary-synthetic&event=workflow_dispatch&head_sha='+binding.source+'&per_page=100&page=1');
 assert.equal(fs.statSync(path.join(f.directory,'journal.json')).mode&0o777,0o600);assert.equal(fs.existsSync(path.join(f.directory,'control.lock')),false);
});
test('already-enabled bits are preserved and unused writes are not repurposed',async()=>{
 const f=fixture({initial:{...initial,enabled:true,workflowState:'active'}}),r=await f.run();bounded(r);
 assert.equal(r.restoration,'Verified');assert.deepEqual(f.handle.effects(),['DispatchOnce']);assert.equal(r.mutations,1);assert.equal(f.handle.snapshot().enabled,true);assert.equal(f.handle.snapshot().workflowState,'active');
});
for(const op of ['EnableRepository','EnableWorkflow'])for(const mode of ['before','after'])test(op+'/'+mode+' acknowledgement loss never replays or dispatches',async()=>{
 const f=fixture({faults:{[op]:mode}}),r=await f.run();bounded(r);
 assert.equal(r.restoration,'Verified');assert.equal(r.runState,'NotDispatched');assert.equal(count(f.handle,op),1);assert.equal(count(f.handle,'DispatchOnce'),0);
 assert.equal(r.ledger.find(x=>x.op===op).outcome,'Unknown');assert.ok(r.incidents.includes(op+'Unknown'));assert.equal(f.handle.snapshot().enabled,false);assert.equal(f.handle.snapshot().workflowState,'disabled_manually');
 const bytes=fs.readFileSync(path.join(f.directory,'journal.json')),n=f.handle.transcript().length;assert.deepEqual(await f.run(),r);assert.equal(f.handle.transcript().length,n);assert.deepEqual(fs.readFileSync(path.join(f.directory,'journal.json')),bytes);
});
for(const mode of ['before','after'])test('dispatch/'+mode+' loss spends one discovery slot and never redispatches',async()=>{
 const f=fixture({faults:{DispatchOnce:mode},...(mode==='before'?{discovery:'zero'}:{})}),r=await f.run();bounded(r);
 assert.equal(r.restoration,'Verified');assert.equal(count(f.handle,'DispatchOnce'),1);assert.equal(count(f.handle,'DiscoverRunOnce'),1);assert.equal(r.ledger.find(x=>x.op==='DispatchOnce').outcome,'Unknown');
 assert.equal(r.runId,mode==='after'?'7001':null);assert.equal(count(f.handle,'CancelKnownRun'),0);
 const n=f.handle.transcript().length;await f.run();assert.equal(f.handle.transcript().length,n);
});
for(const op of ['RestoreWorkflow','RestoreRepository'])for(const mode of ['before','after'])test(op+'/'+mode+' acknowledgement loss verifies once without a resend',async()=>{
 const f=fixture({faults:{[op]:mode}}),r=await f.run();bounded(r);
 assert.equal(count(f.handle,op),1);assert.equal(r.ledger.find(x=>x.op===op).outcome,'Unknown');assert.equal(r.restoration,mode==='after'?'Verified':'Unresolved');
 assert.equal(r.recoveryOwner,'synthetic-recovery-owner');if(mode==='before')assert.ok(r.incidents.includes('RestorationUnresolvedRequiresNamedOperator'));
 const n=f.handle.transcript().length;await f.run();assert.equal(f.handle.transcript().length,n);
});
for(const mode of ['zero','multiple','paginated','missing'])test('one-page '+mode+' discovery remains unknown and cannot cancel a guessed run',async()=>{
 const f=fixture({discovery:mode}),r=await f.run();bounded(r);
 assert.equal(r.runId,null);assert.equal(r.runState,'Unknown');assert.equal(r.restoration,'Verified');assert.equal(count(f.handle,'DiscoverRunOnce'),1);assert.equal(count(f.handle,'CancelKnownRun'),0);
});
for(const kind of ['runSource','runRef','runNonce','runWorkflow','runActor','runActorId','runRepository','runAttempt','runEvent','runMissing'])test('discovery rejects exact binding mismatch '+kind,async()=>{
 const f=fixture({responseFault:{op:'DiscoverRunOnce',kind}}),r=await f.run();bounded(r);
 assert.equal(r.runId,null);assert.equal(count(f.handle,'CancelKnownRun'),0);assert.equal(r.restoration,'Verified');
});
test('every selected run status retains exact discovered run identity',async()=>{
 const f=fixture({responseFault:{op:'ObserveRunStatus',kind:'runId'}}),r=await f.run();bounded(r);
 assert.ok(r.incidents.includes('SelectedRunIdentityUnknown'));assert.equal(r.runId,'7001');
 assert.equal(count(f.handle,'CancelKnownRun'),1);assert.equal(r.runConclusion,'cancelled');assert.equal(r.restoration,'Verified');
});
test('ten status slots bound polling, one cancellation and two observations retain reserve',async()=>{
 const f=fixture({statuses:Array(10).fill('in_progress')}),r=await f.run();bounded(r);
 assert.equal(count(f.handle,'ObserveRunStatus'),10);assert.equal(count(f.handle,'CancelKnownRun'),1);assert.equal(count(f.handle,'ObserveCancellation'),1);assert.equal(r.mutations,6);assert.equal(r.attempts,28);assert.equal(r.runConclusion,'cancelled');assert.equal(r.restoration,'Verified');
});
for(const mode of ['before','after'])test('cancel/'+mode+' acknowledgement loss cannot resend and retains named recovery',async()=>{
 const f=fixture({statuses:Array(10).fill('in_progress'),faults:{CancelKnownRun:mode}}),r=await f.run();bounded(r);
 assert.equal(count(f.handle,'CancelKnownRun'),1);assert.equal(r.ledger.find(x=>x.op==='CancelKnownRun').outcome,'Unknown');assert.equal(r.restoration,'Verified');assert.equal(r.recoveryOwner,'synthetic-recovery-owner');
 assert.equal(count(f.handle,'ObserveCancellation'),mode==='before'?2:1);assert.equal(r.attempts,mode==='before'?29:28);assert.equal(r.recoveryRequired,mode==='before');
 if(mode==='before'){assert.equal(r.runState,'Unknown');assert.ok(r.incidents.includes('SelectedRunCompletionUnknownRequiresNamedOperator'));}
 const n=f.handle.transcript().length;await f.run();assert.equal(f.handle.transcript().length,n);
});
test('phase deadlines preserve cancellation/restoration even when each request approaches ten seconds',async()=>{
 const f=fixture({requestMs:9900,statuses:Array(10).fill('in_progress')}),r=await f.run();bounded(r);
 assert.equal(r.restoration,'Verified');assert.equal(r.mutations,6);assert.ok(count(f.handle,'ObserveRunStatus')<10);assert.equal(count(f.handle,'CancelKnownRun'),1);
 const start=f.journal().startMono;
 for(const entry of r.ledger){
  const stop=entry.op==='ObserveRunStatus'?350000:['CancelKnownRun','ObserveCancellation'].includes(entry.op)?380000:/Restore/.test(entry.op)?440000:['DispatchOnce','DiscoverRunOnce'].includes(entry.op)?100000:80000;
  assert.ok(entry.startedMono-start+10000<=stop);
 }
 assert.ok(r.elapsedMs<440000);
});
test('late response is unknown, charged once and cannot enable the next phase',async()=>{
 const f=fixture({requestMs:10001}),r=await f.run();bounded(r);
 assert.equal(r.attempts,1);assert.equal(r.ledger[0].outcome,'Unknown');assert.equal(r.restoration,'NotRequired');assert.deepEqual(f.handle.effects(),[]);
});
for(const custody of ['unavailable','boolean-only'])test(custody+' custody is blocked before any attempt',async()=>{
 const f=fixture({custody}),r=await f.run();bounded(r);assert.equal(r.attempts,0);assert.equal(r.restoration,'NotRequired');assert.equal(r.state,'BlockedWithoutSettingsMutation');assert.ok(r.liveBlockers.includes('GitHubRefAndSettingsExclusiveCustodyNotEstablished'));
});
test('fixture authority excludes competing ref, workflow and policy writers',async()=>{
 const f=fixture();for(const change of ['ref','workflow','settings'])assert.equal(f.handle.competingWrite(change),false);
 const r=await f.run();assert.equal(r.restoration,'Verified');f.handle.revokeCustody();assert.equal(f.handle.competingWrite('settings'),true);
});
for(const op of ['EnableWorkflow','BeforeRestoreWorkflow','RestoreRepository'])test('loss of exclusive custody at '+op+' stops writes and names recovery owner',async()=>{
 const f=fixture({loseCustodyAt:op}),r=await f.run();bounded(r);
 assert.equal(r.restoration,'Unresolved');assert.equal(r.state,'RecoveryRequired');assert.equal(r.recoveryOwner,'synthetic-recovery-owner');assert.ok(r.incidents.includes('RestorationUnresolvedRequiresNamedOperator'));
 const at=f.handle.transcript().findIndex(x=>x.op===op);assert.ok(at>=0);assert.equal(f.handle.transcript().slice(at+1).length,0);
});
for(const kind of ['oversize','json','redirect'])test('bounded sanitized '+kind+' response remains unknown without leaking bytes',async()=>{
 const f=fixture({responseFault:{op:'DispatchOnce',kind}}),r=await f.run();bounded(r);
 assert.equal(r.ledger.find(x=>x.op==='DispatchOnce').outcome,'Unknown');assert.equal(count(f.handle,'DispatchOnce'),1);assert.equal(r.restoration,'Verified');
 assert.doesNotMatch(JSON.stringify(r)+JSON.stringify(f.journal())+JSON.stringify(f.handle.transcript()),/SYNTHETIC_RESPONSE_SECRET|Bearer|authorization|GITHUB_TOKEN/);
});
for(const kind of ['policy','extraPolicy'])test('changed or unknown policy in restore read '+kind+' is never overwritten',async()=>{
 const f=fixture({responseFault:{op:'BeforeRestoreSettings',kind}}),r=await f.run();bounded(r);
 assert.equal(r.restoration,'Unresolved');assert.equal(count(f.handle,'RestoreWorkflow'),0);assert.equal(count(f.handle,'RestoreRepository'),0);
});
for(const op of ['EnableRepository','EnableWorkflow','DispatchOnce'])for(const mode of ['interruptBefore','interruptAfter'])test('durable '+op+'/'+mode+' intent recovers restoration without replay',async()=>{
 const f=fixture({faults:{[op]:mode}});await assert.rejects(f.run());
 const j=f.journal();assert.equal(j.ledger.at(-1).op,op);assert.equal(j.ledger.at(-1).outcome,'Intent');
 const charged=j.ledger.length,writes=j.mutations;
 const r=await f.run();bounded(r);assert.equal(r.restoration,'Verified');assert.equal(count(f.handle,op),1);assert.ok(r.attempts>=charged);assert.ok(r.mutations>=writes);assert.equal(r.ledger.find(x=>x.op===op).outcome,'Unknown');assert.ok(r.incidents.includes('InterruptedExecutionRecoveryOnly'));
 if(op==='DispatchOnce'){assert.equal(count(f.handle,'DiscoverRunOnce'),0);assert.ok(r.incidents.includes('UndiscoveredDispatchRequiresNamedOperator'));}
});
test('interrupted restoration stays unresolved and never replays an unacknowledged restore',async()=>{
 const f=fixture({faults:{RestoreWorkflow:'interruptAfter'}});await assert.rejects(f.run());assert.equal(f.journal().ledger.at(-1).outcome,'Intent');
 const n=f.handle.transcript().length,r=await f.run();bounded(r);
 assert.equal(r.restoration,'Unresolved');assert.equal(count(f.handle,'RestoreWorkflow'),1);assert.equal(f.handle.transcript().length,n);assert.ok(r.incidents.includes('InterruptedRestorationRequiresNamedOperator'));assert.equal(r.recoveryOwner,'synthetic-recovery-owner');
});
for(const op of ['CancelKnownRun','ObserveCancellation'])for(const mode of ['interruptBefore','interruptAfter'])test('interrupted '+op+'/'+mode+' requires named run recovery without another cancellation',async()=>{
 const f=fixture({statuses:Array(10).fill('in_progress'),faults:{[op]:mode}});await assert.rejects(f.run());
 const cancelled=count(f.handle,'CancelKnownRun'),observed=count(f.handle,'ObserveCancellation'),r=await f.run();bounded(r);
 assert.equal(r.runId,'7001');assert.equal(r.runState,'Unknown');assert.equal(r.recoveryRequired,true);assert.equal(r.restoration,'Verified');assert.equal(r.recoveryOwner,'synthetic-recovery-owner');
 assert.ok(r.incidents.includes('InterruptedCancellationRequiresNamedOperator'));assert.equal(count(f.handle,'CancelKnownRun'),cancelled);assert.equal(count(f.handle,'ObserveCancellation'),observed);assert.equal(r.ledger.find(x=>x.op===op).outcome,'Unknown');
});
test('expired interrupted state cannot restart its deadlines or consume restoration attempts',async()=>{
 const f=fixture({faults:{DispatchOnce:'interruptAfter'}});await assert.rejects(f.run());const j=f.journal(),charged=j.ledger.length;
 f.handle.advance(480001);const r=await f.run();assert.equal(r.attempts,charged);assert.equal(r.restoration,'Unresolved');assert.equal(f.journal().startMono,j.startMono);assert.equal(count(f.handle,'DispatchOnce'),1);
});
test('wall-clock rollback during recovery returns a durable named-operator incident without another request',async()=>{
 const f=fixture({faults:{EnableRepository:'interruptAfter'}});await assert.rejects(f.run());const n=f.handle.transcript().length,savedNow=Date.now,rolledBack=savedNow()-100000;
 let r;try{Date.now=()=>rolledBack;r=await f.run();}finally{Date.now=savedNow;}
 assert.equal(r.state,'RecoveryRequired');assert.equal(r.restoration,'Unresolved');assert.equal(r.recoveryRequired,true);assert.equal(r.recoveryOwner,'synthetic-recovery-owner');assert.ok(r.incidents.includes('ControllerClockRefusedRequiresNamedOperator'));assert.equal(f.handle.transcript().length,n);assert.equal(f.journal().terminal,true);
});
test('stale lock refuses takeover and preserves exact journal bytes',async()=>{
 const f=fixture();await f.run();const file=path.join(f.directory,'journal.json'),bytes=fs.readFileSync(file);fs.writeFileSync(path.join(f.directory,'control.lock'),'stale',{mode:0o600});
 await assert.rejects(f.run(),/ControlStoreLockedRequiresNamedOperator/);assert.deepEqual(fs.readFileSync(file),bytes);
});
test('tampered durable charge or binding is refused rather than replayed',async()=>{
 const f=fixture({faults:{DispatchOnce:'interruptAfter'}});await assert.rejects(f.run());const file=path.join(f.directory,'journal.json'),j=f.journal();j.mutations=0;j.ledger=[];fs.writeFileSync(file,JSON.stringify(j),{mode:0o600});
 const n=f.handle.transcript().length;await assert.rejects(f.run(),/ControlJournalBindingRefused/);assert.equal(f.handle.transcript().length,n);
});
test('different fixture authority cannot reconstruct or resume another control journal',async()=>{
 const f=fixture();await f.run();const other=createControlRecordingFixture({binding,initial});
 await assert.rejects(runLocalCanaryControl(other,f.args),/ControlJournalBindingRefused/);
});
test('arbitrary handles, callbacks, tokens, endpoints and boolean authority are not transport capabilities',async()=>{
 let touched=0;const trapped=new Proxy({},{get(){touched++;throw Error('SecretRead');},ownKeys(){touched++;throw Error('SecretRead');}});
 await assert.rejects(runLocalCanaryControl(trapped,trapped),/ControlFixtureAuthorityRequired/);assert.equal(touched,0);
 for(const extra of [{exchange:()=>{}},{transport:()=>{}},{token:'SYNTHETIC_NO_USE'},{hostname:'api.github.com'},{exclusiveCustody:true}])assert.throws(()=>createControlRecordingFixture({binding,initial,...extra}),/ControlFixtureRefused/);
 assert.throws(()=>createControlRecordingFixture({binding,initial,statuses:[()=>{}]}),/ControlFixtureRefused/);
});
for(const [key,value] of Object.entries({repository:'other/repo',repositoryId:'1',workflowId:'2',workflowPath:'.github/workflows/other.yml',defaultBranch:'other',source:'invalid',sourceRef:'main',workflowSha256:'invalid',activationSha256:'invalid',nonce:'other'}))test('controller rejects unbound '+key+' before store creation',async()=>{
 const before=fs.readdirSync(root);assert.throws(()=>createControlRecordingFixture({binding:{...binding,[key]:value},initial}));assert.deepEqual(fs.readdirSync(root),before);
});
test('journal directory cannot be redirected through a symlink or broad access path',async()=>{
 const f=fixture(),alias=path.join(root,'alias');fs.symlinkSync(f.directory,alias);
 await assert.rejects(runLocalCanaryControl(f.handle,{...f.args,directory:alias}),/ControlStoreRefused/);fs.unlinkSync(alias);
 fs.chmodSync(f.directory,0o755);await assert.rejects(f.run(),/ControlStoreRefused/);assert.equal(fs.existsSync(path.join(f.directory,'journal.json')),false);
});
test('service function and actual controller entrypoint remain unconditionally disabled',()=>{
 let reads=0;const trapped=new Proxy({},{get(){reads++;throw Error();},ownKeys(){reads++;throw Error();}});assert.throws(()=>executeCanaryControl(trapped),/ServiceModeDisabled/);assert.equal(reads,0);
 const result=spawnSync(process.execPath,['scripts/Invoke-TokenForgeCanaryControl.mjs'],{cwd:new URL('..',import.meta.url),env:{PATH:'/usr/bin:/bin',GITHUB_TOKEN:'SYNTHETIC_NO_USE'},encoding:'utf8',timeout:5000});
 assert.equal(result.status,1);assert.equal(result.stdout,'');assert.equal(result.stderr,'TokenForgeServiceModeDisabled\n');
});
