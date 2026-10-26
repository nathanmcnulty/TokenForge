// Entire service action candidate. Both public execution and external transport
// remain unconditionally gated; local entry uses only a branded dummy TLS handle.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {keys,fail,strictJson} from '../offline/TokenForgeOfflineSchema.mjs';
import {OfflineArtifactTransaction as Transaction,assertCanonicalOriginal} from '../offline/TokenForgeArtifactTransaction.mjs';
import {assertAuthorization,assertApprovedLocalRuntime,localRuntimeIdentity,assertServiceFixtureContext,createServiceTransport} from './TokenForgeLocalTlsTransport.mjs';
import {serviceModeGate,validatePublicContext} from './TokenForgeCanaryPreflight.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
const root=fileURLToPath(new URL('../../',import.meta.url));
export const APPROVED_OPERATOR_KEY_SHA256='0'.repeat(64); // No trusted live approval signer is configured.
const PWSH_SHA256='873de21f04b6a0269c220f9c8396ff5cd639e8deb058a32cc26df54b69bbff8d';
const DLL_SHA256='30d5d1268223c806e8c6d26fd138ef2f1db58dd23f067f59ac38387e2d7bad32';
function preflight(actual,approved){assertApprovedLocalRuntime();validatePublicContext(actual,approved);const runtime=localRuntimeIdentity();if(actual.nodeSha256!==runtime.sha256||actual.nodeVersion!==runtime.version)fail('ActionRuntimeRefused');}
function subject(parent,actual,pwsh) {
  const stat=fs.lstatSync(parent);if(!path.isAbsolute(parent)||!stat.isDirectory()||stat.isSymbolicLink()||(stat.mode&0o777)!==0o700||stat.uid!==process.getuid())fail('ActionParentRefused');
  if(!path.isAbsolute(pwsh)||hash(fs.readFileSync(pwsh))!==PWSH_SHA256||hash(fs.readFileSync(path.join(root,'src/TokenForge/lib/net8.0/TokenForge.Credentials.dll')))!==DLL_SHA256)fail('SubjectRuntimeRefused');
  const stage=fs.mkdtempSync(path.join(parent,'canary-'));fs.chmodSync(stage,0o700);
  const result=spawnSync(pwsh,['-NoLogo','-NoProfile','-NonInteractive','-File',path.join(root,'scripts/New-TokenForgeCanarySubject.ps1'),'-Parent',stage,'-Source',actual.source,'-RunId',actual.runId,'-Attempt',actual.attempt],{env:{HOME:stage,PATH:'/usr/bin:/bin'},timeout:20000,maxBuffer:32768,encoding:'utf8'});
  if(result.status!==0||result.error||result.stderr)fail('SyntheticSubjectRefused');
  let receipt;try{receipt=JSON.parse(result.stdout);}catch{fail('SyntheticSubjectRefused');}
  keys(receipt,['Kind','Sha256','Bytes','ArchiveProfile','CompleteOriginalZipPrivacyValidated','BusinessSchemasValidated','OperationalApproval']);
  const original=fs.readFileSync(path.join(stage,'subject/original.zip'));assertCanonicalOriginal(original);
  if(receipt.Kind!=='SyntheticCanarySubject'||receipt.Sha256!==hash(original)||receipt.Bytes!==original.length||receipt.ArchiveProfile!=='CanonicalStoredOriginalZipV1'||receipt.CompleteOriginalZipPrivacyValidated!==true||receipt.BusinessSchemasValidated!==true||receipt.OperationalApproval!==false)fail('SyntheticSubjectRefused');
  return {original,stage};
}
async function execute(options,external=false){
  const actual=options.publicContext,approved=options.approved;
  preflight(actual,approved);
  const parent=options.parent,pwsh=options.pwsh;
  if(options.authorization)assertAuthorization(options.authorization);
  if(!external)assertServiceFixtureContext(options.transport,actual);
  const built=subject(parent,actual,pwsh); // Complete C privacy/business gate first.
  // Runtime availability/backend routing alone never proves approval. An external
  // call additionally requires the reviewed plan digest in runServiceActionCandidate.
  if(options.authorization)assertAuthorization(options.authorization);
  const transport=external?createServiceTransport({publicContext:actual,approved,backendIds:options.backendIds,authorization:options.authorization,credentials:{Runtime:process.env.ACTIONS_RUNTIME_TOKEN,Read:process.env.TF_CANARY_READ_TOKEN}}):options.transport;
  const tx=Transaction.prepare({parent:built.stage,original:built.original,context:Object.fromEntries(['repository','repositoryId','workflowId','source','runId','attempt'].map(k=>[k,actual[k]])),transport});
  try{for(let i=0;i<4&&['Prepared','Created','BlockAck','Committed'].includes(tx.snapshot().state);i++)await tx.advance();const result=await tx.observe();return {...result,syntheticSubject:true,completeOriginalPrivacyAndBusinessValidated:true,operationalApproval:false};}finally{tx.close();}
}
export async function runLocalServiceFixtureAction(options){
  keys(options,['publicContext','approved','parent','pwsh','transport',...('authorization' in options?['authorization']:[])]);return execute(options);
}
export function verifySignedPlan(bytes,signature,keyBytes,expectedKeySha256,now=Date.now()){
  if(!Buffer.isBuffer(bytes)||bytes.length>65536||!Buffer.isBuffer(signature)||signature.length!==64||!Buffer.isBuffer(keyBytes)||keyBytes.length>4096||hash(keyBytes)!==expectedKeySha256)fail('ActivationPlanNotApproved');
  let key;try{key=createPublicKey(keyBytes);}catch{fail('ActivationPlanNotApproved');}
  if(key.asymmetricKeyType!=='ed25519'||!verify(null,bytes,key,signature))fail('ActivationPlanNotApproved');
  const plan=strictJson(bytes);
  keys(plan,['created','expires','workflowCommit','workflowRef','publicContext','approved','sourceSha256','privateParent','pwsh','backendIds','recoveryOwner']);
  if(!Number.isSafeInteger(plan.created)||!Number.isSafeInteger(plan.expires)||plan.created>now||plan.expires<=now||plan.expires-plan.created>480000||typeof plan.recoveryOwner!=='string'||!/^[-A-Za-z0-9]{1,39}$/.test(plan.recoveryOwner))fail('ActivationPlanNotApproved');
  return plan; // Signer authorization is separate from hosted custody enforcement.
}
function loadApprovedPlan(){
  const directory='/opt/tokenforge-canary-approval';
  return verifySignedPlan(fs.readFileSync(directory+'/plan.json'),fs.readFileSync(directory+'/plan.sig'),fs.readFileSync(directory+'/operator.pub'),APPROVED_OPERATOR_KEY_SHA256);
}
export function executionSourceSnapshot(){
  const paths=['.github/actions/tokenforge-canary/action.yml','.github/actions/tokenforge-canary/index.mjs','scripts/transport/TokenForgeCanaryAction.mjs','scripts/transport/TokenForgeLocalTlsTransport.mjs','scripts/transport/TokenForgeCanaryPreflight.mjs','scripts/offline/TokenForgeArtifactProtocol.mjs','scripts/offline/TokenForgeArtifactTransaction.mjs','scripts/offline/TokenForgeOfflineClock.mjs','scripts/offline/TokenForgeOfflineSchema.mjs','scripts/New-TokenForgeCanarySubject.ps1','scripts/TokenForgeSealer.ps1','scripts/TokenForgeSealerZip.ps1','scripts/TokenForgePublicationAdapter.ps1','scripts/TokenForgeDiscoveryCandidate.ps1','scripts/TokenForgeCiState.ps1','scripts/TokenForgeCiEvidenceQueue.ps1','scripts/TokenForgePublicationRecovery.ps1','scripts/TokenForgePublicPermissions.ps1'];
  function walk(relative){const directory=path.join(root,relative),entry=fs.lstatSync(directory);if(!entry.isDirectory()||entry.isSymbolicLink()||fs.realpathSync(directory)!==directory)fail('ActionClosureRefused');for(const name of fs.readdirSync(directory)){const child=relative+'/'+name,stat=fs.lstatSync(path.join(root,child));if(stat.isSymbolicLink()||!stat.isDirectory()&&!stat.isFile())fail('ActionClosureRefused');if(stat.isDirectory())walk(child);else paths.push(child);if(paths.length>512)fail('ActionClosureRefused');}}
  walk('src/TokenForge');const snapshot={};let size=0;for(const name of paths.sort()){const full=path.join(root,name),stat=fs.lstatSync(full);if(!stat.isFile()||stat.isSymbolicLink()||fs.realpathSync(full)!==full||(size+=stat.size)>16777216)fail('ActionClosureRefused');snapshot[name]=hash(fs.readFileSync(full));}return snapshot;
}
export function inspectPublicActionContext(plan,publicEnvironment){
  // Read public slots only. Workflow SHA is a commit, not a workflow blob digest.
  if(publicEnvironment.GITHUB_EVENT_NAME!=='workflow_dispatch'||publicEnvironment.GITHUB_SHA!==plan.workflowCommit||publicEnvironment.GITHUB_WORKFLOW_SHA!==plan.workflowCommit||publicEnvironment.GITHUB_WORKFLOW_REF!==plan.workflowRef||publicEnvironment.GITHUB_REF!=='refs/heads/'+plan.publicContext.sourceRef)fail('ActionWorkflowRefused');
  for(const name of ['NODE_OPTIONS','NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED','NODE_DEBUG','NODE_DEBUG_NATIVE','OPENSSL_CONF','OPENSSL_MODULES','LD_PRELOAD','LD_LIBRARY_PATH','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY'])if(publicEnvironment[name])fail('ActionEnvironmentRefused');
  const actual={...plan.publicContext,repository:publicEnvironment.GITHUB_REPOSITORY,repositoryId:publicEnvironment.GITHUB_REPOSITORY_ID,runId:publicEnvironment.GITHUB_RUN_ID,attempt:publicEnvironment.GITHUB_RUN_ATTEMPT,source:publicEnvironment.GITHUB_SHA,runnerOs:publicEnvironment.RUNNER_OS,runnerArch:publicEnvironment.RUNNER_ARCH,resultsOrigin:publicEnvironment.ACTIONS_RESULTS_URL,actionSha256:hash(fs.readFileSync(path.join(root,'.github/actions/tokenforge-canary/index.mjs'))),nodeVersion:localRuntimeIdentity().version,nodeSha256:localRuntimeIdentity().sha256,nodeOptions:publicEnvironment.NODE_OPTIONS??'',execArgv:[...process.execArgv]};
  if(actual.runId!==plan.publicContext.runId||actual.attempt!==plan.publicContext.attempt||publicEnvironment.GITHUB_JOB!=='canary')fail('ActionRunRefused');
  const snapshot=executionSourceSnapshot();keys(plan.sourceSha256,Object.keys(snapshot));for(const [name,expected] of Object.entries(snapshot))if(plan.sourceSha256[name]!==expected)fail('ActionClosureRefused');
  preflight(actual,plan.approved);
  return actual;
}
export async function runServiceActionCandidate(){
  serviceModeGate(); // Before plan, public environment, tools or credentials.
  const plan=loadApprovedPlan(),authorization={expires:plan.expires,monotonicDeadline:Number(process.hrtime.bigint()/1000000n)+Math.max(0,plan.expires-Date.now())},actual=inspectPublicActionContext(plan,process.env);
  preflight(actual,plan.approved);
  return execute({publicContext:actual,approved:plan.approved,parent:plan.privateParent,pwsh:plan.pwsh,backendIds:plan.backendIds,authorization},true);
}
