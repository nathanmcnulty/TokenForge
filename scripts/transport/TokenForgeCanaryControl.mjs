// Dormant controller: pure bounded procedure and restore checks, no HTTP client.
import {keys,fail,id} from '../offline/TokenForgeOfflineSchema.mjs';
import {serviceModeGate} from './TokenForgeCanaryPreflight.mjs';
export const CONTROL_LIMITS=Object.freeze({attempts:30,mutations:6,totalMs:480000,perRequestMs:10000,bodyBytes:1048576,dispatches:1,runLookups:1,statusReads:10,cancelAttempts:1});
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
  for(const x of [original,lastApplied,current]) {
    keys(x,['repositoryId','workflowId','enabled','allowedActions','shaPinningRequired','workflowState']);id(x.repositoryId);id(x.workflowId);if(x.repositoryId!=='1402673320'||x.workflowId!=='373691621')fail('RestorationStateRefused');
    if(typeof x.enabled!=='boolean'||typeof x.shaPinningRequired!=='boolean'||!['all','local_only','selected'].includes(x.allowedActions)||!['active','disabled_manually'].includes(x.workflowState))fail('RestorationStateRefused');
  }
  if(JSON.stringify(lastApplied)!==JSON.stringify(current)||original.repositoryId!==current.repositoryId||original.workflowId!==current.workflowId||original.allowedActions!==current.allowedActions||original.shaPinningRequired!==current.shaPinningRequired)fail('RestorationConflict');
  return {kind:'DormantRestorationPlan',executable:false,casSupportEstablished:false,requiresExclusiveCustody:true,
    operations:[{method:'PUT',path:`/repos/nathanmcnulty/TokenForge/actions/workflows/${original.workflowId}/${original.workflowState==='active'?'enable':'disable'}`,body:null},
      {method:'PUT',path:'/repos/nathanmcnulty/TokenForge/actions/permissions',body:{enabled:original.enabled}}]};
}
