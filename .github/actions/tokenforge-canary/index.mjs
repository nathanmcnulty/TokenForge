import {serviceModeGate} from '../../../scripts/transport/TokenForgeCanaryPreflight.mjs';
import {runServiceActionCandidate} from '../../../scripts/transport/TokenForgeCanaryAction.mjs';
import {pathToFileURL} from 'node:url';
export async function runDormantCanaryAction(){serviceModeGate();return runServiceActionCandidate();}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  try{await runDormantCanaryAction();}catch{process.stderr.write('TokenForgeServiceModeDisabled\n');process.exitCode=1;}
}
