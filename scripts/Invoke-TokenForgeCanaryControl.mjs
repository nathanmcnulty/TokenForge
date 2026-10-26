// No command-line dispatch path. The controller stays dormant for every input.
import {executeCanaryControl} from './transport/TokenForgeCanaryControl.mjs';
try{executeCanaryControl();}catch{process.stderr.write('TokenForgeServiceModeDisabled\n');process.exitCode=1;}
