import fs from 'node:fs';
import {randomBytes} from 'node:crypto';
import {fail} from './TokenForgeOfflineSchema.mjs';
const clocks=new WeakMap();
export function createFakeClock(wall=1000000) {
  if(!Number.isSafeInteger(wall) || wall<0) fail('ClockRefused');
  const state={wall,mono:0,boot:randomBytes(16).toString('hex')};const handle=Object.freeze({advance(ms){if(!Number.isSafeInteger(ms)) fail('ClockRefused');state.wall+=ms;state.mono+=Math.max(0,ms);}});
  clocks.set(handle,state);return handle;
}
export function clockNow(handle) {
  if(handle===undefined) return {wall:Date.now(),mono:Number(process.hrtime.bigint()/1000000n),boot:fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim()};
  const c=clocks.get(handle);if(!c) fail('ClockRefused');return {...c};
}


export function isFakeClock(handle){return clocks.has(handle);}
export function assertWithinDeadline(clock,j){const t=clockNow(clock);if(t.boot!==j.boot||t.wall<j.lastWall||t.wall>=j.deadline||t.mono<j.lastMono||t.mono>=j.deadlineMono)fail('DeadlineRefused');return t;}
