// Pure bounded JSON/identity validators shared by the offline model. No IO.
export const fail = code => {throw new Error(code);};
export const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
export function keys(x, names) {if (!object(x) || Object.keys(x).length !== names.length || Object.keys(x).sort().some((k,i)=>k!==[...names].sort()[i])) fail('SchemaRefused');}
export function id(x) {if(typeof x !== 'string' || !/^[1-9][0-9]{0,19}$/.test(x) || BigInt(x)>9223372036854775807n) fail('IdentityRefused');return x;}
export function context(x) {
  keys(x,['repository','repositoryId','workflowId','runId','attempt','source']);
  if(typeof x.repository !== 'string' || !/^[A-Za-z0-9_-]{1,39}\/[A-Za-z0-9_-]{1,100}$/.test(x.repository) || typeof x.source !== 'string' || !/^[0-9a-f]{40}$/.test(x.source)) fail('IdentityRefused');
  for(const k of ['repositoryId','workflowId','runId','attempt']) id(x[k]);
  return Object.fromEntries(['repository','repositoryId','workflowId','runId','attempt','source'].map(k=>[k,x[k]]));
}
// JSON.parse alone silently accepts duplicate members. First walk the complete
// JSON grammar with per-object decoded-key sets (including escaped duplicates).
function readJson(bytes, integersAsBigInt=false) {
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);let i=0;
  const ws=()=>{while(/[ \t\r\n]/.test(text[i]??'!')) i++;};
  const string=()=>{
    const start=i;if(text[i++]!=='"') fail('JsonRefused');
    while(i<text.length){const c=text[i++];if(c==='"') return JSON.parse(text.slice(start,i));if(c==='\\') i++;}
    fail('JsonRefused');
  };
  function value(depth=0) {
    if(depth>32) fail('JsonRefused');ws();const c=text[i];
    if(c==='{'||c==='[') {
      i++;ws();const isObject=c==='{',end=isObject?'}':']',seen=new Set(),out=isObject?{}:[];
      if(text[i]===end){i++;return out;}
      for(;;) {
        let key;
        if(isObject){ws();key=string();if(seen.has(key)) fail('JsonRefused');seen.add(key);ws();if(text[i++]!==':') fail('JsonRefused');}
        const item=value(depth+1);
        if(isObject) Object.defineProperty(out,key,{value:item,enumerable:true,writable:true,configurable:true});else out.push(item);
        ws();if(text[i]===end){i++;return out;}if(text[i++]!==',') fail('JsonRefused');
      }
    }
    if(c==='"') return string();
    const match=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));
    if(!match) fail('JsonRefused');i+=match[0].length;
    if(integersAsBigInt && /^-?(?:0|[1-9][0-9]*)$/.test(match[0])) {
      if(match[0].startsWith('-')) fail('JsonRefused');return BigInt(match[0]);
    }
    return JSON.parse(match[0]);
  }
  const result=value();ws();if(i!==text.length) fail('JsonRefused');return result;
}

export function strictJson(bytes, integersAsBigInt=false) {
  try {return readJson(bytes,integersAsBigInt);} catch {fail('JsonRefused');}
}
