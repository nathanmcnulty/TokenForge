import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {assertApprovedLocalRuntime} from '../scripts/transport/TokenForgeLocalTlsTransport.mjs';

// Reuse the reviewed local Linux Node pin before creating any fixture. Python
// and Git are existing local tools; these tests make no hosted-runtime claim.
assertApprovedLocalRuntime();
const script=fileURLToPath(new URL('../scripts/TokenForgeCanaryBootstrap.py',import.meta.url));
const load=String.raw`
import os, pathlib, stat, subprocess, sys, tempfile, time, types
m=types.ModuleType("bootstrap_fixture")
with open(sys.argv[1],"rb") as source:
    exec(compile(source.read(),sys.argv[1],"exec"),m.__dict__)
`;
function python(body,environment={}) {
 const r=spawnSync('/usr/bin/python3',['-I','-S','-B','-c',load+'\n'+body,script],{env:{PATH:'/usr/bin:/bin',LC_ALL:'C',...environment},encoding:'utf8',timeout:25000,maxBuffer:1024*1024});
 assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);assert.equal(r.stdout,'');
}
const fixture=String.raw`
m._check_git_executable()
with tempfile.TemporaryDirectory(prefix="tf-bootstrap-fixture-",dir="/tmp") as fixture_root:
    root=pathlib.Path(fixture_root)
    repo=root/"source.git"
    template=root/"template";template.mkdir(mode=0o700)
    environment=m._child_environment(root/"fixture-home")
    environment.update({"GIT_AUTHOR_DATE":"2000-01-01T00:00:00Z","GIT_COMMITTER_DATE":"2000-01-01T00:00:00Z"})
    def git(*arguments,input=None):
        command=[m.GIT_EXECUTABLE,"--no-replace-objects","--no-lazy-fetch"]
        for config in (*m._GIT_CONFIG,"user.name=Synthetic Fixture","user.email=fixture@example.invalid"):
            command.extend(("-c",config))
        command.extend(("--git-dir="+str(repo),*arguments))
        result=subprocess.run(command,input=input,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                              env=environment,cwd=root,check=True,timeout=5)
        return result.stdout
    git("init","--bare","--object-format=sha1","--template="+str(template))
    def tree(entries):
        children={}
        for mode,name,data in entries:
            first,separator,remainder=name.partition("/")
            children.setdefault(first,[]).append((mode,remainder,data)) if separator else children.update({first:(mode,data)})
        raw=bytearray()
        for name,value in sorted(children.items()):
            if isinstance(value,list):
                mode,kind,oid="040000",b"tree",tree(value).encode()
            else:
                mode,data=value;kind=b"blob";oid=git("hash-object","-w","--stdin",input=data).strip()
            raw.extend(mode.encode()+b" "+kind+b" "+oid+b"\t"+name.encode()+b"\0")
        return git("mktree","-z",input=bytes(raw)).strip().decode()
    def commit(entries):
        return git("commit-tree",tree(entries),"-m","Synthetic offline fixture").strip().decode()
`;
function withFixture(body){python(fixture+'\n'+body.split('\n').map(line=>'    '+line).join('\n'));}

test('CLI and future entry gates precede arguments, environment, tools and temporary files',()=>{
 python(String.raw`
class Trap:
    def __getattribute__(self,name): raise AssertionError("Unexpected input access")
    def __len__(self): raise AssertionError("Unexpected input access")
    def __getitem__(self,key): raise AssertionError("Unexpected input access")
def unexpected(*args,**kwargs): raise AssertionError("Unexpected side effect")
old_argv=sys.argv;old_environment=os.environ
sys.argv=Trap();os.environ=Trap()
m._check_git_executable=unexpected;m._git=unexpected
m.tempfile.TemporaryDirectory=unexpected
try:
    for call in (m.main,lambda:m._future_bootstrap(Trap(),Trap())):
        try: call()
        except m.BootstrapRefused as error: assert str(error)=="TokenForgeServiceModeDisabled"
        else: raise AssertionError("Gate missing")
finally:
    sys.argv=old_argv;os.environ=old_environment
`);
 const r=spawnSync('/usr/bin/python3',['-I','-S','-B',script,'invalid-source','/nonexistent/should-not-be-created'],{env:{PATH:'/usr/bin:/bin',GIT_CONFIG_GLOBAL:'/nonexistent/secret',ACTIONS_RUNTIME_TOKEN:'SYNTHETIC_NO_USE',GITHUB_TOKEN:'SYNTHETIC_NO_USE',HTTPS_PROXY:'http://127.0.0.1:1',TMPDIR:'/nonexistent/never-created'},encoding:'utf8',timeout:3000});
 assert.equal(r.status,1);assert.equal(r.stdout,'');assert.equal(r.stderr,'TokenForgeServiceModeDisabled\n');
});

test('private empty child home blocks netrc fallback and environment inheritance without altering parent',()=>python(String.raw`
with tempfile.TemporaryDirectory(prefix="tf-bootstrap-home-",dir="/tmp") as temporary:
    root=pathlib.Path(temporary);parent=root/"parent";parent.mkdir(mode=0o700)
    (parent/".netrc").write_text("machine github.com login SYNTHETIC password SYNTHETIC\n")
    os.environ.update({"HOME":str(parent),"HTTPS_PROXY":"http://127.0.0.1:1","LD_PRELOAD":"SYNTHETIC",
                       "GIT_CONFIG_COUNT":"1","GIT_CONFIG_KEY_0":"credential.helper","GIT_CONFIG_VALUE_0":"SYNTHETIC",
                       "GIT_EXEC_PATH":"/nonexistent","GITHUB_TOKEN":"SYNTHETIC","GIT_ASKPASS":"/nonexistent"})
    before=dict(os.environ);home=root/"empty"
    child=m._child_environment(home)
    assert dict(os.environ)==before
    assert child["HOME"]==str(home) and child["HOME"]!=before["HOME"]
    assert stat.S_IMODE(home.stat().st_mode)==0o700
    assert sorted(path.name for path in home.iterdir())==["xdg"]
    assert list((home/"xdg").iterdir())==[]
    for key in ("HTTPS_PROXY","LD_PRELOAD","GIT_CONFIG_KEY_0","GIT_CONFIG_VALUE_0","GIT_EXEC_PATH","GITHUB_TOKEN"):
        assert key not in child
    assert child["GIT_CONFIG_COUNT"]=="0" and child["GIT_ASKPASS"]=="/bin/false"
    assert child["GIT_CONFIG_GLOBAL"]=="/dev/null" and child["GIT_CONFIG_SYSTEM"]=="/dev/null"
`));

test('literal local blobs preserve bytes and Git modes while hooks, filters and attributes stay inert',()=>withFixture(String.raw`
marker=root/"executed"
git("config","filter.danger.smudge","/usr/bin/touch "+str(marker))
hooks=repo/"hooks";hooks.mkdir(mode=0o700)
hook=hooks/"post-checkout";hook.write_text("#!/bin/sh\ntouch "+str(marker)+"\n");hook.chmod(0o700)
literal=b"$Format:%H$\nLiteral\r\n\x00bytes\xff"
entries=[("100644",".gitattributes",b"*.txt filter=danger eol=crlf export-subst\n"),
         ("100644",".gitmodules",b"[submodule \"inert\"]\nurl=https://example.invalid/inert\n"),
         ("100644","literal.txt",literal),("100755","run.sh",b"#!/bin/sh\nexit 99\n"),
         ("100644","nested/source/empty.txt",b""),("100644","nested/source/literal.bin",literal)]
source=commit(entries);destination=root/"export"
result=m._export_local_git_objects_for_fixture(repo,source,destination)
assert result=={"source":source,"files":6,"bytes":sum(len(entry[2]) for entry in entries),"externalFetchExecuted":False,"selectedHostedToolApproved":False}
assert not marker.exists() and not (destination/".git").exists()
for mode,name,data in entries:
    assert (destination/name).read_bytes()==data
    assert stat.S_IMODE((destination/name).stat().st_mode)==(0o755 if mode=="100755" else 0o644)
assert stat.S_IMODE(destination.stat().st_mode)==0o700
assert stat.S_IMODE((destination/"nested").stat().st_mode)==0o700
assert stat.S_IMODE((destination/"nested/source").stat().st_mode)==0o700
`));

test('exact full commit only: refs, abbreviated SHA and noncommit objects are refused',()=>withFixture(String.raw`
source=commit([("100644","file.txt",b"Synthetic")])
blob=git("hash-object","-w","--stdin",input=b"Synthetic").strip().decode()
for index,value in enumerate(("HEAD",source[:12],source+"^{commit}",source.upper(),"-"+source,blob)):
    destination=root/("export"+str(index))
    try: m._export_local_git_objects_for_fixture(repo,value,destination)
    except m.BootstrapRefused: pass
    else: raise AssertionError("Unapproved commit accepted")
    assert not destination.exists()
`));

test('symlink and gitlink modes are refused before any export path exists',()=>withFixture(String.raw`
source=commit([("120000","link",b"/nonexistent/target")])
try: m._export_local_git_objects_for_fixture(repo,source,root/"symlink-export")
except m.BootstrapRefused: pass
else: raise AssertionError("Symlink accepted")
assert not (root/"symlink-export").exists()
tree=git("mktree","-z",input=b"160000 commit "+source.encode()+b"\tmodule\0").strip().decode()
gitlink=git("commit-tree",tree,"-m","Synthetic gitlink fixture").strip().decode()
try: m._export_local_git_objects_for_fixture(repo,gitlink,root/"gitlink-export")
except m.BootstrapRefused: pass
else: raise AssertionError("Gitlink accepted")
assert not (root/"gitlink-export").exists()
`));

test('all paths, file counts and aggregate sizes are checked before creating output',()=>python(String.raw`
oid=b"a"*40
def record(path,mode=b"100644",kind=b"blob",size=b"1"):
    return mode+b" "+kind+b" "+oid+b" "+size+b"\t"+path+b"\0"
for raw in [record(path) for path in (b"../escape",b"/absolute",b"a/../../escape",b"a//b",b".git/config",b".Git/config",b"control\nname",b"a\\b",b"space name",b"trailing.",b"\xff",b"a"*241,b"a/"*12+b"b")]+[
    record(b"file")+record(b"file"),record(b"a")+record(b"a/b"),
    record(b"link",mode=b"120000"),record(b"module",mode=b"160000",kind=b"commit",size=b"-"),
    record(b"file",mode=b"100664"),record(b"file",size=b"01"),record(b"file")[:-1],
    b"garbage\0",record(b"huge",size=str(m.MAX_SOURCE_BYTES+1).encode()),
    b"".join(record(("file"+str(index)).encode(),size=b"0") for index in range(m.MAX_FILES+1))]:
    try: m._source_entries(raw)
    except m.BootstrapRefused: pass
    else: raise AssertionError("Invalid source tree accepted")
valid=record(b".github/actions/action.yml",size=b"0")+record(b"src/Code.cs",mode=b"100755")
assert len(m._source_entries(valid))==2
`));

test('existing output and symlink parents are preserved, never overwritten',()=>withFixture(String.raw`
source=commit([("100644","file.txt",b"Synthetic")])
existing=root/"existing";existing.mkdir();(existing/"keep").write_bytes(b"Preserve")
try: m._export_local_git_objects_for_fixture(repo,source,existing)
except (m.BootstrapRefused,FileExistsError): pass
else: raise AssertionError("Existing output accepted")
assert (existing/"keep").read_bytes()==b"Preserve"
link=root/"link";link.symlink_to(existing,target_is_directory=True)
try: m._export_local_git_objects_for_fixture(repo,source,link/"export")
except m.BootstrapRefused: pass
else: raise AssertionError("Symlink parent accepted")
assert not (existing/"export").exists()
`));

test('mid-export failure removes partial source and the private child home',()=>withFixture(String.raw`
source=commit([("100644","first.txt",b"First"),("100644","second.txt",b"Second")])
original=m._git;homes=[];count=0
def fail_late(repository,arguments,environment,deadline,output_cap):
    global count
    homes.append(pathlib.Path(environment["HOME"]))
    if arguments[:2]==["cat-file","blob"]:
        count+=1
        if count==2: raise m.BootstrapRefused("SyntheticReadFailure")
    return original(repository,arguments,environment,deadline,output_cap)
m._git=fail_late
try: m._export_local_git_objects_for_fixture(repo,source,root/"export")
except m.BootstrapRefused as error: assert str(error)=="SyntheticReadFailure"
else: raise AssertionError("Failure fixture did not stop")
assert count==2 and not (root/"export").exists()
assert homes and all(not home.exists() for home in homes)
`));

test('object alternates and changed Git executable identity are refused before export',()=>withFixture(String.raw`
source=commit([("100644","file.txt",b"Synthetic")])
info=repo/"objects/info";info.mkdir(parents=True,exist_ok=True)
(info/"alternates").write_text("/nonexistent/object-store\n")
try: m._export_local_git_objects_for_fixture(repo,source,root/"export")
except m.BootstrapRefused: pass
else: raise AssertionError("Alternates accepted")
assert not (root/"export").exists()
m.LOCAL_GIT_SHA256="0"*64
try: m._check_git_executable()
except m.BootstrapRefused as error: assert str(error)=="TokenForgeBootstrapGitUnapproved"
else: raise AssertionError("Changed Git executable accepted")
`));

test('Git subprocess output and monotonic deadline are bounded without retries',()=>withFixture(String.raw`
oid=git("hash-object","-w","--stdin",input=b"Synthetic over-cap output").strip().decode()
try: m._git(repo,["cat-file","blob",oid],environment,time.monotonic()+5,1)
except m.BootstrapRefused as error: assert str(error)=="TokenForgeBootstrapOutputExceeded"
else: raise AssertionError("Unbounded output accepted")
def unexpected(*args,**kwargs): raise AssertionError("Expired command started")
m.subprocess.Popen=unexpected
try: m._git(repo,["cat-file","blob",oid],environment,time.monotonic()-1,64)
except m.BootstrapRefused as error: assert str(error)=="TokenForgeBootstrapExpired"
else: raise AssertionError("Expired command accepted")
`));

test('future source has one fixed public HTTPS fetch and no activation switch or checkout',()=>{
 const source=fs.readFileSync(script,'utf8');
 assert.match(source,/PUBLIC_SOURCE = "https:\/\/github\.com\/nathanmcnulty\/TokenForge\.git"/);
 assert.match(source,/"http\.followRedirects=false"/);assert.match(source,/"protocol\.allow=never"/);
 assert.match(source,/"protocol\.https\.allow=always"/);assert.match(source,/"http\.emptyAuth=false"/);
 assert.equal((source.match(/\["fetch",/g)||[]).length,1);
 assert.doesNotMatch(source,/os\.environ|enable_service|allow_service|--activate|"checkout"|"archive"/);
});
