"""Offline policy planning only. Strict, bounded YAML caller contract; no execution."""
import json
import re
import sys
import yaml

if yaml.__version__ != "6.0.2":
    raise RuntimeError("Pinned offline policy parser unavailable")


class StrictLoader(yaml.BaseLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError("aliases forbidden")
        self.nodes = getattr(self, "nodes", 0) + 1
        if self.nodes > 4096:
            raise ValueError("node bound")
        node = super().compose_node(parent, index)
        if node.tag not in ("tag:yaml.org,2002:str", "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq"):
            raise ValueError("tag forbidden")
        return node

    def construct_mapping(self, node, deep=False):
        result = {}
        for key, value in node.value:
            name = self.construct_object(key, deep=deep)
            if not isinstance(name, str) or name in result or name == "<<":
                raise ValueError("duplicate or invalid key")
            result[name] = self.construct_object(value, deep=deep)
        return result


def connected(text, commit):
    if len(text.encode("utf-8")) > 131072 or not re.fullmatch(r"[a-f0-9]{40}", commit):
        return False
    doc = yaml.load(text, Loader=StrictLoader)
    if not isinstance(doc, dict) or not isinstance(doc.get("on"), dict) or set(doc["on"]) != {"workflow_dispatch"}:
        return False
    if doc.get("permissions") not in ({}, {"contents": "read"}):
        return False
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return False
    expected = "nathanmcnulty/TokenForge/.github/workflows/tokenforge-sealer.yml@" + commit
    callers = [(name, job) for name, job in jobs.items() if isinstance(job, dict) and job.get("uses") == expected]
    if len(callers) != 1:
        return False
    name, caller = callers[0]
    if set(caller) - {"name", "needs", "uses", "permissions", "with", "if"} or "if" in caller:
        return False
    if caller.get("permissions") != {"contents": "read", "actions": "read", "id-token": "write", "attestations": "write"}:
        return False
    inputs = caller.get("with")
    if not isinstance(inputs, dict) or set(inputs) != {"artifact-id"}:
        return False
    match = re.fullmatch(r"\$\{\{ needs\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.candidate-artifact-id \}\}", inputs["artifact-id"])
    if not match:
        return False
    predecessor = match[1]
    if caller.get("needs") not in (predecessor, [predecessor]) or predecessor == name:
        return False
    worker = jobs.get(predecessor)
    if not isinstance(worker, dict) or "candidate-artifact-id" not in worker.get("outputs", {}):
        return False
    for other_name, job in jobs.items():
        if not isinstance(job, dict):
            return False
        if other_name == name or job.get("if") == "${{ false }}":
            continue
        permissions = job.get("permissions", {})
        if not isinstance(permissions, dict) or any(value != "read" and value != "none" for value in permissions.values()):
            return False
    return True


if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.read(262145)
        if len(raw) > 262144:
            raise ValueError("input bound")
        request = json.loads(raw)
        result = connected(request["yaml"], request["commit"])
    except Exception:
        result = False
    print("true" if result else "false")
