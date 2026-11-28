# B3 public discovery replay

On 2026-11-28 UTC, the latest file revisions for all three public sources matched the B1 post-review catalog at `ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62`. The [B2 review handoff](catalog-candidate-ingestion.md#hand-public-changes-to-candidate-review) completed with no additions, changed claims, or reopened cases. Each exact-AppId result set was empty.

| Source | UTC check time | Observed file revision (matches baseline) | SHA-256 of retained B1 bytes | Coverage |
| --- | --- | --- | --- | --- |
| ROADtools first-party scopes | 2026-11-28T04:57:59Z | `3b975e832aa543d6d1b2466a3a5be0bd9e01d304` | `4785005674c88780d0c055b4a5820ee6e8bca6a74a93df5885ea7c25a2d02b0e` | Unchanged |
| EntraDocs MicrosoftApps | 2026-11-28T04:57:59Z | `79f6738f9d40de112ae3d656769046ec6a76ed59` | `62ef6bfd3b417ed657165919aa3fa05d1f3aa261d5a2d248a0c9b0e0b4bdde19` | Unchanged |
| entrascopes.com resources | 2026-11-28T04:58:02Z | `5a7624739f81b83cbc5c8df41e52cbc908a28e61` | `a20ea8fadb3668f86c1e352697b6b456c5928684c5e820543b5d5cc59ea82bb7` | Unchanged |

The hashes match the pinned catalog's source stamps. Collection retrieved GitHub file history for the specified branch and path. All three revisions matched, so the changed-capture directory was empty. The unchanged replay skipped byte verification and projection internally. The separate SHA-256 check below read the retained B1 files.

The search of the checkout and available B1/B2 artifacts found no previously accepted review state. The replay used the pinned issue #151 seed and returned 13 unresolved cases with their issue association intact. Verified promotion still requires separate Microsoft ownership evidence for the exact AppId. Any emitted review item remains pending. State and replay outputs were kept locally. There were no proposed issue updates.

## Collect a new observation

Run in Bash with GitHub public access, curl, jq, and a fresh output directory. The commands below record the start of each history check in UTC and retrieve raw bytes by immutable revision only when the file revision differs. A failed history check records `Unavailable`. A failed download leaves the changed revision without a capture hash and the handoff records `NeedsCapture`.

```bash
set -euo pipefail
out=/tmp/tokenforge-b3-public
mkdir -p "$out/captures"
for row in \
 'roadtools dirkjanm/ROADtools master roadtx/roadtools/roadtx/firstpartyscopes.json 3b975e832aa543d6d1b2466a3a5be0bd9e01d304' \
 'microsoftApps merill/microsoft-info main _info/MicrosoftApps.json 79f6738f9d40de112ae3d656769046ec6a76ed59' \
 'resources f-bader/entrascopes.com main resources.json 5a7624739f81b83cbc5c8df41e52cbc908a28e61'
do
  read -r name repo branch path old <<< "$row"
  checked=$(date -u +%FT%TZ)
  printf '%s %s\n' "$name" "$checked"
  if curl -fsSL --max-time 30 --get "https://api.github.com/repos/$repo/commits" \
    --data-urlencode "sha=$branch" --data-urlencode "path=$path" \
    --data-urlencode per_page=1 -o "$out/$name.history.json" &&
    revision=$(jq -er '.[0].sha | select(test("^[0-9a-f]{40}$"))' "$out/$name.history.json")
  then
    committed=$(jq -er '.[0].commit.committer.date' "$out/$name.history.json")
    jq -n --arg r "$revision" --arg t "$checked" --arg c "$committed" \
      '{revision:$r, checkedAt:$t, committedAt:$c}' > "$out/$name.stamp.json"
    if [[ $revision != "$old" ]] && curl -fsSL --max-time 30 \
      "https://raw.githubusercontent.com/$repo/$revision/$path" -o "$out/captures/$name.download"
    then
      mv "$out/captures/$name.download" "$out/captures/$name.json"
      hash=$(sha256sum "$out/captures/$name.json" | cut -d' ' -f1)
      jq --arg h "$hash" '. + {sha256:$h}' "$out/$name.stamp.json" > "$out/$name.tmp"
      mv "$out/$name.tmp" "$out/$name.stamp.json"
    fi
  else
    printf '{"status":"Unavailable"}\n' > "$out/$name.stamp.json"
  fi
done
jq -S -n --slurpfile r "$out/roadtools.stamp.json" --slurpfile m "$out/microsoftApps.stamp.json" \
  --slurpfile e "$out/resources.stamp.json" '{roadtools:$r[0],microsoftApps:$m[0],resources:$e[0]}' \
  > "$out/observations.json"
cat "$out/observations.json"
```

## Reproduce the observed replay offline

Run from a TokenForge checkout containing the pinned catalog objects on Linux x64. The run used Python 3.13.5 and the B2 reviewed `public-health-e2e-1d6617e` package with PowerShell 7.6.7. Use the retained paths from [B2 verification](catalog-candidate-ingestion.md#b2-local-verification), or adjust them to match local storage. The runtime was supplied to the command, and source projection is only invoked for changed revisions.

To recreate the historical observation without contacting GitHub, run this in a fresh local output directory at the path below. Keep it separate from any newer collection.

```bash
out=/tmp/tokenforge-b3-public
mkdir -p "$out/captures"
cat > "$out/observations.json" <<'JSON'
{
  "microsoftApps": {
    "checkedAt": "2026-11-28T04:57:59Z",
    "committedAt": "2026-11-23T16:19:40Z",
    "revision": "79f6738f9d40de112ae3d656769046ec6a76ed59"
  },
  "resources": {
    "checkedAt": "2026-11-28T04:58:02Z",
    "committedAt": "2025-08-20T08:22:02Z",
    "revision": "5a7624739f81b83cbc5c8df41e52cbc908a28e61"
  },
  "roadtools": {
    "checkedAt": "2026-11-28T04:57:59Z",
    "committedAt": "2026-04-27T12:01:30Z",
    "revision": "3b975e832aa543d6d1b2466a3a5be0bd9e01d304"
  }
}
JSON
```

```bash
set -euo pipefail
out=/tmp/tokenforge-b3-public
runtime=/tmp/tokenforge-b2-validation
export PATH="$runtime/powershell:$PATH"
python3 --version
pwsh -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()'
sha256sum "$runtime/TokenForge-public-health-linux-x64.tar.gz" "$runtime/native/tokenforge" /tmp/tokenforge-b1-public-captures/*.json "$out/observations.json"
baseline=ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62
replay=(python3 -B scripts/Diff-TokenForgePublicCatalog.py --baseline-repo "$PWD"
  --baseline-commit "$baseline" --observations "$out/observations.json"
  --captures "$out/captures" --native "$runtime/native/tokenforge" --review)
"${replay[@]}" > "$out/first.json"
"${replay[@]}" > "$out/second.json"
cmp "$out/first.json" "$out/second.json"
jq -e '.review.nextState' "$out/first.json" > "$out/next-state.json"
"${replay[@]}" --review-state "$out/next-state.json" > "$out/repeat.json"
cmp "$out/first.json" "$out/repeat.json"
jq -e '.complete and (.newApplications == []) and
  ([.sources[].status] | all(. == "Unchanged")) and
  (.review.coverageGaps == {}) and (.review.reviewItemCount == 0) and
  (.review.reviewItems == []) and
  (.review.nextState.cases | length == 13 and all(.[]; .status == "Unresolved" and .issue == 151))' "$out/first.json"
sha256sum "$out"/{first,second,repeat}.json
ls -A "$out/captures"
```

The observations SHA-256 was `894c1bea8b0407c275ed72248a65c08121cba9b35dc78f7a7d73de8f64ce3bcd`. The package archive SHA-256 was `3e396f3486b9671ba5a71b6afd53a0e7a869fcb466e428beea30df596923446f`. The supplied native executable SHA-256 was `aa1ad0d814970379376ee5da6ddf531ccb22b1b738ad65709599ee64c4a2f61b`.

All three invocations exited 0 and reported complete coverage of the supplied observations with zero review items. Both `cmp` calls succeeded. All three receipts had SHA-256 `78b251563ec0c020f5b8fc138c3cd52f3269c4198b409fab7730ec3c1bda273b`. The result covers the unchanged-file path. A real newer capture is still needed to exercise claim projection and reopening on a public increment. Ownership for the 13 seeded cases and coverage of the global application population remain unknown.

For a later incomplete collection, preserve the observed source gap. The handoff exits 2 and returns JSON `null` for `reviewItemCount`, `reviewItems`, and `nextState`. Retain the prior state until complete coverage is available.
