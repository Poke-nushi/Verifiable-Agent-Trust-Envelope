# Read the published ACS capture

This replay reads four files from [AngeYobo's ACS #435 capture](https://gist.github.com/AngeYobo/fe5cd44a864b4d54809cf1ded1e6d956/3ed175e24f4f4c5078aeddf5a0e301a4efd77aba).
The [#435 discussion](https://github.com/GenAI-Security-Project/agent-control-standard/issues/435)
and [#436 follow-up](https://github.com/GenAI-Security-Project/agent-control-standard/issues/436)
provide the upstream context. The logs and upstream scripts are not bundled
here; see [NOTICE](NOTICE) for attribution.

The pinned Gist revision is `3ed175e24f4f4c5078aeddf5a0e301a4efd77aba`.
[PUBLISHED-CAPTURE.json](PUBLISHED-CAPTURE.json) records each source URL, byte
length and SHA-256. [published-selection.json](published-selection.json) selects
the request and sessions for this reading.

## Obtain and check the files

From this reader's folder, download the four raw files into a new directory.
These commands fetch log data only; they do not run the upstream scripts or
any commands recorded in the logs.

```bash
capture_dir=$(mktemp -d /tmp/vate-acs-capture.XXXXXX)
curl --fail --silent --show-error --location --proto '=https' \
  --output "$capture_dir/host-audit.jsonl" \
  'https://gist.githubusercontent.com/AngeYobo/fe5cd44a864b4d54809cf1ded1e6d956/raw/005115918fc6b07762d6b45fb7c517e75a0192ca/host-audit.jsonl'
curl --fail --silent --show-error --location --proto '=https' \
  --output "$capture_dir/guardian-envelopes.jsonl" \
  'https://gist.githubusercontent.com/AngeYobo/fe5cd44a864b4d54809cf1ded1e6d956/raw/43daf1c94455b684dcc7686a310f5832107d943a/guardian-envelopes.jsonl'
curl --fail --silent --show-error --location --proto '=https' \
  --output "$capture_dir/host-events.jsonl" \
  'https://gist.githubusercontent.com/AngeYobo/fe5cd44a864b4d54809cf1ded1e6d956/raw/209481a5dc71a29bae0a68aa5c7c1243087d548f/host-events.jsonl'
curl --fail --silent --show-error --location --proto '=https' \
  --output "$capture_dir/proxy.jsonl" \
  'https://gist.githubusercontent.com/AngeYobo/fe5cd44a864b4d54809cf1ded1e6d956/raw/73cde1c51a942a01bf942b000f5941a63fec268d/proxy.jsonl'
python3 -B check_capture.py --directory "$capture_dir"
```

If you already have these files, pass their directory to `check_capture.py`.
The Python wrapper works offline. It checks all four raw-file hashes and byte
lengths, the selection hash, and the resulting report hash. Missing or changed
files cause exit 64; they do not become absent observations. Use raw downloads:
copying JSON through an editor can change whitespace or line endings.

| File | Bytes | Raw SHA-256 |
| --- | ---: | --- |
| `host-audit.jsonl` | 338 | `ba67c73e372cd927fb2788567e16cb78221bf159e3472b03d933b473d8eec3f6` |
| `guardian-envelopes.jsonl` | 5277 | `e90560d249fca37064b08e6d7825bfc152392c7100fccfbbf6f45e71e2793532` |
| `host-events.jsonl` | 3311 | `6800989cdb3a3c4aef742f4ba8a159c5cf150bfaa89027d08fadf02a6495ff09` |
| `proxy.jsonl` | 3833 | `f351882fd7f6d45854c897e1cc82cdc2b3151d353515e0a3f2b45d281fa84f11` |

## Expected reading

The output is 7831 bytes including the final LF, with SHA-256
`0adcd9fb15ebca72851bd5e6b5de1813cc783bd5f255ce88de6bce5125177277`.
This is a fixed reading of these four files:

| Observation | What the reader retains |
| --- | --- |
| Host fallback | The host reports a timeout and `proceed` / `proceeded`. The handshake reports a default timeout of 5000 ms. |
| Original Guardian response | `deny`, recorded 3.132 seconds after the host fallback. This is a comparison of source timestamps, not proof of arrival or application at the host. |
| Result hooks | Separate request IDs and their `allow` responses. They do not change the original request's decision. |
| Execution and results | Request-to-execution and request-to-result links remain `unresolved`. Command-text equality is only a candidate cue. |
| Dispatch and commitment | Unknown. A reported host tool interval may include time spent waiting for the Guardian. |

The upstream fixture run recorded exit 1 with `Unexpected hook coverage`.
Generating this reader report does not turn that run into a passing test. The
replay checks the saved capture bytes and their reading; it does not rerun ACS,
authenticate the logs, or independently confirm execution or effects.

For a different capture, use `acs_reader.py` with your own selection as described
in [README.md](README.md#read-your-capture). The fixed hashes here identify this
particular capture, rather than a general ACS compatibility test.
