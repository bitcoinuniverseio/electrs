# Exact failed probe recovery only

The next owned workflow deliberately runs only `sandbox-diagnostic.py --recover-only`. It does not invoke the scope proof or retry a unit. Original run38017693834/attempt1, source ddabecc64aaf and its failed controller outcome remain history; the actual stderr reason has not yet been recovered. Metadata succeeded, but sandbox enforcement is unqualified.

The diagnostic reads only `/opt/github-runners/runner-27/_work/_temp/universe-electrs-sandbox-probe-38017693834-1-[16hex]` and six known diagnostic filenames. Paths, regular file types, owner, unique folder match and source/unit fields are checked. Aggregate raw bytes and emitted JSON are each limited to32KiB. Files are not changed. Secret-pattern hits cause raw output to be withheld rather than exposed. No environment, native data, unknown file or other run is read.

If the exact folder was cleaned, the fallback uses the existing outside-checkout `/usr/bin/journalctl`, its recorded file hash, exact owned user-unit prefix and UTC02:38:27–02:38:30 interval. Output is bounded and independently filtered to that run/attempt’s16hex unit name and timestamp. The reader’s3s deadline can terminate only its own read-only journal helper. It cannot start, stop or modify a unit. Empty or unavailable evidence is not scope success or a guessed failure cause.

Future proof failures additionally print bounded own stdout/stderr, exact unit and failure receipt path. Diagnostics cannot mask the original failure, create a unit or trigger a retry. Existing proof code remains available for a separately reviewed later execution, but the current workflow has no `--run-proof` step. No recovery command has been executed during this source preparation.
