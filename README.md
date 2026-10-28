# Detection Rules Lab

[![CI](https://github.com/Lawrence-Flash/detection-rules-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Lawrence-Flash/detection-rules-lab/actions/workflows/ci.yml)

Detection-as-code practice repo by Lawrence Tshabalala, a junior cybersecurity analyst / DevSecOps in South Africa.

The repository holds Sigma rules, a synthetic log for each rule that should fire, a synthetic log that should not, and a small Python tool that checks both offline.

## What detection-as-code means

A detection is a file in git. Someone reviews the diff, CI runs it against sample logs, and the history shows who changed it and why. The alternative is a search saved inside a SIEM console, with no review and no negative test.

Sigma is the YAML format used here. A rule names the log source and the fields that matter. It does not ship alerts by itself. A SIEM, or a converter, turns it into a query.

## Quick start

You need Python 3.10 or newer. From the repository root:

```bash
python3 -m rulelab validate
python3 -m rulelab test
python3 -m rulelab coverage
python3 -m unittest discover -s tests -v
```

`validate` checks required fields, UUIDs, dates, and ATT&CK tags. `test` runs every rule against its positive and negative events and exits non-zero if a positive misses or a negative fires. `coverage` prints a MITRE ATT&CK table and writes [`docs/coverage.md`](docs/coverage.md). None of these commands install packages or open a network connection.

Optional conversion uses pySigma. It is not required to use the lab:

```bash
python3 -m pip install -r requirements-dev.txt
sigma check --fail-on-issues rules
python3 -m rulelab convert
```

`convert` writes Splunk SPL under `examples/splunk/` and Elasticsearch Lucene under `examples/lucene/`. Those queries use the field names from the Sigma files. No Splunk CIM or Elastic Common Schema pipeline is applied.

## Rules

19 rules. Mappings follow MITRE ATT&CK enterprise v20. Tactic tags use the current shortnames (`attack.stealth`, `attack.credential-access`, `attack.defense-impairment`). `stable` is not used: these rules have not been tuned on a production log source.

| Rule | ATT&CK | Level | Log source |
| --- | --- | --- | --- |
| Linux Base64 Decode Piped to a Shell (`rules/linux/base64_decode_pipe_shell.yml`) | T1059.004, T1140 | high | linux / process_creation |
| Linux Crontab Replace (`rules/linux/crontab_replace.yml`) | T1053.003 | medium | linux / cron |
| Linux Curl Piped to a Shell (`rules/linux/curl_pipe_shell.yml`) | T1059.004, T1105 | high | linux / process_creation |
| Linux SSH authorized_keys Write (`rules/linux/ssh_authorized_keys_write.yml`) | T1098.004 | high | linux / process_creation |
| Linux SSH Failed Password (`rules/linux/ssh_failed_password.yml`) | T1110.001 | low | linux / auth |
| Linux Sudo Root Shell (`rules/linux/sudo_to_root_shell.yml`) | T1548.003 | medium | linux / auth |
| Linux Local User Created (`rules/linux/useradd_local_account.yml`) | T1136.001 | medium | linux / auth |
| Web Path Traversal Request (`rules/web/path_traversal_request.yml`) | T1190 | high | webserver |
| Web SQL Injection Request (`rules/web/sql_injection_request.yml`) | T1190 | high | webserver |
| Web Vulnerability Scanner User-Agent (`rules/web/vulnerability_scanner_user_agent.yml`) | T1595.002 | low | webserver |
| Windows Certutil Download (`rules/windows/certutil_urlcache_download.yml`) | T1105 | high | windows / process_creation |
| Windows Network Logon Bad Password 4625 (`rules/windows/failed_logon_4625_bad_password.yml`) | T1110.001 | low | windows / security |
| Windows User Added to Local Administrators (`rules/windows/local_administrators_4732.yml`) | T1098.007 | high | windows / security |
| Windows LSASS Memory Access (`rules/windows/lsass_process_access.yml`) | T1003.001 | high | windows / process_access |
| Windows Pass the Hash Logon (`rules/windows/pass_the_hash_logon_type_9.yml`) | T1550.002 | high | windows / security |
| Windows PowerShell DownloadString (`rules/windows/powershell_downloadstring.yml`) | T1059.001, T1105 | high | windows / process_creation |
| Windows Encoded PowerShell (`rules/windows/powershell_encoded_command.yml`) | T1027.010, T1059.001 | high | windows / process_creation |
| Windows Suspicious Scheduled Task (`rules/windows/scheduled_task_created_4698.yml`) | T1053.005 | medium | windows / security |
| Windows Security Log Cleared (`rules/windows/security_log_cleared_1102.yml`) | T1685.005 | high | windows / security |

The coverage table, including tactics with zero rules, is in [`docs/coverage.md`](docs/coverage.md).

Levels are a hint, not a page-out policy. A single SSH failure or a single 4625 is `low` because one event is a weak signal. Encoded PowerShell, certutil urlcache, and an LSASS read with a dump-style access mask are `high` because the procedure is specific, and they still have false positives listed on the rule.

## How to add a rule

1. Add `rules/<linux|windows|web>/<name>.yml`. Copy the shape of an existing rule. `author` stays `Lawrence Tshabalala`. `id` is a new UUID. `status` is `test` or `experimental`.
2. Map the behavior to a current ATT&CK technique page. If the id is not already in `rulelab/attack.py`, add the id, the name, the tactics from that page, and the URL. `validate` rejects a technique it does not know, and it rejects tactic tags that do not match the page.
3. Keep the detection count-free. The built-in matcher accepts `contains`, `startswith`, `endswith`, `re`, and `all`, plus `and` / `or` / `not`, parentheses, and `1 of selection*`. If the idea needs "more than 10 events in 5 minutes", write the single event a SIEM would count, and say that in the description.
4. Add `tests/data/<linux|windows|web>/<name>_positive.json` and `<name>_negative.json`. Each file is a JSON list of objects. Every object sets `"synthetic": true`. Put IP addresses only in IP fields, and only from the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, or loopback.
5. Make the negative event close to the positive one. A successful SSH login is a useful negative for a failed-password rule. An empty object is not.
6. Run `validate`, `test`, and `coverage`. Put the new row in the table above. Commit `docs/coverage.md` with the rule.

## Tests and CI

Synthetic events live in `tests/data/`. They are invented lab records. Hosts use the `.example` domain. Account names are `labuser`, `labadmin`, and `svc-lab`. The encoded PowerShell sample decodes to `Write-Output 'synthetic-lab'`.

GitHub Actions runs unit tests, `rulelab validate`, and `rulelab test` on Python 3.10, 3.11, and 3.12. A miss on a positive event or a hit on a negative event fails the build. A second job installs sigma-cli and pySigma, runs `sigma check --fail-on-issues`, and checks that `examples/` still matches `rulelab convert`. CodeQL analyzes the Python. Dependabot updates GitHub Actions weekly.

`sigma check` downloads the current ATT&CK STIX file. If MITRE renames a tactic, that job fails until `rulelab/attack.py` and the rule tags are updated. The stdlib job does not download anything.

## Limitations

The built-in matcher is a subset of Sigma. It covers the modifiers listed above, on one event at a time. It has no `count`, no `near`, no timeframe, and no `base64` or `windash` modifiers. Plain matches are case-insensitive. `re` is case-sensitive unless the pattern includes `(?i)`.

Field names in the events are the names written in the rules. There is no Sigma pipeline, so a Windows `CommandLine` here is not automatically `process.command_line` or a CIM field.

This is not a SIEM. It does not collect logs, store state, send alerts, or talk to a network at runtime.

The SSH and 4625 rules are single-event indicators. They do not prove a brute-force attack or a burst. A SIEM would count them. The pass-the-hash rule matches one logon shape (type 9, `seclogo`, `Negotiate`). A type 3 NTLM logon is a different event and does not match. The scheduled-task rule expects the task XML in `TaskContent`.

## What I learned

I started by treating "SSH brute force" as if one failed password was the attack. It is not. It is the line you count. Writing the rule forced me to say that in the description and to keep the level at `low`, because this matcher cannot count.

The same thing happened with Windows 4625. SubStatus `0xC000006A` means the password was wrong and the account existed. One of those events cannot tell password guessing from password spraying. Spraying has its own sub-technique and needs many accounts, so I tagged only T1110.001 and left the gap in the text.

Checking the current ATT&CK pages changed two mappings I would have copied from memory. Defense Evasion is now Stealth, and clearing the Security log is T1685.005 under Defense Impairment. T1070.001 is revoked. Event 1102 did not change. The id did. Pass the hash (T1550.002) is Lateral Movement only in v20, and the rule I can actually write is the local type 9 logon, not every NTLM authentication on the network.

I also got more out of the negative events than the positive ones. `sudo` to run `apt` is root, and it should not match a root-shell rule. A browser fetching `/blog/nikto-vs-nuclei` should not match a scanner rule. `Invoke-WebRequest` is a download, and the DownloadString rule is honest about missing it. A detection without that kind of negative is just a story.

The matcher is there so the rules can be tested on a laptop with no API key. It is not a second Sigma implementation, and I do not want to pretend the converted SPL is ready for a production sourcetype.

## License

MIT. See [LICENSE](LICENSE).
