# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

| Purpose | macOS or Linux | Windows PowerShell |
| --- | --- | --- |
| Run starter or full analysis | `python3 analyze_case.py` | `py analyze_case.py` |
| Run login stage only | `python3 analyze_case.py --stage logins` | `py analyze_case.py --stage logins` |
| Check function 1 | `python3 check_solution.py LoginChecks` | `py check_solution.py LoginChecks` |
| Check function 2 | `python3 check_solution.py DownloadChecks` | `py check_solution.py DownloadChecks` |
| Run all checks | `python3 check_solution.py` | `py check_solution.py` |

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find_login_sequences` and `correlate_downloads` in
`analyze_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source_ip, host)` and count
   FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
   Each success is evaluated independently; earlier successes do not reset
   the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session_id**. Keep only
   `action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
   Count events, even if their paths repeat. Sum their integer bytes values.
   Retain alerts with zero matches. Sort by descending byte total, then time
   and success event ID. This ranking measures recorded volume, not guilt.
3. `event_id` identifies one event within its source. `session_id` links the
   two sources. `bytes` is the transfer size recorded by the application;
   independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence_tools.py` verifies the original CSV byte hashes against
`evidence_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section

| Source | Data rows excluding header | Accepted unique | Duplicate | Rejected |
| --- | --- | --- | --- | --- |
| auth_log.csv | [60] | [54] | [1] | [5] |
| file_log.csv | [35] | [30] | [1] | [4] |

- SHA-256 check outcome and what it establishes: [There are the same ]
- One rejected event ID and the exact rejection reason: [A900,Invalid isoformat string: 'not-a-time' ]
- Number of flagged successful sessions: [3]

| Success ID | Account | Session | Supporting failure IDs | Download IDs | Event count | Total bytes |
| --- | --- | --- | --- | --- | --- | --- |
| A005 | analyst01 | S-104 | A002, A003, A004 | F001, F002, F003 | 3 | 5509120 |
| A018 | analyst02 | S-304 | A015, A016, A017 | F013 | 1 | 2048 |
| A014 | backup_svc | S-204 | A011, A012, A013 | none | 0 | 0 |

## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

| Source and event ID | Original timestamp | UTC timestamp | What the row records |
| --- | --- | --- | --- |
| auth_log.csv A002 | 2026-10-20T08:58:00Z | 2026-10-20T08:58:00Z | FAIL login, analyst01, 203.0.113.44, DF-PORTAL01 |
| auth_log.csv A003 | 2026-10-20T09:00:00Z | 2026-10-20T09:00:00Z | FAIL login, analyst01, 203.0.113.44, DF-PORTAL01 (a second identical row is a duplicate, excluded) |
| auth_log.csv A004 | 2026-10-20T10:01:00+01:00 | 2026-10-20T09:01:00Z | FAIL login, analyst01, 203.0.113.44, DF-PORTAL01 |
| auth_log.csv A005 | 2026-10-20T09:03:00Z | 2026-10-20T09:03:00Z | SUCCESS login, analyst01, session S-104 |
| file_log.csv F001 | 2026-10-20T09:05:00Z | 2026-10-20T09:05:00Z | DOWNLOAD SUCCESS, /training/case-017/evidence_export.zip, 5242880 bytes (a second identical row is a duplicate, excluded) |
| file_log.csv F002 | 2026-10-20T10:07:00+01:00 | 2026-10-20T09:07:00Z | DOWNLOAD SUCCESS, /training/case-017/interview_notes.pdf, 262144 bytes |
| file_log.csv F003 | 2026-10-20T09:13:00Z | 2026-10-20T09:13:00Z | DOWNLOAD SUCCESS, /training/case-017/hashes.txt, 4096 bytes |

- Manual sum of download bytes, showing the addition: [5 5091 20]
- A001 versus A002: which qualifies for the A005 window and why? [A002 falls right on the 5-minute threshold for A005 (08:58:00Z), so it counts. A001 misses by just one second (08:57:59Z) and is excluded. That leaves A005 with three supporting failures—A002, A003, and A004.]
- F003 versus F004: which qualifies for the A005 follow-up and why? [F003 qualifies because its time (09:13:00Z) hits the exact upper limit (+10 minutes). F004 misses by just one second (09:13:01Z) and is excluded, despite matching parameters.
F005 matches the username and host within the time window, but uses a different session ID (S-OTHER vs S-104). Since all three attributes must match, F005 isn't linked to the session.]
- Why F005 is excluded even though the account matches: [This is beacause the session ID is't same from A005. Even though the account name and host match and the time is in range]
- One +01:00 timestamp and its equivalent UTC time: [For A004, 2026-10-20T10:01:00+01:00 converts to 09:01:00Z by subtracting 1-hour offset.]
- One limitation of excluding malformed records: [Dropping malformed records means some activity gets left out. For instance, file_log.csv was ignored because its bytes value said "unknown". If that was a valid download in session S-104, the actual total for A005 exceeds 5,509,120 bytes—making our calculated total a minimum, not an exact count.]

## Checks actually run

Command, date and actual final result (paste output, including failures if any):

```text
[test_supplied_case (__main__.CaseChecks.test_supplied_case) ... ok
test_closed_window_includes_zero_and_ten_minutes (__main__.DownloadChecks.test_closed_window_includes_zero_and_ten_minutes) ... ok
test_configurable_followup (__main__.DownloadChecks.test_configurable_followup) ... ok
test_does_not_mutate_either_input (__main__.DownloadChecks.test_does_not_mutate_either_input) ... ok
test_empty (__main__.DownloadChecks.test_empty) ... ok
test_keeps_alert_with_no_downloads (__main__.DownloadChecks.test_keeps_alert_with_no_downloads) ... ok
test_ranking_event_ties_and_repeated_paths (__main__.DownloadChecks.test_ranking_event_ties_and_repeated_paths) ... ok
test_requires_session_account_host_action_and_success (__main__.DownloadChecks.test_requires_session_account_host_action_and_success) ... ok
test_conflicting_ids_are_not_silently_discarded (__main__.EvidenceChecks.test_conflicting_ids_are_not_silently_discarded) ... ok
test_equivalent_time_offsets_and_missing_offset (__main__.EvidenceChecks.test_equivalent_time_offsets_and_missing_offset) ... ok
test_hash_mismatch_stops_analysis (__main__.EvidenceChecks.test_hash_mismatch_stops_analysis) ... ok
test_supplied_quality_counts_and_duplicates (__main__.EvidenceChecks.test_supplied_quality_counts_and_duplicates) ... ok
test_account_ip_and_host_must_all_match (__main__.LoginChecks.test_account_ip_and_host_must_all_match) ... ok
test_does_not_mutate_input (__main__.LoginChecks.test_does_not_mutate_input) ... ok
test_empty (__main__.LoginChecks.test_empty) ... ok
test_failures_without_success_are_not_alerts (__main__.LoginChecks.test_failures_without_success_are_not_alerts) ... ok
test_outside_equal_and_future_failures_do_not_count (__main__.LoginChecks.test_outside_equal_and_future_failures_do_not_count) ... ok
test_parameters_and_each_success_window (__main__.LoginChecks.test_parameters_and_each_success_window) ... ok
test_ties_and_output_order (__main__.LoginChecks.test_ties_and_output_order) ... ok
test_unsorted_rows_and_evidence_order (__main__.LoginChecks.test_unsorted_rows_and_evidence_order) ... ok
test_window_includes_exactly_five_minutes (__main__.LoginChecks.test_window_includes_exactly_five_minutes) ... ok

----------------------------------------------------------------------
Ran 21 tests in 0.005s
]
```

All 21 supplied checks should pass. Passing these checks is limited validation
of the stated classroom rule, not certification of a forensic tool.

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):

**Unsupported parts:**
(1) **"Belongs to the attacker":** The ranking measures recorded volume only. Nothing supplied shows identity, motive, or authorization, and an account (analyst01) is not a person.
(2) **"Proves stole evidence":** F001 to F003 record DOWNLOAD SUCCESS events. They don’t show theft, a destination, or a completed transfer, and no file contents are supplied.
(3) **"Hashes prove authentic and complete":** A SHA-256 match shows only agreement with the supplied baseline. Origin and completeness are unestablished, and 9 rows were rejected.

**Rewrite:** Session S-104 (analyst01, success A005 at 2026-10-20T09:03:00Z after failures A002 to A004) has the highest recorded download volume, 5,509,120 bytes across F001 to F003, so it is the best candidate for review. This shows only what the logs record: it doesn’t identify a person, intent or authorization, and matching hashes show agreement with the supplied baseline, not authenticity or completeness, with 9 rows excluded as malformed.

**Note:** The GenAI tool (Claude) was already cautious and rejected all three overstated parts without further prompting; we report that as observed.

**One claim we corrected or independently verified, with event IDs:**
We checked that F005 (8,000,000 bytes, 09:04:00Z) should not be counted for A005. It matches the username and host and is inside the time window, but its session_id is S-OTHER, not S-104, so the join fails. A shared username alone is not a reliable link. We also independently re-added F001 + F002 + F003 = 5,242,880 + 262,144 + 4,096 = 5,509,120 bytes.

**Final 180-220 word finding, reviewed and edited by the pair:**

**Observation.** Session S-104 (analyst01, 203.0.113.44, DF-PORTAL01) is the leading session for review. Three failures (A002 08:58:00Z, A003 09:00:00Z, A004 09:01:00Z) preceded success A005 at 09:03:00Z. Between 09:05:00Z and 09:13:00Z, the log records three successful downloads, F001, F002 and F003, totalling 5,509,120 bytes. By comparison, flagged session S-304 (A018, analyst02) shows one download, F013, of 2,048 bytes, and A014 (backup_svc) shows none, so S-104 ranks first by recorded volume only.

**Inference and limits.** This pattern merits review, but it does not identify a person, show lack of authorisation or prove completed exfiltration. Nine malformed rows (five authentication, four file) were excluded, so true activity may be larger. Matching SHA-256 hashes show agreement with the supplied baseline only, not authenticity or completeness; clock accuracy is also unverified. A plausible benign explanation is that the account holder mistyped a password and then exported routine case files.

**Next evidence requests:** (1) The portal’s MFA and authorisation records for A005 and session S-104; (2) transfer completion and destination network logs for F001–F003.

*(186 words.)*

---

It cites evidence IDs (A002–A005, F001–F003, A014, A018, F013), separates observation from inference/limits, includes comparison sessions (S-304, A014), specifies two limitations (excluded malformed rows, SHA-256 agreement vs completeness), provides one benign explanation (mistyped password for routine case export), includes two next evidence requests (MFA/authorisation records, network logs), and avoids equating an account or IP to identity.

## AI use and pair review

- Names of both partners: [Maximilien SIMON & Charles DUBOIS]
- GenAI tool/ChatGPT date and displayed model: Claude (Antropic), Sonnet 5.5 used on 2026-11-05
- Prompts used and what they produced: [Prompt 1,2,3,4 and ask explanation of different step]
- One follow-up question or correction, with a short response excerpt: [A001 (08:57:59Z) misses the window start by one second. A002 (08:58:00Z) hits the lower bound exactly and counts. A009 (09:03:00Z) matches the success timestamp, but strict inequality (<) excludes it.]
- Results of code and evidence checks performed: [All 21 tests passed. Re-running analysis on the final code yielded 3 alerts: A005 (5,509,120 bytes), A018 (2,048 bytes), and A014 (0 bytes). Manual event ID lookups in the CSVs (A001–A010, A902, F001–F010) verified the data, and the manual byte sum of 5,509,120 matches `summary.json`. Timezone conversions (`+01:00`) for A004 and F002 were also confirmed.]


## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub_CLI_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min_failures=2` with `min_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.
