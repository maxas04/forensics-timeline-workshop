#"""DF-017 synthetic investigation. Implement only the two TODO functions."""
import argparse
from datetime import timedelta
from pathlib import Path
from evidence_tools import load_case, write_json

BASE = Path(__file__).resolve().parent

# Field names an auth row might use for its outcome, in order of preference.
OUTCOME_KEYS = ('result', 'status', 'outcome', 'event_type', 'action')
SUCCESS_VALUES = {'SUCCESS', 'SUCCEEDED', 'OK', 'PASS', 'LOGIN_SUCCESS'}
FAILURE_VALUES = {'FAIL', 'FAILURE', 'FAILED', 'LOGIN_FAILURE', 'LOGIN_FAILED'}


def _outcome(row, allowed):
    """True if any known outcome field of the row exactly matches `allowed`."""
    for field in OUTCOME_KEYS:
        if field in row and str(row[field]).strip().upper() in allowed:
            return True
    return False


def find_login_sequences(rows, min_failures=3, window_minutes=5):
    if not rows:
        return []

    window_delta = timedelta(minutes=window_minutes)

    # Group rows by (username, source_ip, host)
    groups = {}
    for row in rows:
        key = (row['username'], row['source_ip'], row['host'])
        groups.setdefault(key, []).append(row)

    results = []

    for key, group_rows in groups.items():
        failures = [r for r in group_rows if _outcome(r, FAILURE_VALUES)]
        successes = [r for r in group_rows if _outcome(r, SUCCESS_VALUES)]

        for succ in successes:
            succ_time = succ['timestamp']
            window_start = succ_time - window_delta

            # Failures within [succ_time - window_minutes, succ_time)
            matching_fails = [
                f for f in failures
                if window_start <= f['timestamp'] < succ_time
            ]

            if len(matching_fails) >= min_failures:
                sorted_fails = sorted(
                    matching_fails, key=lambda f: (f['timestamp'], f['event_id'])
                )
                results.append({
                    'username': key[0],
                    'source_ip': key[1],
                    'host': key[2],
                    'session_id': succ.get('session_id'),
                    'success_id': succ['event_id'],
                    'success_time': succ_time,
                    'failure_ids': [f['event_id'] for f in sorted_fails],
                })

    results.sort(key=lambda r: (r['success_time'], r['success_id']))
    return results


def correlate_downloads(alerts, file_rows, followup_minutes=10):
    """Enrich each alert with file activity; return a new list of new dicts.

    Input timestamps are aware UTC datetime objects; bytes is already an int.
    For each alert at success_time T, match file rows on ALL of
    (username, host, session_id). Keep only action == 'DOWNLOAD',
    result == 'SUCCESS', and T <= timestamp <= T + timedelta(minutes=followup_minutes).
    Sort matching rows by (timestamp, event_id). Copy the original alert fields
    into a NEW dict, then add:
      download_ids: matching event IDs in that order
      download_count: number of matching events (not distinct paths)
      total_bytes: sum of the matching bytes values
    Keep alerts with no matches: [], 0, 0. Sort returned alerts by descending
    total_bytes, then success_time, then success_id. Empty alerts returns [].
    Do not mutate either input or its nested lists. Do not merge sessions based
    only on a shared account. No hardcoded IDs or outcomes; no extra packages.
    """
    window = timedelta(minutes=followup_minutes)

    # Index successful downloads by the full session key so each alert only
    # looks at rows from its own (username, host, session_id).
    downloads_by_session = {}
    for row in file_rows:
        if row["action"] != "DOWNLOAD" or row["result"] != "SUCCESS":
            continue
        key = (row["username"], row["host"], row["session_id"])
        downloads_by_session.setdefault(key, []).append(row)

    enriched = []
    for alert in alerts:
        start = alert["success_time"]
        end = start + window
        key = (alert["username"], alert["host"], alert["session_id"])

        # Closed interval: both endpoints are included.
        matches = [
            row
            for row in downloads_by_session.get(key, [])
            if start <= row["timestamp"] <= end
        ]
        matches.sort(key=lambda row: (row["timestamp"], row["event_id"]))

        result = dict(alert)  # new top-level dict; inputs stay untouched
        result["download_ids"] = [row["event_id"] for row in matches]
        result["download_count"] = len(matches)
        result["total_bytes"] = sum(row["bytes"] for row in matches)
        enriched.append(result)

    enriched.sort(
        key=lambda a: (-a["total_bytes"], a["success_time"], a["success_id"])
    )
    return enriched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=['logins', 'all'], default='all')
    args = parser.parse_args()
    try:
        auth, files, audit = load_case(BASE)
    except ValueError as error:
        parser.exit(1, f'Evidence check failed: {error}\n')
    write_json(BASE / 'audit.json', audit)
    print('SHA-256 checks match the supplied manifest.')
    for name in ['auth_log.csv', 'file_log.csv']:
        info = audit[name]
        print(f"{name}: {info['data_rows']} rows; {info['accepted']} accepted; "
              f"{len(info['duplicates'])} duplicate; {len(info['rejected'])} rejected.")
    print('Saved audit.json. A hash match does not prove origin or completeness.')
    try:
        alerts = find_login_sequences(auth)
        write_json(BASE / 'login_alerts.json', alerts)
        print(f'Found {len(alerts)} login sequences; saved login_alerts.json.')
        if args.stage == 'logins':
            return
        findings = correlate_downloads(alerts, files)
    except NotImplementedError as error:
        print(f'Starter ready: {error}. Previously generated outputs may be stale.')
        return
    summary = {'case': 'DF-017 training data only',
               'rule': {'min_failures': 3, 'login_window_minutes': 5, 'followup_minutes': 10},
               'evidence_sha256': audit['sha256'], 'findings': findings,
               'interpretation': 'Rule matches identify sessions for review; they do not prove intrusion, exfiltration, or identity.'}
    write_json(BASE / 'summary.json', summary)
    print('Saved summary.json. Verify event IDs against both original CSV files.')
    for item in findings:
        print(f"{item['success_id']} {item['username']} {item['session_id']}: "
              f"{len(item['failure_ids'])} failures, {item['download_count']} downloads, "
              f"{item['total_bytes']} bytes")


if __name__ == '__main__':
    main()