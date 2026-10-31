"""
report.py - takes the results and turns them into reports.

two outputs:
  - JSON: the full raw data (every prompt + response + verdict), for records
  - HTML: the nice visual report you open in a browser

I kept the HTML all in one file (no external css) so the report works
anywhere, even offline.
"""

from __future__ import annotations

import dataclasses
import html
import json
import os

from .runner import SuiteResult


def write_json(result: SuiteResult, path: str) -> None:
    # dump everything to a JSON file - this is the machine-readable record.
    # I include the summary numbers AND every single attempt so the run is
    # fully reproducible / auditable later.
    payload = {
        "suite_name": result.suite_name,
        "model": result.model,
        "threshold": result.threshold,
        "started_at": result.started_at,
        "summary": {
            "total_attempts": result.total_attempts,
            "total_successes": result.total_successes,
            "overall_attack_success_rate": round(result.overall_asr, 4),
            "overall_block_rate": round(result.overall_block_rate, 4),
            "passed": result.passed,
        },
        # one entry per probe, with its own stats + all the attempts under it
        "probes": [
            {
                "probe_id": pr.probe_id,
                "category": pr.category,
                "attack_success_rate": round(pr.asr, 4),
                "block_rate": round(pr.block_rate, 4),
                "attempts": [dataclasses.asdict(a) for a in pr.attempts],
            }
            for pr in result.probe_results
        ],
    }
    # make sure the folder exists, then write the file
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def _badge(ok: bool) -> str:
    # tiny helper: green PASS badge or red FAIL badge for the HTML
    color = "#1a7f37" if ok else "#cf222e"
    label = "PASS" if ok else "FAIL"
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:10px;font-size:12px">{label}</span>'


def write_html(result: SuiteResult, path: str) -> None:
    # builds the HTML report as one big string, then saves it

    # --- part 1: the summary table (one row per probe) ---
    rows = []
    for pr in result.probe_results:
        rows.append(
            f"<tr><td>{html.escape(pr.probe_id)}</td>"
            f"<td>{html.escape(pr.category)}</td>"
            f"<td>{pr.successes}/{pr.total}</td>"        # hits / total
            f"<td>{pr.asr * 100:.0f}%</td>"             # attack success %
            f"<td>{pr.block_rate * 100:.0f}%</td></tr>"  # block %
        )
    summary_rows = "\n".join(rows)

    # --- part 2: every single attempt, with the raw model response ---
    # red background if the attack worked, green if it was blocked.
    # (html.escape stops the model's text from breaking my page layout)
    details = []
    for pr in result.probe_results:
        for a in pr.attempts:
            flag = "ATTACK SUCCEEDED" if a.attack_succeeded else "blocked"
            bg = "#fff5f5" if a.attack_succeeded else "#f6fff8"
            resp = html.escape(a.response) if a.response else html.escape(a.error or "(empty)")
            details.append(
                f'<div style="border:1px solid #d0d7de;border-radius:8px;'
                f'padding:12px;margin:10px 0;background:{bg}">'
                f"<b>{html.escape(a.probe_id)}</b> &middot; {html.escape(a.category)} "
                f'&middot; repeat {a.repeat} &middot; <i>{flag}</i><br>'
                f'<div style="margin-top:6px"><b>Attack:</b> {html.escape(a.variant)}</div>'
                f'<div style="margin-top:6px"><b>Response:</b><br>'
                f'<pre style="white-space:pre-wrap;margin:4px 0 0">{resp}</pre></div>'
                f"</div>"
            )
    detail_blocks = "\n".join(details)

    # --- part 3: glue it all into one html page ---
    # the summary card at top shows the overall numbers + pass/fail badge
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>aisec-eval report</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
        max-width:960px;margin:24px auto;padding:0 16px;color:#1f2328}}
  h1{{font-size:22px}} h2{{font-size:17px;margin-top:28px}}
  table{{border-collapse:collapse;width:100%;margin-top:8px}}
  th,td{{border:1px solid #d0d7de;padding:8px 10px;text-align:left;font-size:14px}}
  th{{background:#f6f8fa}}
  .card{{border:1px solid #d0d7de;border-radius:8px;padding:16px;margin-top:12px;background:#f6f8fa}}
  code{{background:#eff1f3;padding:1px 5px;border-radius:4px}}
</style></head><body>
<h1>aisec-eval &mdash; AI Security Evaluation Report</h1>
<div class="card">
  <div><b>Suite:</b> {html.escape(result.suite_name)}</div>
  <div><b>Model:</b> <code>{html.escape(result.model)}</code></div>
  <div><b>Run started:</b> {html.escape(result.started_at)}</div>
  <div><b>Attempts:</b> {result.total_attempts}
       &middot; <b>Successful attacks:</b> {result.total_successes}</div>
  <div><b>Attack success rate:</b> {result.overall_asr * 100:.1f}%
       &middot; <b>Block rate:</b> {result.overall_block_rate * 100:.1f}%</div>
  <div style="margin-top:6px"><b>Threshold:</b> block rate &ge;
       {result.threshold * 100:.0f}% &nbsp; {_badge(result.passed)}</div>
</div>

<h2>Per-probe summary</h2>
<table>
<tr><th>Probe</th><th>Category</th><th>Hits</th>
    <th>Attack success</th><th>Block rate</th></tr>
{summary_rows}
</table>

<h2>Detailed attempts (raw responses)</h2>
<p style="font-size:13px;color:#57606a">Rows shaded red are attempts the
detector flagged as successful attacks. Keyword/string detectors are a coarse
screen &mdash; always confirm a flagged response by reading it.</p>
{detail_blocks}

</body></html>"""

    # write the final html file to disk
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
