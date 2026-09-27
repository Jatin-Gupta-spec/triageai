"""PERSIST-001: scheduled-task creation.

Locked default (spec Section 7): Medium severity / Medium confidence,
mapped to MITRE T1053.005. Detects the creation of a Windows scheduled
task -- NOT whether that task is malicious. Per the spec: "Legitimate
administration is a required negative case" -- meaning this rule MUST
still fire on a plainly legitimate administrative task (e.g. a routine
update check), because it detects the ACTION (task creation), not
intent. The required fixture proving this lives in
tests/test_rule_persist001.py as
test_legitimate_administrative_task_still_matches.

Detection heuristic, stated explicitly (this rule's own documented
interpretation, not spec-locked -- same pattern as AUTH-001/PS-001):
an event is treated as scheduled-task creation if EITHER:
  (a) event_id == "4698" (Windows Security log: "A scheduled task was
      created" -- the authoritative signal, logged by Windows itself
      regardless of which tool created the task), OR
  (b) command_line invokes schtasks.exe (or bare "schtasks") with a
      /create flag (case-insensitive, exact token match).

Deliberately relies on (a) as the PRIMARY signal, not a fallback --
this is a direct lesson from this project's own SOC lab work: the
soc-lab README documents that schtasks.exe process-creation events are
NOT logged by that lab's current Sysmon configuration (SC-003 /
INV-004, a real gap found and recorded there). A rule that only
checked command_line for schtasks.exe would silently inherit that
exact same blind spot. Event ID 4698 comes from the Windows Security
log via a DIFFERENT audit policy than Sysmon's process-creation
logging, so it is not subject to that particular gap -- which is why
it's checked first here, not as an afterthought.

Register-ScheduledTask (the PowerShell cmdlet alternative to
schtasks.exe) is a documented, OPEN evidence gap, not silently
covered: it is not currently recognized by heuristic (b), only caught
if the source SIEM happens to also emit a 4698 for it. Extending (b)
to recognize that cmdlet name is a reasonable future addition, not a
bug fix to this stage.
"""

from __future__ import annotations

from triageai.models import Confidence, NormalizedEvent, RuleMatch, Severity

RULE_ID = "PERSIST-001"
MITRE_TECHNIQUE = "T1053.005"
_SCHEDULED_TASK_CREATED_EVENT_ID = "4698"


def _is_scheduled_task_creation(event: NormalizedEvent) -> bool:
    if event.event_id == _SCHEDULED_TASK_CREATED_EVENT_ID:
        return True

    command_line = (event.command_line or "").lower()
    if "schtasks" not in command_line:
        return False
    return any(token.lower() == "/create" for token in command_line.split())


def evaluate(events: tuple[NormalizedEvent, ...]) -> tuple[RuleMatch, ...]:
    """Flag every scheduled-task creation event or schtasks /create command.

    Fires regardless of whether the task appears benign or malicious --
    per this rule's documented limitation, that judgment belongs to the
    human analyst reviewing the full case, not to this deterministic
    pattern match.
    """
    matches: list[RuleMatch] = []

    for event in events:
        if not _is_scheduled_task_creation(event):
            continue

        matches.append(
            RuleMatch(
                rule_id=RULE_ID,
                mitre_technique=MITRE_TECHNIQUE,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                matched_event_ids=(event.original_record_id,),
                description=(
                    f"Scheduled task created on host {event.host or '?'} "
                    f"(pattern match only -- does not indicate malicious intent)"
                ),
            )
        )

    return tuple(matches)