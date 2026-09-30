"""PERSIST-001: scheduled-task creation.

Locked default (spec Section 7): Medium severity / Medium confidence,
mapped to MITRE T1053.005. Detects the creation of a Windows scheduled
task -- NOT whether that task is malicious. Per the spec: "Legitimate
administration is a required negative case" -- this rule MUST still
fire on a plainly legitimate administrative task, because it detects
the ACTION, not intent.

Detection heuristic (this rule's own documented interpretation, not
spec-locked): an event is treated as scheduled-task creation if
EITHER:
  (a) event_id == "4698" (Windows Security log: "A scheduled task was
      created" -- the authoritative signal, logged regardless of
      which tool created the task), OR
  (b) the FIRST token of command_line, by its basename
      (command_line.py), is exactly "schtasks" or "schtasks.exe", AND
      an exact "/create" token is present anywhere in the line.

Stage 18 fix: (b) previously checked whether the SUBSTRING "schtasks"
appeared anywhere in command_line, which wrongly matched a tool merely
mentioning the word (echo schtasks /create) or an unrelated,
similarly-named executable (not-schtasks-tool, schtasks-backup.exe).
Requiring an EXACT basename match on the first token closes both.

(a) is checked before (b), deliberately: this project's own soc-lab
work documented that schtasks.exe process-creation events are not
logged by that lab's current Sysmon configuration. A rule relying
only on command-line matching would silently inherit that same blind
spot.

Register-ScheduledTask (the PowerShell cmdlet alternative to
schtasks.exe) remains a documented, OPEN evidence gap: not recognized
by heuristic (b), only caught if the source SIEM also emits a 4698 for
it. Unlike PS-001, this rule does not follow an executable invoked via
a parent shell's /c-style flag -- no existing design or test ever
called for that here, so it is not attempted.
"""

from __future__ import annotations

from triageai.command_line import executable_basename
from triageai.models import Confidence, NormalizedEvent, RuleMatch, Severity

RULE_ID = "PERSIST-001"
MITRE_TECHNIQUE = "T1053.005"
_SCHEDULED_TASK_CREATED_EVENT_ID = "4698"
_SCHTASKS_EXECUTABLE_NAMES = frozenset({"schtasks", "schtasks.exe"})


def _is_scheduled_task_creation(event: NormalizedEvent) -> bool:
    if event.event_id == _SCHEDULED_TASK_CREATED_EVENT_ID:
        return True

    command_line = event.command_line
    if command_line is None:
        return False

    if executable_basename(command_line) not in _SCHTASKS_EXECUTABLE_NAMES:
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