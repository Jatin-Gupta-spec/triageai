# Release Checklist

Run every item in order. Don't skip ahead on the assumption a step
"should" pass — actually run it and read the real output, the same
discipline this whole project was built on.

## 1. Code and tests
- [ ] `python -m pytest -q` — all pass, only the expected platform-
      specific skips (Windows: symlink tests needing elevated
      privileges, see LIMITATIONS.md item 9)
- [ ] `python -m ruff check .` — clean
- [ ] `python -m mypy src` — clean (strict mode, enforced via
      `pyproject.toml`)
- [ ] `python -m pip_audit` — no known vulnerabilities in real
      third-party dependencies (the `triageai` skip-reason line is
      expected, not a finding)

## 2. Cross-platform CI
- [ ] All four CI matrix legs green (ubuntu-latest and windows-latest,
      Python 3.11 and 3.13)
- [ ] Windows-latest's symlink/junction tests confirmed to RUN, not
      skip, in the CI log itself

## 3. Determinism
- [ ] Two runs of the same fixture, hashed with `Get-FileHash`,
      produce identical SHA-256 — repeat across at least a benign, a
      suspicious, a contradictory, and a hostile-input fixture

## 4. Manual privacy check
- [ ] A planted canary (fake password, API token, Authorization
      header, Cookie, email, and a user-profile path with a space in
      it) run through `analyze`, with the full output read by a human
      and confirmed clean

## 5. Repository cleanliness
- [ ] `git status --short` empty
- [ ] `git ls-files | grep` for `.venv`, `__pycache__`,
      `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.pyc`,
      `.egg-info` returns nothing

## 6. Acceptance record
- [ ] `ACCEPTANCE.md` updated with the real commit, real date, and
      real test/lint/type-check/audit results from BOTH a fresh
      Windows venv and the current Ubuntu CI log -- never
      hand-written or assumed

## 7. Tag and archive
- [ ] `git tag -a vX.Y.Z -m "..."`, then `git show vX.Y.Z` read and
      confirmed to point at the intended commit
- [ ] `git archive --format=zip --output=... vX.Y.Z` built FROM THE
      TAG, not from a loose working-tree state
- [ ] Archive listing inspected -- confirmed no `.venv`, `.git`,
      caches, scratch files, or credentials
- [ ] Archive extracted into a genuinely separate directory, installed
      into a fresh venv, and the full check suite re-run there --
      proving the release doesn't secretly depend on an untracked
      local file
- [ ] Archive and any temporary extraction directory deleted after
      verification

## 8. Push
- [ ] `git push`
- [ ] `git push origin vX.Y.Z`