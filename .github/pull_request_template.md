## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `python3 -m unittest discover -s tests` passes
- [ ] `python3 tools/build_index.py --check` passes (run `python3 tools/build_index.py` after adding or editing cards)
- [ ] No new dependencies (Python stdlib only, nothing added to `package.json`) and no install scripts
- [ ] Still read-only by default; no secret values printed in any output format

### If this adds or changes an incident card

- [ ] `python3 scripts/zerohour.py card validate incidents/<card>.json` passes
- [ ] Every fact is backed by a linked primary source
- [ ] IOCs are only ones a cited source reports
- [ ] Remediation is in safe order (contain / disarm → rotate → upgrade / pin → hunt → harden) with dangerous steps flagged
- [ ] Any fixtures are inert (name and location only, no working payload)
