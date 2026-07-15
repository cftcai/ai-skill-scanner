# ai-skill-scanner TODO

## Completed (2026-07-15)
- feat(script): --make-public mode added to bulk_visibility.sh (visibility + topics)
- feat(workflow): scan-url.yml added for lightweight web demo backend (workflow_dispatch with url input)
- doc(web): updated demo with note for real scans via new workflow
- GitHub Actions section moved to top with improved visual formatting
- Web frontend demo UX improved (empty input, dedicated demo button, dynamic versions)

## In Progress / Next
- feat(scanner): implement full --update-signatures flag + inline schema validation in scanner.py (basic version added; full git cache + load in next iteration)
- Keep all repos private until web + real scanning path fully validated end-to-end

## Not Done
- Full production backend wiring for web demo (dispatch integration tested)
- Make repositories public + add topics (use bulk script --make-public after validation)
- Add secret scanning / dependency review to CI
- Publish as PyPI package + hosted demo

## Recommended Strategy
Short-term: Finish scanner flag + schema validation and test the scan-url workflow end-to-end.
Medium-term: Add real dispatch button or API call from web demo.
Long-term: Decide on public hosting and packaging.