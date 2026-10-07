# Issue tracker: GitHub

Issues and specs live in this repo's GitHub Issues. Use `gh`. It infers the repo from `git remote`.

## Commands

| Action                    | Command                                                                  |
| ------------------------- | ------------------------------------------------------------------------ |
| Create (publish a ticket) | `gh issue create --title "..." --body-file - <<'EOF' ... EOF`            |
| Read (fetch a ticket)     | `gh issue view <n> --comments`                                           |
| List                      | `gh issue list --state open --label <label> --json number,title,labels`  |
| Comment                   | `gh issue comment <n> --body "..."`                                      |
| Label                     | `gh issue edit <n> --add-label "..."` / `--remove-label "..."`           |
| Close                     | `gh issue close <n> --comment "..."`                                     |

## Pull requests

**PRs as a request surface: no.** Set this to `yes` to triage external PRs like issues. `/triage` reads this flag.

When the flag is `yes`, use the `gh pr` equivalents. Triage only PRs whose `authorAssociation` is `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR` or `NONE`. Issues and PRs share one number space, so for a bare `#42`, try `gh pr view` first, then `gh issue view`.

## Wayfinding

`/wayfinder` uses one **map** issue whose **child** issues are its tickets.

- **Map:** an issue labelled `wayfinder:map`. Its body holds Notes, Decisions so far and Fog.
- **Child:** a GitHub sub-issue of the map, labelled `wayfinder:<research|prototype|grilling|task>`. If sub-issues aren't available, list the child in a task list in the map body and start the child's body with `Part of #<map>`.
- **Blocking:** use native dependencies: `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<id>`. Here `<id>` is the blocker's database id from `gh api repos/<owner>/<repo>/issues/<n> --jq .id`, not its `#number`. If dependencies aren't available, start the child's body with `Blocked by: #<n>, ...`.
- **Frontier:** the map's open children that have no open blocker and no assignee. Take the first one in map order.
- **Claim:** `gh issue edit <n> --add-assignee @me`. Make this the session's first write.
- **Resolve:** comment the answer, close the issue, then add a one-line summary and a link to the map's Decisions so far.
