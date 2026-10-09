# Local state and helper

The helper enforces the package's prop-firm filter independently of candidate preferences. Its `excluded` result is not evidence that a candidate selected that exclusion. It evaluates one operative `pay_floor`; additional profile fields such as desired pay, separate contract floors/terms, undisclosed-pay handling and candidate exclusions are not generally enforced by the helper. The agent must apply those confirmed instructions for the actual role and pay type, and distinguish its own assessment from helper checks. Do not infer an annual contract income or silently overwrite the confirmed floor to make a posting pass. Follow [onboarding](onboarding.md) for preference provenance.

Python 3.10+ on macOS/Linux. No runtime dependencies or network. The installed skill stays read-only; use an explicit private directory selected by the user. JSON files contain personal information and are not encrypted. The helper creates ledger files with mode 0600 and uses a POSIX file lock plus atomic replacement. Don't share a ledger between users or publish it. Keep external evidence accessible to its owner; a path alone does not prove the evidence exists or was read.

Malformed setup/command values return a structured error without replacing the saved ledger. Scope actions, companies, roles and sources must be arrays of nonblank strings; sources must be recognized, instruction references must be nonblank text, and revocation must be a JSON boolean. The helper also validates saved scopes before using them. JSON inputs and ledgers must be regular files; pipes, devices and other special files are refused without opening a blocking read. Confirmation and observed-active fields require actual JSON booleans; strings or numbers must not be interpreted as permission. Explicit unknown preference answers and a missing resume can still support research. A saved ledger with an unsupported schema or malformed record containers must be preserved for review, not silently reinitialized or migrated.

Ledger lock acquisition is limited to one second. A busy ledger returns an error; wait for the owning command to finish before retrying. Do not delete or steal its lock. The operating system releases the lock when that process exits. Symlinked, multiply linked and non-regular lock targets are refused. This bounds local lock contention only; it does not cancel a browser/file-picker or other host-managed call.

From the skill folder:

```sh
python3 scripts/job_search.py init --state /chosen/private/job-search/ledger.json --input profile.json
python3 scripts/job_search.py evaluate --state /chosen/private/job-search/ledger.json --input posting.json
python3 scripts/job_search.py prepare --state /chosen/private/job-search/ledger.json --input preparation.json
python3 scripts/job_search.py show --state /chosen/private/job-search/ledger.json
```

Paths above are user-selected examples, not directories to create literally. The agent creates the JSON input files from the conversation and observed source data, then reads the result. Never interpolate posting text into a shell command. Use structured file tools or safe JSON writes.

Commands supported in this pilot:

| Command | Input and outcome |
| --- | --- |
| `init`, `profile` | Confirmed profile; assistance must be research_only or prepare_only |
| `source-check` | Source ID, status, method, evidence and actual URL/check |
| `evaluate`, `recheck` | Observed posting or explicit synthetic fixture; preserves duplicates/history |
| `prepare` | Job key, evidence IDs and exact truthful materials; optional local attachments for hashing only |
| `review` | Job key, unchanged packet SHA-256 and actual user review reference |
| `gate` | Always not ready for external application actions in this pilot |
| `block`, `resolve-block` | Technical block evidence/resolution; never clears an uncertain external action |
| `show` | Read the local ledger |

`approval`, `standing-scope`, `execution`, `attempt`, `receipt` and `bounce-check` are disabled at the command boundary before state writes. Profiles cannot select assisted_apply. The helper contains inherited internal functions and blank legacy templates for schema continuity; they are not an execution interface or permission grant. The helper cannot constrain unrelated host tools or a user's manual edits. The skill's preparation-only scope governs its use of host tools.

Do not reuse a ledger from another user or overwrite existing history. Select a new private pilot state path. The helper has no network or sending implementation. Its observed-active and evidence flags must reflect inspected source evidence or clearly labeled synthetic tests, never invented live verification. A source timestamp is not a permanent freshness guarantee.
