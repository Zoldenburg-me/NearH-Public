# How we worked

nearH was built in parallel by two people and several AI coding agents, each in a fixed role. This file describes the roles and the loop every change went through. It describes the process, not the code; for what the code does, see [README.md](README.md).

## Roles
- **Owner:** one of the two people on the team. Sets scope, approves anything that touches keys, funds or publishing, and is the only one who can make an exception to the rules below. Owner-side actions (setting a mandate, changing payees, topping up the float) are signed with the owner's passkey; no agent can do them.
- **Teammate:** the second person, working with their own coding agent. Took anything that needs a login, a sandbox account, a portal API key or a passkey tap, plus scoped coding tasks.
- **Lead agent:** turns the plan into tasks on a shared task board, assigns them, picks a reviewer for each pull request and closes tasks once they are merged. It is the only one that creates, closes or reassigns tasks.
- **Builder agents:** each claims one task, works only inside the folder that task names, and opens one pull request for it. One open task per folder, so two builders never edit the same code at once.
- **Reviewer agent:** reads each pull request and posts a verdict. It is read-only: it never commits and never edits the board. It is always a different agent from the builder.
- **Automated PR reviewer:** an outside review bot that comments on every pull request, as a second pair of eyes next to the reviewer agent.
- **CI:** runs the contract tests (`cargo test`) and every TypeScript package's tests (`pnpm -r test`) on pull requests that touch code; docs-only changes skip both suites.

## The loop
1. **Board task.** The lead writes a task: what to build, which folder, what it depends on and what "done" means (usually a test that must pass).
2. **Builder pull request.** The builder claims the task, branches from `main`, makes the smallest change that completes it, adds a test that fails without each new rule, and runs the tests and a secret scan before every commit. The pull request says what changed, how it was tested and what was not checked.
3. **Checks.** CI runs the tests, the automated PR reviewer (the Devin review bot) comments, and the lead agent assigns a reviewer agent.
4. **Verdict.** The reviewer posts one comment per reviewed commit. It starts with the commit SHA it read and the verdict: `clear` or `changes needed`. The builder fixes every Critical, High and Medium finding, pushes, and the reviewer reads the new head.
5. **Merge.** A pull request merges only when CI is green and a `clear` names its current head SHA, so a verdict on an older commit never counts. If the branch is rebased onto `main` without conflicts and its diff is unchanged, the lead may carry the `clear` over; any other change needs a new review. The builder merges; nobody merges their own unreviewed work.
6. **Close.** The lead closes the task on the board.

**Security findings come before features.** When a review or an audit found a security problem, fixing it took priority over new feature work, and it went through the same loop: a task, a pull request with a test that reproduces the problem, a review, a merge.

## Ground rules every role followed
- **Testnets and sandboxes only:** NEAR testnet, Base Sepolia and the Monerium sandbox. No mainnet and no live funds.
- **No secrets in the repo.** Each agent had its own throwaway keys in an untracked `.env`; commits were scanned for secrets before they were made.
- **Agents pay, owners decide.** The agent tools are `pay_x402`, `pay_sepa`, `revoke` (of the agent itself) and `get_receipt`. Everything that changes the rules is owner-side.
- **Claims match the code.** The README and pull request text say only what the code does today, and every pull request lists what it did not check.
