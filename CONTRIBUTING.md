# Contributing

This document is the source of truth for contribution rules.

## 1. Development Flow

1. Create a branch from `main`.
2. Implement changes and add/update tests.
3. Add `semver:minor` or `semver:major` to the PR if the next release should not be a patch.
4. Commit using Conventional Commits.

## 2. Branch Rules

- `main`: always releasable.
- Working branches: `feature/<topic>`, `fix/<topic>`, `chore/<topic>`.
- Direct push to `main` is not allowed.

## 3. Commit Message Rules (Conventional Commits)

Format:

`<type>(<scope>): <subject>`

Examples:

- `feat(api): add user profile endpoint`
- `fix(parser): handle empty input`
- `docs(readme): clarify setup steps`
- `chore(ci): update workflow cache key`

Types:

- `feat`: new feature
- `fix`: bug fix
- `docs`: documentation only
- `refactor`: code change without behavior change
- `test`: tests
- `chore`: maintenance/configuration

## 4. Release Automation

- Merged changes on `main` that touch `**/*.rs`, `Cargo.toml`, or `Cargo.lock` trigger an automated release.
- The default version bump is `patch`.
- `semver:minor` and `semver:major` override the default bump for the next release.
- If no semver tag exists yet, automation first bootstraps a release from the current Cargo package version.
- Published releases upload Linux `x86_64` and `arm64` binaries.

## 5. CI and Automerge

- Renovate PRs are expected to merge through repository auto-merge after required CI checks pass.
- Keep branch protection aligned with the `CI` workflow so auto-merge cannot bypass validation.
