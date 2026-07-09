<!--
Thanks for contributing! Keep changes within scope: a browser-side, zero-backend
extension whose assessment engine is passive. See CONTRIBUTING.md.
-->

## Summary

<!-- What does this PR change, and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature / detector / check
- [ ] Refactor / cleanup
- [ ] Documentation
- [ ] Build / CI / release tooling

## Checklist

- [ ] `npm run lint` passes (strict `tsc --noEmit`)
- [ ] `npm run eslint` passes
- [ ] `npm run test` passes (added/updated tests for changed pure modules)
- [ ] `npm run build:all` succeeds (Chrome/Edge + Firefox)
- [ ] Assessment/detection logic stays in pure modules, not in React components
- [ ] No new site mutation beyond the explicit, user-initiated cookie editor
      (no request/response/header modification, no `declarativeNetRequest`)
- [ ] New detection patterns are ReDoS-safe, and any secret-shaped test fixtures
      are assembled from fragments so secret scanners do not match them
- [ ] Updated `README.md` / `ARCHITECTURE.md` / `CHANGELOG.md` if behavior or
      structure changed

## Manual verification

<!-- How did you exercise this in a real browser? Which target(s)? -->
