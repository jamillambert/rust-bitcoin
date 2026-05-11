# rust-bitcoin workflow notes

We are attempting to run max 20 parallel jobs using GitHub actions (usage limit for free tier).

ref: https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration

The minimal/recent lock files are handled by CI (`rust.yml`).

## Jobs

Run from rust.yml unless stated otherwise. Unfortunately we are now exceeding the 20 job target.
(Prepare is quick and must be run first anyway.)

0.  `Test - stable toolchain, minimal deps`
1.  `Test - stable toolchain, recent deps`
2.  `Test - msrv toolchain, minimal deps`
3.  `Test - msrv toolchain, recent deps`
4.  `Check - api`
5.  `Check - lint`
6.  `Check - docs`
7.  `Check - docsrs`
8.  `Check - bench`
9.  `Prerelease`
10. `Prepare`
11. `ASAN`
12. `WASM`
13. `Arch32bit`
14. `Cross - s390x-unknown-linux-gnu`
15. `Cross - aarch64-unknown-linux-gnu`
16. `Embedded`
17. `Kani`
18. `Coveralls` - run by `coveralls.yml`
19. `release` - run by `release.yml`
20. `labeler` - run by `manage-pr.yml`
21. `Shellcheck` - run by `shellcheck.yml`
