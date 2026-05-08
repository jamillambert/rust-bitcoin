# rust-bitcoin workflow notes

We are attempting to run max 20 parallel jobs using GitHub actions (usage limit for free tier).

ref: https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration

The minimal/recent lock files are handled by CI (`rust.yml`).

## Jobs

Run from rust.yml unless stated otherwise. Unfortunately we are now exceeding the 20 job target.
(Prepare is quick and must be run first anyway.)

0.  `Test - stable toolchain, minimal deps`
1.  `Test - stable toolchain, recent deps`
2.  `Test - nightly toolchain, minimal deps`
3.  `Test - nightly toolchain, recent deps`
4.  `Test - msrv toolchain, minimal deps`
5.  `Test - msrv toolchain, recent deps`
6.  `Check - lint`
7.  `Check - docs`
8.  `Check - docsrs`
9.  `Check - bench`
10. `Prepare`
11. `ASAN`
12. `WASM`
13. `Arch32bit`
14. `Cross`
15. `Embedded`
16. `Kani`
17. `Coveralls` - run by `coveralls.yml`
18. `release` - run by `release.yml`
19. `labeler` - run by `manage-pr.yml`
20. `Shellcheck` - run by `shellcheck.yml`
