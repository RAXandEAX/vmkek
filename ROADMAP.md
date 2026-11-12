# Roadmap

[Русский](ROADMAP.ru.md) · [README](README.md)

1. **Make the project easy to try.** A clean clone builds from the lockfile. The README has a working example for Windows and Linux and a profile matrix that explains what is supported.
2. **Measure compatibility and overhead.** Publish the pass rate, failure categories, file size, and p95 runtime on a fixed corpus. Use the same baseline and preserve timeouts so others can repeat the comparison.
3. **Evaluate resistance independently.** Give reviewers several builds without source. Record time to recover behavior, time to reach an accepted result, and the work that transfers to a different seed. Publish scoped findings with the conditions of the test.
4. **Qualify more VM profiles.** Compare depth 2 with the experimental depths on the same fixtures. Check calling conventions, exceptions, and re-entry. Use overhead and independent analysis results to decide which profiles are ready for wider use.
5. **Validate Windows drivers on a live kernel.** Load a properly signed synthetic `.sys` on a dedicated test machine, exercise the expected IOCTL, and check unload. Record the platform and configuration alongside the results.
6. **Exercise the online service under failure.** Verify managed key custody and rotation, loss of a node, PostgreSQL recovery, sustained load, and release rollback. Publish a runbook and state which deployment assumptions were exercised.

The [architecture notes](docs/architecture.md) describe the currently implemented profiles and their evidence.
