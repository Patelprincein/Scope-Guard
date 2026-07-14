# Contributing to ScopeGuard

Thank you for your interest in contributing to ScopeGuard!  
Please read this guide before submitting issues or pull requests.

---

## Code of Conduct

Be respectful, constructive, and professional in all interactions.  
This project exists for **authorized, ethical security assessments only**.  
Any contribution that facilitates unauthorized access will be rejected.

---

## How to Report a Bug

1. Search [existing issues](../../issues) first to avoid duplicates.
2. Open a new issue with the **Bug Report** template.
3. Include:
   - Your OS and Bash version (`bash --version`)
   - The exact command you ran (redact any sensitive targets)
   - The full error output from `scopeguard.log`
   - Expected vs. actual behavior

---

## How to Suggest a Feature

1. Open a new issue with the **Feature Request** template.
2. Describe the use case — what does it enable that the current tool cannot do?
3. If it involves a new external tool dependency, explain why it is worth adding.

---

## Submitting a Pull Request

1. **Fork** the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-improvement
   ```

2. **Keep it focused** — one logical change per PR.

3. **Test your changes** locally:
   ```bash
   bash -n scopeguard.sh          # syntax check
   bash scopeguard.sh --help      # sanity check
   ```

4. **Follow the existing code style**:
   - Use `local` variables inside all functions
   - Use `printf` over `echo` for portable output
   - Always quote variables
   - Use `|| true` where a non-zero exit should not abort the script
   - Prefer `command -v` over `which`

5. Update `CHANGELOG.md` under an `[Unreleased]` section.

6. Open your PR against the `main` branch with a clear description.

---

## Adding Nuclei Templates or Scan Profiles

If you want to contribute additional scan coverage (e.g., new path probes, new NSE scripts, new Nuclei template sets), open an issue first to discuss scope and risk implications before writing code.

---

## License

By contributing you agree that your contributions will be licensed under the [MIT License](LICENSE).
