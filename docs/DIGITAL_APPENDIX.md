# Digital appendix

Repository URL:

```text
https://github.com/Esperosa/service-fingerprinting-passive-analysis
```

Purpose:

- public source-code appendix for the bachelor thesis,
- reproducible reference for the implemented prototype,
- documentation of the verification workspace and executable workflow.

The repository contains only the public software appendix. The full thesis
working directory, including LaTeX sources and local publication notes, is kept
in a separate private repository.

Recommended verification commands:

```powershell
npm install
npm run build:ui
npm run test:ui
cargo fmt --check
cargo test
cargo build --release
```

The directory `workspace_thesis_verify_current` contains the controlled
verification workspace referenced by the thesis text.
