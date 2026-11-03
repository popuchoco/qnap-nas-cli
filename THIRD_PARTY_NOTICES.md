# Third-party references

No third-party source code is bundled in this project, and the projects below are not runtime dependencies. They are listed as product, architecture, and compatibility research references.

## Research projects

### `akari-sora/synology-nas-cli`

- Repository: https://github.com/akari-sora/synology-nas-cli
- License: MIT
- Copyright: Copyright (c) 2026 Akari Sora
- Reference scope: product and architecture ideas including a Python standard-library implementation, shared CLI/JSON/stdio-MCP core, separation of audit and repair workflows, and explicit credential, TLS, compatibility-dump, and agent-safety boundaries.

This project uses QNAP QTS interfaces and implements its own QTS protocol layer. It does not include Synology DSM endpoints, repair commands, ransomware-detection rules, or source code from `synology-nas-cli`. If code is copied in the future, its original copyright and license notices must be retained as required by the MIT License.

### `rvben/qnap-cli`

- Repository: https://github.com/rvben/qnap-cli
- License: MIT
- Reference scope: public implementation and compatibility fixtures used during research into common QTS 5.1/5.2 CGI requests, login forms, sysinfo, and storage response shapes.

No Rust source code from this project is included. `qnap-cli` focuses on file management, while this project focuses on health diagnostics, incident evidence, NAS operations, and guarded agent workflows.

## QNAP vendor documentation

QNAP Authentication and File Station API documents define vendor interfaces; they are documentation references and are not redistributed here.

- [QTS File Station HTTP API v5](https://download.qnap.com/dev/QNAP_QTS_File_Station_API_v5.pdf)
- QTS Authentication API v5.1 documentation
