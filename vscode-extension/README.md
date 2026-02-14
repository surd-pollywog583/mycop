# mycop VS Code Extension

AI-powered code security scanner for VS Code. Detects vulnerabilities in
Python, JavaScript, and TypeScript code.

## Prerequisites

Install the `mycop` CLI:

```sh
# macOS
brew install mycop/tap/mycop

# or via cargo
cargo install mycop

# or via install script
curl -fsSL https://raw.githubusercontent.com/AbdumajidRashidov/mycop/main/install.sh | sh
```

## Features

- Scans files on save and shows security findings as diagnostics
- Supports Python, JavaScript, and TypeScript
- Configurable severity threshold
- Manual scan via Command Palette: "mycop: Scan Current File" / "mycop: Scan Workspace"

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `mycop.executablePath` | `mycop` | Path to mycop binary |
| `mycop.severity` | `low` | Minimum severity to show |
| `mycop.scanOnSave` | `true` | Auto-scan on file save |

## Usage

1. Open a Python, JavaScript, or TypeScript file
2. Save the file (or run "mycop: Scan Current File" from the Command Palette)
3. Security findings appear as diagnostics in the Problems panel
4. Hover over highlighted code for details

## Development

```sh
cd vscode-extension
npm install
npm run compile
```

To test: press F5 in VS Code to launch the Extension Development Host.
