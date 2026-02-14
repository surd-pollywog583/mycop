import * as vscode from 'vscode';
import * as cp from 'child_process';

const DIAGNOSTIC_SOURCE = 'mycop';
let diagnosticCollection: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
    context.subscriptions.push(diagnosticCollection);

    // Command: scan current file
    context.subscriptions.push(
        vscode.commands.registerCommand('mycop.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                scanFile(editor.document);
            }
        })
    );

    // Command: scan workspace
    context.subscriptions.push(
        vscode.commands.registerCommand('mycop.scanWorkspace', () => {
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
            if (workspaceFolder) {
                scanPath(workspaceFolder.uri.fsPath);
            }
        })
    );

    // Auto-scan on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((doc) => {
            const config = vscode.workspace.getConfiguration('mycop');
            if (config.get<boolean>('scanOnSave', true)) {
                scanFile(doc);
            }
        })
    );

    // Scan all open files on activation
    vscode.workspace.textDocuments.forEach(scanFile);
}

export function deactivate() {
    diagnosticCollection.dispose();
}

function getExecutablePath(): string {
    const config = vscode.workspace.getConfiguration('mycop');
    return config.get<string>('executablePath', 'mycop');
}

function getSeverity(): string {
    const config = vscode.workspace.getConfiguration('mycop');
    return config.get<string>('severity', 'low');
}

function scanFile(document: vscode.TextDocument): void {
    const supportedLanguages = [
        'python',
        'javascript',
        'typescript',
        'typescriptreact',
        'javascriptreact',
    ];
    if (!supportedLanguages.includes(document.languageId)) {
        return;
    }
    scanPath(document.uri.fsPath, document.uri);
}

function scanPath(filePath: string, fileUri?: vscode.Uri): void {
    const executable = getExecutablePath();
    const severity = getSeverity();
    const args = ['scan', filePath, '--format', 'sarif', '--severity', severity];

    cp.execFile(
        executable,
        args,
        { maxBuffer: 10 * 1024 * 1024 },
        (error, stdout, stderr) => {
            // mycop exits 1 when findings exist, which is not an error for us
            if (stderr && !stdout) {
                vscode.window.showErrorMessage(`mycop error: ${stderr}`);
                return;
            }

            try {
                const sarif = JSON.parse(stdout);
                const diagnosticsMap = parseSarif(sarif);

                if (fileUri) {
                    // Single file scan — clear old diagnostics for this file
                    diagnosticCollection.set(
                        fileUri,
                        diagnosticsMap.get(fileUri.fsPath) || []
                    );
                } else {
                    // Workspace scan — replace all diagnostics
                    diagnosticCollection.clear();
                    for (const [path, diags] of diagnosticsMap) {
                        diagnosticCollection.set(vscode.Uri.file(path), diags);
                    }
                }
            } catch {
                // Parse error — likely no findings or empty output
            }
        }
    );
}

interface SarifResult {
    ruleId: string;
    level: string;
    message: { text: string };
    locations: Array<{
        physicalLocation: {
            artifactLocation: { uri: string };
            region: { startLine: number; startColumn: number };
        };
    }>;
}

interface SarifRun {
    tool: {
        driver: {
            rules?: Array<{
                id: string;
                shortDescription?: { text: string };
            }>;
        };
    };
    results: SarifResult[];
}

function parseSarif(sarif: {
    runs: SarifRun[];
}): Map<string, vscode.Diagnostic[]> {
    const diagnosticsMap = new Map<string, vscode.Diagnostic[]>();

    for (const run of sarif.runs || []) {
        for (const result of run.results || []) {
            for (const location of result.locations || []) {
                const phys = location.physicalLocation;
                const filePath = phys.artifactLocation.uri;
                const line = Math.max(0, (phys.region.startLine || 1) - 1);
                const col = Math.max(0, (phys.region.startColumn || 1) - 1);

                const range = new vscode.Range(line, col, line, col + 20);
                const severity = sarifLevelToVscode(result.level);
                const message = result.message.text;

                const diagnostic = new vscode.Diagnostic(range, message, severity);
                diagnostic.source = DIAGNOSTIC_SOURCE;
                diagnostic.code = result.ruleId;

                const existing = diagnosticsMap.get(filePath) || [];
                existing.push(diagnostic);
                diagnosticsMap.set(filePath, existing);
            }
        }
    }

    return diagnosticsMap;
}

function sarifLevelToVscode(level: string): vscode.DiagnosticSeverity {
    switch (level) {
        case 'error':
            return vscode.DiagnosticSeverity.Error;
        case 'warning':
            return vscode.DiagnosticSeverity.Warning;
        case 'note':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}
