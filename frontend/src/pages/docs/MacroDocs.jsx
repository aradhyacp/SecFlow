import { FileCode, Shield, Zap, Search, FileText, AlertTriangle, CheckCircle } from 'lucide-react'

const Section = ({ title, icon: Icon, children }) => (
    <div className="mb-12">
        <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
                <Icon size={20} />
            </div>
            <h2 className="text-2xl font-bold text-white">{title}</h2>
        </div>
        <div className="prose prose-invert prose-p:text-foreground/70 prose-headings:text-white max-w-none">
            {children}
        </div>
    </div>
)

export default function MacroDocs() {
    return (
        <div className="space-y-8">
            <div className="border-b border-white/10 pb-8">
                <div className="inline-block px-3 py-1 bg-cyan-500/10 text-cyan-300 rounded-full text-xs font-mono mb-4">
                    OFFICE DOCUMENT TRIAGE
                </div>
                <h1 className="text-4xl font-bold text-white mb-4">Macro Analysis Documentation</h1>
                <p className="text-xl text-foreground/60">
                    Complete guide to analyzing suspicious Office documents for VBA macro behavior, embedded scripts, and IOC extraction using the SecFlow Macro Analyzer.
                </p>
            </div>

            <Section title="What is Macro Analysis?" icon={FileCode}>
                <p>
                    Macro Analysis investigates Office documents for potentially malicious automation logic such as VBA code, auto-run routines, encoded payloads, and command execution patterns.
                    It helps identify phishing payloads, loaders, and document-borne malware before execution.
                </p>
                <ul className="list-disc pl-5 mt-3 space-y-2 text-foreground/70">
                    <li><strong>Word:</strong> DOC, DOCX, DOCM, RTF</li>
                    <li><strong>Excel:</strong> XLS, XLSX, XLSM, XLSB</li>
                    <li><strong>PowerPoint:</strong> PPT, PPTX, PPTM</li>
                    <li><strong>Macro Streams:</strong> VBA modules and suspicious keywords</li>
                    <li><strong>IOCs:</strong> URLs, domains, IPs, email artifacts, and commands</li>
                </ul>
                <div className="p-4 bg-cyan-500/10 border border-cyan-500/20 rounded-lg my-6 mt-6">
                    <div className="flex items-start gap-3">
                        <AlertTriangle className="text-cyan-300 mt-1 shrink-0" size={18} />
                        <div className="text-sm text-cyan-100">
                            <strong>Operational note:</strong> Macro Analysis is static triage. It does not execute document content and is designed for safe initial classification.
                        </div>
                    </div>
                </div>
            </Section>

            <Section title="Analysis Pipeline" icon={Zap}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Stage 1: Document Intake and Validation</h3>
                <p>
                    Uploaded files are validated for supported Office formats and normalized for parser safety.
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>Extension and structure validation</li>
                    <li>File metadata and size profiling</li>
                    <li>Preparation for macro extraction</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Stage 2: VBA and Behavior Extraction</h3>
                <p>
                    The analyzer extracts VBA content and inspects behavior patterns commonly used by malicious documents.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-cyan-300 mb-2">Macro Presence</h4>
                        <p className="text-sm text-foreground/70">Detects whether macro streams exist and how many modules are present.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-cyan-300 mb-2">Auto-Execution Flags</h4>
                        <p className="text-sm text-foreground/70">Finds patterns such as AutoOpen and Document_Open behavior triggers.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-cyan-300 mb-2">Suspicious Keywords</h4>
                        <p className="text-sm text-foreground/70">Identifies risky API and shell-like invocation patterns in VBA code.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-cyan-300 mb-2">IOC Extraction</h4>
                        <p className="text-sm text-foreground/70">Harvests indicators such as URLs, IP addresses, domains, and command strings.</p>
                    </div>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Stage 3: Threat Enrichment</h3>
                <p>
                    If configured, file hashes are enriched with threat intelligence for additional verdict context.
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>VirusTotal engine verdict breakdown</li>
                    <li>Malicious/suspicious/undetected totals</li>
                    <li>Report metadata for analyst cross-checking</li>
                </ul>
            </Section>

            <Section title="Interpreting Results" icon={Search}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Risk Levels</h3>
                <div className="space-y-3 my-4">
                    <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                        <h4 className="font-bold text-red-400 mb-1">MALICIOUS</h4>
                        <p className="text-sm text-red-200">Clear harmful intent, often combining macro automation with payload delivery or execution behavior.</p>
                    </div>
                    <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                        <h4 className="font-bold text-yellow-400 mb-1">SUSPICIOUS</h4>
                        <p className="text-sm text-yellow-200">Contains risky constructs or indicators but requires analyst validation.</p>
                    </div>
                    <div className="p-4 bg-cyan-500/10 border border-cyan-500/20 rounded-lg">
                        <h4 className="font-bold text-cyan-300 mb-1">MACRO_PRESENT</h4>
                        <p className="text-sm text-cyan-100">Macros are present but high-risk indicators are limited; continue triage.</p>
                    </div>
                    <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
                        <h4 className="font-bold text-green-400 mb-1">CLEAN</h4>
                        <p className="text-sm text-green-200">No high-confidence malicious indicators detected in static analysis.</p>
                    </div>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Output Fields</h3>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>flags:</strong> behavior booleans (autoexec, suspicious keywords, executable patterns)</li>
                    <li><strong>indicators:</strong> categorized evidence arrays from extracted code</li>
                    <li><strong>iocs:</strong> normalized indicators of compromise for downstream workflows</li>
                    <li><strong>macros:</strong> extracted macro snippets and source preview</li>
                    <li><strong>vt:</strong> optional external enrichment details</li>
                </ul>
            </Section>

            <Section title="Operational Guidance" icon={Shield}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Recommended Triage Flow</h3>
                <div className="space-y-3 my-4">
                    <div className="flex items-start gap-3 p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <CheckCircle className="text-cyan-300 mt-1 shrink-0" size={18} />
                        <div>
                            <h4 className="font-bold text-white mb-1">1. Validate risk level and flags</h4>
                            <p className="text-sm text-foreground/70">Prioritize files with suspicious or malicious classifications first.</p>
                        </div>
                    </div>
                    <div className="flex items-start gap-3 p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <CheckCircle className="text-cyan-300 mt-1 shrink-0" size={18} />
                        <div>
                            <h4 className="font-bold text-white mb-1">2. Review IOC categories</h4>
                            <p className="text-sm text-foreground/70">Pivot extracted URLs, domains, and IPs into web/recon workflows.</p>
                        </div>
                    </div>
                    <div className="flex items-start gap-3 p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <CheckCircle className="text-cyan-300 mt-1 shrink-0" size={18} />
                        <div>
                            <h4 className="font-bold text-white mb-1">3. Escalate to malware sandbox if needed</h4>
                            <p className="text-sm text-foreground/70">Use binary analysis when macros reference executable payload chains.</p>
                        </div>
                    </div>
                </div>
            </Section>

            <Section title="Report Export and Sharing" icon={FileText}>
                <p>
                    Macro analysis output is structured for SOC pipelines and incident workflows.
                    Use extracted indicators and risk labels in tickets, case notes, and orchestration reports.
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>Preserve original document hash and filename</li>
                    <li>Attach extracted IOC sets and suspicious macro snippets</li>
                    <li>Map findings to response actions and containment priorities</li>
                </ul>
            </Section>
        </div>
    )
}
