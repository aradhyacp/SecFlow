import { FileCode, FileText, AlertTriangle, CheckCircle, Shield, Database } from 'lucide-react'

const Section = ({ title, icon: Icon, children }) => (
    <div className="mb-12">
        <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-300">
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
                <div className="inline-block px-3 py-1 bg-amber-500/10 text-amber-300 rounded-full text-xs font-mono mb-4">
                    OFFICE MACRO FORENSICS
                </div>
                <h1 className="text-4xl font-bold text-white mb-4">Macro Analysis Documentation</h1>
                <p className="text-xl text-foreground/60">
                    Analyze Office and RTF documents for VBA/XLM macro abuse, suspicious execution behavior,
                    and extracted indicators of compromise.
                </p>
            </div>

            <Section title="What Is Macro Analysis?" icon={FileCode}>
                <p>
                    Macro Analysis focuses on documents that may contain embedded script logic used for phishing,
                    initial malware execution, and downloader behavior. SecFlow Macro Analyzer uses <code>olevba</code>
                    to detect and extract macro content from common Office formats.
                </p>
                <ul className="list-disc pl-5 mt-3 space-y-2 text-foreground/70">
                    <li><strong>Macro discovery:</strong> Detects whether VBA content exists.</li>
                    <li><strong>Source extraction:</strong> Pulls stream/module-level macro code.</li>
                    <li><strong>Indicator tagging:</strong> Flags AutoExec, Suspicious, IOC, and obfuscation clues.</li>
                    <li><strong>Risk scoring:</strong> Classifies findings into clean, macro_present, suspicious, or malicious.</li>
                </ul>
            </Section>

            <Section title="Supported Inputs" icon={FileText}>
                <p>
                    The backend endpoint is <code>POST /api/macro-analyzer/analyze</code> and expects
                    <code> multipart/form-data</code> with a <code>file</code> field.
                </p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 my-4">
                    {['DOC', 'DOCX', 'DOCM', 'XLS', 'XLSX', 'XLSM', 'XLSB', 'PPT', 'PPTX', 'PPTM', 'RTF'].map((ext) => (
                        <div key={ext} className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-center">
                            <span className="text-sm font-mono font-bold text-amber-300">.{ext}</span>
                        </div>
                    ))}
                </div>
                <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg my-6">
                    <div className="flex items-start gap-3">
                        <Shield className="text-blue-300 mt-1 shrink-0" size={18} />
                        <div className="text-sm text-blue-200">
                            Upload only one document at a time in the dashboard workflow to preserve clear, auditable
                            macro analysis context per sample.
                        </div>
                    </div>
                </div>
            </Section>

            <Section title="Analysis Workflow" icon={Database}>
                <ol className="list-decimal pl-5 mt-3 space-y-2 text-foreground/70">
                    <li>File extension is validated against allowed Office/RTF document types.</li>
                    <li><code>olevba</code> detects macro presence and extracts VBA modules when available.</li>
                    <li>Indicator categories are computed (AutoExec, Suspicious, IOC, Hex/Base64 strings).</li>
                    <li>Risk level is derived from execution and suspicious indicator combinations.</li>
                    <li>If VirusTotal key is configured, hash lookup/upload enrichment is attached to the result.</li>
                </ol>
                <p className="mt-4">
                    The response includes macro source snippets, indicator groups, IOC entries,
                    risk level, and optional VirusTotal statistics for triage.
                </p>
            </Section>

            <Section title="Interpreting Results" icon={AlertTriangle}>
                <div className="space-y-3 my-4">
                    <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                        <h4 className="font-bold text-emerald-300 mb-1">CLEAN</h4>
                        <p className="text-sm text-emerald-200">No macro evidence or no suspicious patterns detected.</p>
                    </div>
                    <div className="p-4 bg-sky-500/10 border border-sky-500/20 rounded-lg">
                        <h4 className="font-bold text-sky-300 mb-1">MACRO_PRESENT</h4>
                        <p className="text-sm text-sky-200">Macros exist but indicator profile is lower risk.</p>
                    </div>
                    <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg">
                        <h4 className="font-bold text-amber-300 mb-1">SUSPICIOUS</h4>
                        <p className="text-sm text-amber-200">Potentially risky macro behavior or IOC signals found.</p>
                    </div>
                    <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                        <h4 className="font-bold text-red-300 mb-1">MALICIOUS</h4>
                        <p className="text-sm text-red-200">Strong malicious traits, often AutoExec + Suspicious indicators.</p>
                    </div>
                </div>
                <div className="p-4 bg-[#0c1120] border border-white/10 rounded-lg mt-6">
                    <div className="flex items-start gap-3">
                        <CheckCircle className="text-neon-blue mt-1 shrink-0" size={18} />
                        <p className="text-sm text-foreground/70 m-0">
                            Recommended next step: run suspicious IOC artifacts through Smart Pipeline for cross-tool
                            correlation with Web, Malware, Recon, and Steg analyzers.
                        </p>
                    </div>
                </div>
            </Section>
        </div>
    )
}
