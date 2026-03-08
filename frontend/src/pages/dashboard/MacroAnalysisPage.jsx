import { useRef, useState } from 'react'
import { motion } from 'framer-motion'
import {
    Upload,
    FileCode,
    Terminal,
    Activity,
    Loader2,
    AlertTriangle,
    Shield,
    Database,
    FileText,
    CheckCircle2,
    XCircle,
} from 'lucide-react'

const ALLOWED_EXTENSIONS = ['doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'xlsb', 'ppt', 'pptx', 'pptm', 'rtf']

const RISK_STYLE = {
    clean: {
        label: 'CLEAN',
        badge: 'bg-emerald-500/10 border border-emerald-500/25 text-emerald-300',
        text: 'No suspicious macro behavior detected.',
    },
    macro_present: {
        label: 'MACRO PRESENT',
        badge: 'bg-sky-500/10 border border-sky-500/25 text-sky-300',
        text: 'Macros detected with low-risk indicator patterns.',
    },
    suspicious: {
        label: 'SUSPICIOUS',
        badge: 'bg-amber-500/10 border border-amber-500/25 text-amber-300',
        text: 'Suspicious macro indicators and/or IOCs were found.',
    },
    malicious: {
        label: 'MALICIOUS',
        badge: 'bg-red-500/10 border border-red-500/25 text-red-300',
        text: 'High-risk macro behavior with auto-exec and suspicious traits.',
    },
}

const TerminalLine = ({ text, color = 'text-foreground/70' }) => (
    <motion.div
        initial={{ opacity: 0, x: -10 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.25 }}
        className={`font-mono text-[10px] ${color}`}
    >
        <span className="text-foreground/20 mr-2">$</span>
        {text}
    </motion.div>
)

const getExtension = (name) => name.split('.').pop()?.toLowerCase() || ''

export default function MacroAnalysisPage() {
    const [file, setFile] = useState(null)
    const [analyzing, setAnalyzing] = useState(false)
    const [result, setResult] = useState(null)
    const [logs, setLogs] = useState([])
    const [error, setError] = useState('')
    const fileInputRef = useRef(null)

    const addLog = (text, color = 'text-foreground/70') => {
        setLogs((prev) => [...prev, { text, color }])
    }

    const clearResults = () => {
        setResult(null)
        setError('')
        setLogs([])
    }

    const clearAll = () => {
        setFile(null)
        clearResults()
    }

    const validateFile = (candidate) => {
        const extension = getExtension(candidate.name)
        if (!ALLOWED_EXTENSIONS.includes(extension)) {
            setError(`Unsupported file type .${extension || 'unknown'}. Allowed: ${ALLOWED_EXTENSIONS.map((ext) => ext.toUpperCase()).join(', ')}`)
            return false
        }
        setError('')
        return true
    }

    const handleFileSelect = (event) => {
        const selected = event.target.files?.[0]
        if (!selected) return

        if (!validateFile(selected)) {
            event.target.value = ''
            return
        }

        setFile({
            name: selected.name,
            size: `${(selected.size / (1024 * 1024)).toFixed(2)} MB`,
            ext: getExtension(selected.name),
            rawFile: selected,
        })
        clearResults()
        event.target.value = ''
    }

    const handleFileDrop = (event) => {
        event.preventDefault()
        const dropped = event.dataTransfer.files?.[0]
        if (!dropped) return

        if (!validateFile(dropped)) return

        setFile({
            name: dropped.name,
            size: `${(dropped.size / (1024 * 1024)).toFixed(2)} MB`,
            ext: getExtension(dropped.name),
            rawFile: dropped,
        })
        clearResults()
    }

    const runMacroAnalysis = async () => {
        if (!file?.rawFile) return

        setAnalyzing(true)
        setError('')
        setResult(null)
        setLogs([])

        addLog('[+] Macro analyzer initialized...', 'text-emerald-400')
        addLog(`[+] Uploading ${file.name}...`)
        addLog('[*] Validating Office/RTF container...')

        try {
            const formData = new FormData()
            formData.append('file', file.rawFile)

            const response = await fetch('http://localhost:5006/api/macro-analyzer/analyze', {
                method: 'POST',
                body: formData,
            })

            const data = await response.json()
            if (!response.ok || !data.success) {
                throw new Error(data.error || `Request failed with status ${response.status}`)
            }

            addLog('[+] VBA extraction complete.', 'text-emerald-400')
            addLog('[+] Indicator analysis complete.', 'text-emerald-400')
            if (data.vt?.success) {
                addLog('[+] VirusTotal enrichment complete.', 'text-emerald-400')
            } else if (data.vt?.error) {
                addLog(`[!] VirusTotal enrichment skipped: ${data.vt.error}`, 'text-amber-400')
            }
            addLog(`[+] Risk classified as ${String(data.risk_level || 'clean').toUpperCase()}.`, 'text-emerald-400')

            setResult(data)
        } catch (requestError) {
            const message = requestError instanceof Error ? requestError.message : 'Macro analysis failed'
            setError(message)
            addLog(`[!] ${message}`, 'text-red-400')
        } finally {
            setAnalyzing(false)
        }
    }

    const indicatorEntries = Object.entries(result?.indicators || {})
    const macroItems = result?.macros || []
    const iocItems = result?.iocs || []
    const suspiciousHits = indicatorEntries.reduce((acc, [, items]) => acc + items.length, 0)
    const vtStats = result?.vt?.stats || {}
    const vtMalicious = (vtStats.malicious || 0) + (vtStats.suspicious || 0)
    const riskLevel = String(result?.risk_level || 'clean').toLowerCase()
    const riskStyle = RISK_STYLE[riskLevel] || RISK_STYLE.clean

    return (
        <div className="max-w-7xl mx-auto space-y-6 pb-20">
            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-6 py-4">
                    <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-md bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
                            <FileCode size={22} className="text-amber-300" />
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-white tracking-tight">Macro Analysis</h2>
                            <p className="text-xs text-foreground/40 font-mono">Office Document Macro Forensics</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                        <span className="text-[10px] font-mono text-emerald-400 font-bold tracking-wider">API ONLINE</span>
                    </div>
                </div>
                {analyzing && (
                    <motion.div
                        className="h-0.5 bg-gradient-to-r from-amber-500 via-emerald-400 to-amber-500"
                        style={{ backgroundSize: '200% 100%' }}
                        animate={{ backgroundPosition: ['0% 0', '200% 0'] }}
                        transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
                    />
                )}
            </div>

            <div className={analyzing || result ? 'grid grid-cols-1 lg:grid-cols-12 gap-6' : 'max-w-xl mx-auto mt-10 space-y-4'}>
                <div className={analyzing || result ? 'lg:col-span-4 space-y-4' : 'space-y-4'}>
                    <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileSelect} />

                    <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                            <Upload size={12} className="text-amber-300" />
                            <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">Document Upload</span>
                        </div>
                        <motion.div
                            layout
                            className={`p-8 text-center transition-all cursor-pointer ${file ? 'bg-emerald-500/[0.03]' : 'hover:bg-white/[0.01]'} ${analyzing ? 'pointer-events-none opacity-50' : ''}`}
                            onDragOver={(event) => event.preventDefault()}
                            onDrop={handleFileDrop}
                            onClick={() => !file && fileInputRef.current?.click()}
                        >
                            {file ? (
                                <>
                                    <FileText className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
                                    <div className="font-mono text-white text-sm truncate">{file.name}</div>
                                    <div className="text-[10px] text-foreground/30 font-mono mt-1">{file.size} .{file.ext}</div>
                                    <button
                                        onClick={(event) => {
                                            event.stopPropagation()
                                            clearAll()
                                        }}
                                        className="mt-3 px-3 py-1 text-[10px] font-mono text-foreground/40 border border-white/[0.06] rounded hover:text-red-400 hover:border-red-500/20 transition-all"
                                    >
                                        Remove
                                    </button>
                                </>
                            ) : (
                                <>
                                    <Upload className="w-10 h-10 text-foreground/10 mx-auto mb-3" />
                                    <div className="text-foreground/40 mb-1 text-sm">Drop one Office document</div>
                                    <div className="text-[10px] text-foreground/20 font-mono mb-4">OR CLICK TO UPLOAD</div>
                                    <div className="text-[9px] text-foreground/20 font-mono border border-white/[0.04] px-2 py-1 rounded inline-block">
                                        SUPPORTED: {ALLOWED_EXTENSIONS.map((ext) => ext.toUpperCase()).join(', ')}
                                    </div>
                                </>
                            )}
                        </motion.div>
                    </div>

                    {error && (
                        <div className="px-3 py-2 rounded border border-red-500/20 bg-red-500/10 text-[10px] font-mono text-red-300 flex items-start gap-2">
                            <XCircle size={12} className="mt-0.5 shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}

                    <button
                        disabled={!file || analyzing}
                        onClick={runMacroAnalysis}
                        className={`w-full py-3 rounded-lg font-mono text-xs font-bold tracking-wider transition-all ${!file || analyzing
                            ? 'bg-white/5 border border-white/[0.06] text-foreground/20 cursor-not-allowed'
                            : 'bg-gradient-to-r from-amber-500/20 to-emerald-500/20 border border-amber-500/30 text-amber-300 hover:border-amber-400/50'
                            }`}
                    >
                        {analyzing ? (
                            <span className="flex items-center justify-center gap-2">
                                <Loader2 className="animate-spin" size={14} /> ANALYZING...
                            </span>
                        ) : (
                            'SUBMIT DOCUMENT'
                        )}
                    </button>

                    {(analyzing || logs.length > 0) && (
                        <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                            <div className="flex items-center gap-2 px-4 py-2 border-b border-white/[0.04] bg-white/[0.02]">
                                <Terminal size={12} className="text-foreground/30" />
                                <span className="text-[10px] font-mono text-foreground/30">MACRO ANALYSIS LOG</span>
                            </div>
                            <div className="p-3 h-[220px] overflow-y-auto custom-scrollbar bg-black/20">
                                <div className="space-y-0.5">
                                    {logs.map((entry, index) => (
                                        <TerminalLine key={`${entry.text}-${index}`} text={entry.text} color={entry.color} />
                                    ))}
                                    {analyzing && (
                                        <motion.div
                                            animate={{ opacity: [0, 1, 0] }}
                                            transition={{ duration: 0.8, repeat: Infinity }}
                                            className="w-2 h-3 bg-emerald-400 mt-1 inline-block"
                                        />
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {(analyzing || result) && (
                    <div className="lg:col-span-8 space-y-4">
                        {!result ? (
                            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg min-h-[420px] flex flex-col items-center justify-center text-foreground/20 animate-pulse">
                                <Activity size={42} className="mb-3" />
                                <p className="font-mono text-xs">Running olevba extraction and indicator scoring...</p>
                            </div>
                        ) : (
                            <>
                                <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                    <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.04] bg-white/[0.02]">
                                        <div className="flex items-center gap-3">
                                            <div className="w-8 h-8 rounded bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
                                                <Shield size={16} className="text-amber-300" />
                                            </div>
                                            <div>
                                                <div className="text-xs font-mono font-bold text-white">Macro Risk Overview</div>
                                                <div className="text-[10px] text-foreground/30 font-mono">{result.filename} . {result.file_type}</div>
                                            </div>
                                        </div>
                                        <div className={`px-3 py-1.5 rounded text-[10px] font-mono font-bold tracking-wider ${riskStyle.badge}`}>
                                            {riskStyle.label}
                                        </div>
                                    </div>
                                    <div className="px-5 py-4">
                                        <p className="text-sm text-foreground/60 mb-4">{riskStyle.text}</p>
                                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                            <div className="bg-black/20 border border-white/[0.04] rounded-lg p-3 text-center">
                                                <div className="text-lg font-bold font-mono text-amber-300">{result.macro_count || 0}</div>
                                                <div className="text-[9px] font-mono text-foreground/25 uppercase tracking-wider mt-0.5">Macros</div>
                                            </div>
                                            <div className="bg-black/20 border border-white/[0.04] rounded-lg p-3 text-center">
                                                <div className="text-lg font-bold font-mono text-cyan-300">{iocItems.length}</div>
                                                <div className="text-[9px] font-mono text-foreground/25 uppercase tracking-wider mt-0.5">IOCs</div>
                                            </div>
                                            <div className="bg-black/20 border border-white/[0.04] rounded-lg p-3 text-center">
                                                <div className="text-lg font-bold font-mono text-blue-300">{suspiciousHits}</div>
                                                <div className="text-[9px] font-mono text-foreground/25 uppercase tracking-wider mt-0.5">Indicator Hits</div>
                                            </div>
                                            <div className="bg-black/20 border border-white/[0.04] rounded-lg p-3 text-center">
                                                <div className="text-lg font-bold font-mono text-red-300">{vtMalicious}</div>
                                                <div className="text-[9px] font-mono text-foreground/25 uppercase tracking-wider mt-0.5">VT Alerts</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                    <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                                        <AlertTriangle size={12} className="text-amber-300" />
                                        <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">Indicators</span>
                                    </div>
                                    <div className="p-4">
                                        {indicatorEntries.length === 0 ? (
                                            <div className="text-[11px] font-mono text-foreground/35">No macro indicators were extracted.</div>
                                        ) : (
                                            <div className="space-y-3">
                                                {indicatorEntries.map(([category, items]) => (
                                                    <div key={category} className="rounded border border-white/[0.05] bg-black/20 p-3">
                                                        <div className="text-[10px] uppercase tracking-wider font-mono text-amber-300 mb-2">{category}</div>
                                                        <div className="space-y-1.5">
                                                            {items.slice(0, 8).map((item, idx) => (
                                                                <div key={`${category}-${idx}`} className="text-[11px] text-foreground/65 leading-relaxed">
                                                                    <span className="text-white/90">{item.keyword}</span>
                                                                    <span className="text-foreground/35"> . {item.description}</span>
                                                                </div>
                                                            ))}
                                                            {items.length > 8 && (
                                                                <div className="text-[10px] font-mono text-foreground/35">+ {items.length - 8} more indicator(s)</div>
                                                            )}
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                </div>

                                <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                    <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                                        <FileCode size={12} className="text-cyan-300" />
                                        <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">Extracted Macro Source</span>
                                    </div>
                                    <div className="p-4 space-y-3">
                                        {macroItems.length === 0 ? (
                                            <div className="text-[11px] font-mono text-foreground/35">No VBA macro body extracted for this file.</div>
                                        ) : (
                                            macroItems.slice(0, 3).map((macro, index) => {
                                                const preview = String(macro.code || '')
                                                const shortened = preview.length > 900 ? `${preview.slice(0, 900)}\n... [truncated]` : preview
                                                return (
                                                    <div key={`${macro.module || 'module'}-${index}`} className="rounded border border-white/[0.05] bg-black/20 overflow-hidden">
                                                        <div className="px-3 py-2 border-b border-white/[0.04] bg-white/[0.02] text-[10px] font-mono text-foreground/35 flex items-center justify-between gap-3">
                                                            <span>{macro.module || 'Unnamed module'}</span>
                                                            <span>{macro.stream || 'stream unknown'}</span>
                                                        </div>
                                                        <pre className="p-3 text-[10px] font-mono text-foreground/60 overflow-x-auto leading-relaxed">{shortened || '# empty macro body'}</pre>
                                                    </div>
                                                )
                                            })
                                        )}
                                        {macroItems.length > 3 && (
                                            <div className="text-[10px] font-mono text-foreground/35">+ {macroItems.length - 3} more macro module(s) hidden</div>
                                        )}
                                    </div>
                                </div>

                                <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                    <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                                        <Database size={12} className="text-blue-300" />
                                        <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">IOC and VirusTotal Context</span>
                                    </div>
                                    <div className="p-4 space-y-4">
                                        <div>
                                            <div className="text-[10px] uppercase tracking-wider font-mono text-foreground/35 mb-2">Extracted IOCs</div>
                                            {iocItems.length === 0 ? (
                                                <div className="text-[11px] font-mono text-foreground/35">No IOC values extracted.</div>
                                            ) : (
                                                <div className="space-y-1.5">
                                                    {iocItems.slice(0, 12).map((ioc, index) => (
                                                        <div key={`${ioc.value}-${index}`} className="text-[11px] text-foreground/65">
                                                            <span className="text-cyan-300">{ioc.value}</span>
                                                            <span className="text-foreground/35"> . {ioc.context}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>

                                        <div className="border-t border-white/[0.05] pt-3">
                                            <div className="text-[10px] uppercase tracking-wider font-mono text-foreground/35 mb-2">VirusTotal</div>
                                            {result.vt ? (
                                                result.vt.success ? (
                                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                                                        <div className="rounded border border-red-500/20 bg-red-500/10 p-2 text-center">
                                                            <div className="text-sm font-mono text-red-300">{vtStats.malicious || 0}</div>
                                                            <div className="text-[9px] text-red-200/70">malicious</div>
                                                        </div>
                                                        <div className="rounded border border-amber-500/20 bg-amber-500/10 p-2 text-center">
                                                            <div className="text-sm font-mono text-amber-300">{vtStats.suspicious || 0}</div>
                                                            <div className="text-[9px] text-amber-200/70">suspicious</div>
                                                        </div>
                                                        <div className="rounded border border-emerald-500/20 bg-emerald-500/10 p-2 text-center">
                                                            <div className="text-sm font-mono text-emerald-300">{vtStats.harmless || 0}</div>
                                                            <div className="text-[9px] text-emerald-200/70">harmless</div>
                                                        </div>
                                                        <div className="rounded border border-sky-500/20 bg-sky-500/10 p-2 text-center">
                                                            <div className="text-sm font-mono text-sky-300">{vtStats.undetected || 0}</div>
                                                            <div className="text-[9px] text-sky-200/70">undetected</div>
                                                        </div>
                                                    </div>
                                                ) : (
                                                    <div className="text-[11px] font-mono text-amber-300/90 flex items-center gap-2">
                                                        <AlertTriangle size={12} />
                                                        {result.vt.error || 'VirusTotal enrichment unavailable.'}
                                                    </div>
                                                )
                                            ) : (
                                                <div className="text-[11px] font-mono text-foreground/35">VirusTotal enrichment not configured for this environment.</div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </>
                        )}
                    </div>
                )}
            </div>
        </div>
    )
}
