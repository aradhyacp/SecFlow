import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import { Upload, FileCode, ShieldAlert, Activity, CheckCircle2, XCircle, FileText, Crosshair } from 'lucide-react'
import { API_ENDPOINTS } from '../../config/api'

const ALLOWED_EXTENSIONS = ['doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'xlsb', 'ppt', 'pptx', 'pptm', 'rtf']

const TerminalLine = ({ text, color = 'text-foreground/70' }) => (
    <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.3 }} className={`font-mono text-[10px] ${color}`}>
        <span className="text-foreground/20 mr-2">$</span>{text}
    </motion.div>
)

const getRiskTheme = (riskLevel) => {
    const level = String(riskLevel || 'clean').toLowerCase()

    if (level === 'malicious') {
        return {
            badge: 'bg-red-500/10 text-red-400 border-red-500/20',
            card: 'bg-red-500/5 border-red-500/15',
        }
    }

    if (level === 'suspicious') {
        return {
            badge: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
            card: 'bg-amber-500/5 border-amber-500/15',
        }
    }

    if (level === 'macro_present') {
        return {
            badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
            card: 'bg-cyan-500/5 border-cyan-500/15',
        }
    }

    return {
        badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
        card: 'bg-emerald-500/5 border-emerald-500/15',
    }
}

export default function MacroAnalysisPage() {
    const [file, setFile] = useState(null)
    const [analyzing, setAnalyzing] = useState(false)
    const [analysis, setAnalysis] = useState(null)
    const [error, setError] = useState(null)
    const [logs, setLogs] = useState([])
    const [healthStatus, setHealthStatus] = useState('unknown')

    const fileInputRef = useRef(null)

    const addLog = (text, color = 'text-foreground/70') => {
        setLogs((prev) => [...prev, { text, color }])
    }

    const validateFile = (fileName) => {
        const extension = fileName.split('.').pop().toLowerCase()
        if (!ALLOWED_EXTENSIONS.includes(extension)) {
            setError(`Invalid file type. Allowed: ${ALLOWED_EXTENSIONS.join(', ').toUpperCase()}`)
            return false
        }

        setError(null)
        return true
    }

    const clearAll = () => {
        setFile(null)
        setAnalysis(null)
        setError(null)
        setLogs([])
    }

    useEffect(() => {
        fetch(API_ENDPOINTS.macro.health)
            .then((response) => response.json())
            .then((data) => setHealthStatus(data?.status || 'unknown'))
            .catch(() => setHealthStatus('unhealthy'))
    }, [])

    const handleFileSelect = (event) => {
        if (event.target.files && event.target.files[0]) {
            const selectedFile = event.target.files[0]
            if (validateFile(selectedFile.name)) {
                setFile({
                    name: selectedFile.name,
                    size: (selectedFile.size / (1024 * 1024)).toFixed(2) + ' MB',
                    rawFile: selectedFile,
                })
                setAnalysis(null)
            }
        }
    }

    const handleFileDrop = (event) => {
        event.preventDefault()
        const droppedFile = event.dataTransfer.files[0]
        if (droppedFile && validateFile(droppedFile.name)) {
            setFile({
                name: droppedFile.name,
                size: (droppedFile.size / (1024 * 1024)).toFixed(2) + ' MB',
                rawFile: droppedFile,
            })
            setAnalysis(null)
        }
    }

    const handleScan = async () => {
        if (!file?.rawFile) return

        setAnalyzing(true)
        setError(null)
        setAnalysis(null)
        setLogs([])

        addLog('[+] Initializing macro analysis pipeline...')
        addLog(`[+] Uploading ${file.name} to macro-analyzer service...`)

        try {
            const formData = new FormData()
            formData.append('file', file.rawFile)

            const response = await fetch(API_ENDPOINTS.macro.analyze, {
                method: 'POST',
                body: formData,
            })

            const payload = await response.json().catch(() => null)
            if (!response.ok) {
                throw new Error(payload?.error || `Macro API error (${response.status})`)
            }

            if (!payload?.success) {
                throw new Error(payload?.error || 'Macro analysis failed')
            }

            addLog('[+] olevba analysis complete', 'text-emerald-400')
            if (payload.vt?.success) {
                addLog('[+] VirusTotal enrichment complete', 'text-emerald-400')
            }

            setAnalysis(payload)
        } catch (scanError) {
            addLog(`[!] ${scanError.message}`, 'text-red-500')
            setError(scanError.message)
        } finally {
            setAnalyzing(false)
        }
    }

    const riskTheme = getRiskTheme(analysis?.risk_level)
    const indicatorEntries = analysis?.indicators ? Object.entries(analysis.indicators) : []
    const indicatorCount = indicatorEntries.reduce((acc, [, value]) => acc + (Array.isArray(value) ? value.length : 0), 0)
    const iocCount = Array.isArray(analysis?.iocs) ? analysis.iocs.length : 0
    const macroPreview = analysis?.macros?.[0]?.code || ''

    return (
        <div className="max-w-7xl mx-auto space-y-6 pb-20">
            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-6 py-4">
                    <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-md bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                            <FileCode size={22} className="text-cyan-400" />
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-white tracking-tight">Macro Analysis</h2>
                            <p className="text-xs text-foreground/40 font-mono">Office VBA, IOC extraction, VT enrichment</p>
                        </div>
                    </div>
                    <div className={`flex items-center gap-2 px-3 py-1.5 rounded text-[10px] font-mono font-bold tracking-wider ${healthStatus === 'healthy'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : 'bg-red-500/10 text-red-400 border border-red-500/20'
                        }`}>
                        <div className={`w-1.5 h-1.5 rounded-full ${healthStatus === 'healthy' ? 'bg-emerald-400' : 'bg-red-400'} animate-pulse`} />
                        {healthStatus === 'healthy' ? 'API ONLINE' : 'API OFFLINE'}
                    </div>
                </div>
                {analyzing && (
                    <motion.div className="h-0.5 bg-gradient-to-r from-cyan-500 via-emerald-400 to-cyan-500" style={{ backgroundSize: '200% 100%' }} animate={{ backgroundPosition: ['0% 0', '200% 0'] }} transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }} />
                )}
            </div>

            <div className={analyzing || analysis ? 'grid grid-cols-1 lg:grid-cols-12 gap-6' : 'max-w-xl mx-auto mt-12'}>
                <div className={analyzing || analysis ? 'lg:col-span-4 space-y-4' : 'space-y-4'}>
                    <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileSelect} />

                    <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                            <Upload size={12} className="text-cyan-400" />
                            <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">Office Evidence</span>
                        </div>
                        <motion.div
                            layout
                            className={`p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-all ${file ? 'bg-emerald-500/[0.03]' : 'hover:bg-white/[0.01]'} ${analyzing ? 'pointer-events-none opacity-50' : ''}`}
                            onDragOver={(event) => event.preventDefault()}
                            onDrop={handleFileDrop}
                            onClick={() => !file && fileInputRef.current?.click()}
                        >
                            {file ? (
                                <>
                                    <FileText className="w-10 h-10 text-cyan-400 mb-3" />
                                    <div className="font-mono text-white text-sm mb-0.5">{file.name}</div>
                                    <div className="text-[10px] text-foreground/30 font-mono">{file.size}</div>
                                    <button onClick={(event) => { event.stopPropagation(); clearAll() }} className="mt-3 px-3 py-1 text-[10px] font-mono text-foreground/40 border border-white/[0.06] rounded hover:text-red-400 hover:border-red-500/20 transition-all">
                                        Remove
                                    </button>
                                </>
                            ) : (
                                <>
                                    <Upload className="w-10 h-10 text-foreground/10 mb-3" />
                                    <div className="text-foreground/40 mb-1 text-sm">Drop Office file to analyze</div>
                                    <div className="text-[10px] text-foreground/20 font-mono mb-4">OR CLICK TO UPLOAD</div>
                                    <div className="text-[9px] text-foreground/20 font-mono border border-white/[0.04] px-2 py-1 rounded">
                                        SUPPORTED: {ALLOWED_EXTENSIONS.map((ext) => ext.toUpperCase()).join(', ')}
                                    </div>
                                </>
                            )}
                        </motion.div>
                    </div>

                    {error && !analyzing && (
                        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="p-3 rounded-lg border border-red-500/20 bg-red-500/10 text-red-400 text-[10px] flex items-start gap-2 font-mono">
                            <ShieldAlert size={12} className="mt-0.5 flex-shrink-0" /> {error}
                        </motion.div>
                    )}

                    <button
                        disabled={!file || analyzing}
                        onClick={handleScan}
                        className={`w-full py-3 rounded-lg font-mono text-xs font-bold tracking-wider transition-all ${!file || analyzing
                            ? 'bg-white/5 border border-white/[0.06] text-foreground/20 cursor-not-allowed'
                            : 'bg-gradient-to-r from-cyan-500/20 to-emerald-500/20 border border-cyan-500/30 text-cyan-400 hover:border-cyan-400/50'
                            }`}
                    >
                        {analyzing ? <span className="flex items-center justify-center gap-2"><Activity className="animate-spin" size={14} /> ANALYZING...</span> : 'ANALYZE DOCUMENT'}
                    </button>

                    {(analyzing || analysis || logs.length > 0) && (
                        <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                            <div className="flex items-center gap-2 px-4 py-2 border-b border-white/[0.04] bg-white/[0.02]">
                                <div className="flex gap-1.5">
                                    <div className="w-2 h-2 rounded-full bg-red-500/60" />
                                    <div className="w-2 h-2 rounded-full bg-amber-500/60" />
                                    <div className="w-2 h-2 rounded-full bg-emerald-500/60" />
                                </div>
                                <span className="text-[10px] font-mono text-foreground/20 ml-2">MACRO ANALYSIS LOG</span>
                            </div>
                            <div className="p-3 h-[220px] overflow-y-auto custom-scrollbar bg-black/20">
                                <div className="space-y-0.5">
                                    {logs.map((log, index) => <TerminalLine key={`${log.text}-${index}`} text={log.text} color={log.color} />)}
                                    {analyzing && <motion.div animate={{ opacity: [0, 1, 0] }} transition={{ duration: 0.8, repeat: Infinity }} className="w-2 h-3 bg-cyan-400 mt-1 inline-block" />}
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {(analyzing || analysis) && (
                    <div className="lg:col-span-8 space-y-4">
                        {!analysis ? (
                            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg flex flex-col items-center justify-center text-foreground/15 animate-pulse min-h-[500px]">
                                <FileCode size={48} className="mb-4 opacity-30" />
                                <p className="font-mono text-xs">Scanning VBA streams and indicators...</p>
                                <p className="text-[10px] mt-1 font-mono">olevba + optional VirusTotal enrichment</p>
                            </div>
                        ) : (
                            <>
                                <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                    <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.04] bg-white/[0.02]">
                                        <div>
                                            <h3 className="text-sm font-bold text-white">Document Verdict</h3>
                                            <p className="text-[10px] text-foreground/25 font-mono">{analysis.filename}</p>
                                        </div>
                                        <span className={`px-3 py-1.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider border ${riskTheme.badge}`}>
                                            {String(analysis.risk_level || 'clean').replace('_', ' ')}
                                        </span>
                                    </div>

                                    <div className="p-4 grid grid-cols-2 md:grid-cols-4 gap-3">
                                        <div className="text-center p-3 bg-black/20 border border-white/[0.04] rounded">
                                            <div className="text-xl font-bold text-white font-mono">{analysis.macro_count || 0}</div>
                                            <div className="text-[9px] text-foreground/30 uppercase font-mono">Macros</div>
                                        </div>
                                        <div className="text-center p-3 bg-black/20 border border-white/[0.04] rounded">
                                            <div className="text-xl font-bold text-cyan-400 font-mono">{indicatorCount}</div>
                                            <div className="text-[9px] text-foreground/30 uppercase font-mono">Indicators</div>
                                        </div>
                                        <div className="text-center p-3 bg-black/20 border border-white/[0.04] rounded">
                                            <div className="text-xl font-bold text-amber-400 font-mono">{iocCount}</div>
                                            <div className="text-[9px] text-foreground/30 uppercase font-mono">IOCs</div>
                                        </div>
                                        <div className={`text-center p-3 border rounded ${riskTheme.card}`}>
                                            <div className="text-xl font-bold text-white font-mono">{analysis.has_macros ? 'YES' : 'NO'}</div>
                                            <div className="text-[9px] text-foreground/30 uppercase font-mono">Macros Present</div>
                                        </div>
                                    </div>
                                </div>

                                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                                    <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                        <div className="px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02] text-[10px] text-foreground/40 font-mono uppercase tracking-wider">Behavior Flags</div>
                                        <div className="p-4 space-y-2">
                                            {Object.entries(analysis.flags || {}).map(([flag, value]) => (
                                                <div key={flag} className="flex items-center justify-between px-3 py-2 rounded bg-black/20 border border-white/[0.04]">
                                                    <span className="text-[10px] font-mono text-foreground/35 uppercase">{flag.replace('_', ' ')}</span>
                                                    <span className={`inline-flex items-center gap-1 text-[10px] font-mono ${value ? 'text-red-400' : 'text-emerald-400'}`}>
                                                        {value ? <XCircle size={11} /> : <CheckCircle2 size={11} />}
                                                        {value ? 'FLAGGED' : 'CLEAR'}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                        <div className="px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02] text-[10px] text-foreground/40 font-mono uppercase tracking-wider">VirusTotal</div>
                                        <div className="p-4">
                                            {analysis.vt?.success ? (
                                                <div className="space-y-2">
                                                    <div className="grid grid-cols-3 gap-2">
                                                        <div className="text-center p-2 rounded bg-red-500/10 border border-red-500/20">
                                                            <div className="text-sm font-bold text-red-400 font-mono">{analysis.vt.stats?.malicious || 0}</div>
                                                            <div className="text-[9px] text-foreground/30 font-mono">Malicious</div>
                                                        </div>
                                                        <div className="text-center p-2 rounded bg-amber-500/10 border border-amber-500/20">
                                                            <div className="text-sm font-bold text-amber-400 font-mono">{analysis.vt.stats?.suspicious || 0}</div>
                                                            <div className="text-[9px] text-foreground/30 font-mono">Suspicious</div>
                                                        </div>
                                                        <div className="text-center p-2 rounded bg-emerald-500/10 border border-emerald-500/20">
                                                            <div className="text-sm font-bold text-emerald-400 font-mono">{analysis.vt.stats?.harmless || 0}</div>
                                                            <div className="text-[9px] text-foreground/30 font-mono">Harmless</div>
                                                        </div>
                                                    </div>
                                                    <div className="text-[10px] text-foreground/35 font-mono break-all pt-2 border-t border-white/[0.04]">
                                                        SHA256: {analysis.vt.sha256}
                                                    </div>
                                                </div>
                                            ) : (
                                                <div className="text-[10px] text-foreground/35 font-mono">
                                                    {analysis.vt?.error || 'VirusTotal enrichment skipped (API key not configured).'}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>

                                {indicatorEntries.length > 0 && (
                                    <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                        <div className="px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02] text-[10px] text-foreground/40 font-mono uppercase tracking-wider">Indicator Categories</div>
                                        <div className="p-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                                            {indicatorEntries.map(([category, values]) => (
                                                <div key={category} className="p-3 rounded bg-black/20 border border-white/[0.04]">
                                                    <div className="text-xs font-mono text-cyan-400 mb-1">{category}</div>
                                                    <div className="text-[10px] text-foreground/30 font-mono">{Array.isArray(values) ? values.length : 0} entries</div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {iocCount > 0 && (
                                    <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                        <div className="px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02] text-[10px] text-foreground/40 font-mono uppercase tracking-wider">Extracted IOCs</div>
                                        <div className="p-4 flex flex-wrap gap-2">
                                            {analysis.iocs.map((ioc, index) => (
                                                <span key={`${ioc.value}-${index}`} className="px-2.5 py-1 rounded bg-amber-500/10 border border-amber-500/20 text-amber-300 text-[10px] font-mono break-all">
                                                    {ioc.value}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                    <div className="px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02] text-[10px] text-foreground/40 font-mono uppercase tracking-wider">Macro Source Preview</div>
                                    <div className="p-4 bg-black/20">
                                        <pre className="text-[10px] text-gray-300 font-mono whitespace-pre-wrap max-h-[320px] overflow-y-auto custom-scrollbar">{macroPreview || 'No macro source extracted.'}</pre>
                                    </div>
                                </div>
                            </>
                        )}
                    </div>
                )}
            </div>

            {!analyzing && !analysis && (
                <div className="h-[40vh] flex flex-col items-center justify-center text-foreground/15">
                    <Crosshair size={52} strokeWidth={0.8} className="mb-4" />
                    <p className="font-mono tracking-wider text-xs">UPLOAD OFFICE EVIDENCE TO START MACRO ANALYSIS</p>
                </div>
            )}
        </div>
    )
}
