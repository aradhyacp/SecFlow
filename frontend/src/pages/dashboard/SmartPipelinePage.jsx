import { useState, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Upload, FileCode, Workflow, Layers, GitBranch, FileOutput,
    Activity, Terminal, CheckCircle2, XCircle, Clock, ArrowRight,
    Globe, Bug, Eye, Radar, Loader2, Trash2, FileText,
    Shield, AlertTriangle, Hash, ChevronRight, Crosshair, Server
} from 'lucide-react'
import { Button } from '../../components/ui/Button'
import { API_ENDPOINTS, resolveReportUrl } from '../../config/api'

const TerminalLine = ({ text, delay = 0, color = 'text-foreground/70' }) => (
    <motion.div
        initial={{ opacity: 0, x: -10 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay, duration: 0.3 }}
        className={`font-mono text-xs ${color}`}
    >
        <span className="text-foreground/30 mr-2">$</span>
        {text}
    </motion.div>
)

// Pipeline step status badge
const StatusBadge = ({ status }) => {
    const config = {
        pending: { icon: Clock, color: 'text-foreground/30', bg: 'bg-foreground/5 border border-foreground/10', label: 'QUEUED' },
        running: { icon: Loader2, color: 'text-amber-400', bg: 'bg-amber-400/10 border border-amber-400/20', label: 'ACTIVE', spin: true },
        complete: { icon: CheckCircle2, color: 'text-emerald-400', bg: 'bg-emerald-400/10 border border-emerald-400/20', label: 'DONE' },
        error: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-400/10 border border-red-400/20', label: 'FAIL' },
        skipped: { icon: Clock, color: 'text-foreground/20', bg: 'bg-foreground/5 border border-foreground/10', label: 'SKIP' },
    }
    const { icon: Icon, color, bg, label, spin } = config[status] || config.pending
    return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-mono font-bold tracking-wider ${color} ${bg}`}>
            <Icon size={10} className={spin ? 'animate-spin' : ''} />
            {label}
        </span>
    )
}

const ANALYZERS = [
    { key: 'web', label: 'Web Analysis', icon: Globe, desc: 'DNS, SSL, headers, tech stack', accepts: ['url'] },
    { key: 'malware', label: 'Malware Analysis', icon: Bug, desc: 'Static & dynamic binary inspection', accepts: ['exe', 'dll', 'so', 'elf', 'bin', 'o', 'out'] },
    { key: 'macro', label: 'Macro Analysis', icon: FileCode, desc: 'Office macro extraction and IOC triage', accepts: ['doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'xlsb', 'ppt', 'pptx', 'pptm', 'rtf'] },
    { key: 'steg', label: 'Steg Analysis', icon: Eye, desc: 'Hidden data detection in media', accepts: ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'wav', 'mp3'] },
    { key: 'recon', label: 'Recon Analysis', icon: Radar, desc: 'OSINT & digital footprint', accepts: ['ip', 'domain', 'email', 'phone'] },
]

const ORCHESTRATOR_MAX_PASSES = 3

const buildPipelineSteps = (analyzerKeys = [], analyzerStatus = 'pending') => {
    const analyzerSteps = analyzerKeys
        .map((key) => ANALYZERS.find((analyzer) => analyzer.key === key))
        .filter(Boolean)
        .map((analyzer) => ({ ...analyzer, status: analyzerStatus }))

    return [
        { key: 'input', label: 'Input Processing', icon: Layers, desc: 'Parsing & classifying inputs', status: 'pending' },
        { key: 'routing', label: 'Smart Routing', icon: GitBranch, desc: 'Selecting appropriate analyzers', status: 'pending' },
        ...analyzerSteps,
        { key: 'report', label: 'Unified Report', icon: FileOutput, desc: 'Consolidating all findings', status: 'pending' },
    ]
}

const normalizeAnalyzerKey = (value) => {
    const key = String(value || '').trim().toLowerCase()
    if (!key) return null

    if (key === 'url') return 'web'
    if (key === 'steganography') return 'steg'
    if (key === 'reconnaissance') return 'recon'

    return ANALYZERS.some((analyzer) => analyzer.key === key) ? key : null
}

export default function SmartPipelinePage() {
    const [files, setFiles] = useState([])
    const [textInput, setTextInput] = useState('')
    const [running, setRunning] = useState(false)
    const [logs, setLogs] = useState([])
    const [pipelineSteps, setPipelineSteps] = useState([])
    const [results, setResults] = useState(null)
    const [inputModeNotice, setInputModeNotice] = useState('')
    const fileInputRef = useRef(null)

    const addLog = (text, color = 'text-foreground/70') => {
        setLogs(prev => [...prev, { text, color }])
    }

    const mapToFileEntry = (file) => ({
        name: file.name,
        size: (file.size / 1024).toFixed(1) + ' KB',
        type: file.name.split('.').pop().toLowerCase(),
        rawFile: file,
    })

    const handleFileSelect = (e) => {
        if (textInput.trim()) {
            setInputModeNotice('IOC/Target mode is active. Clear it to upload file evidence.')
            e.target.value = ''
            return
        }

        if (e.target.files?.length) {
            const selectedFiles = Array.from(e.target.files)
            const firstFile = selectedFiles[0]

            setFiles([mapToFileEntry(firstFile)])
            if (selectedFiles.length > 1) {
                setInputModeNotice('Only one file is accepted. The first selected file was kept.')
            } else {
                setInputModeNotice('')
            }
        }
        e.target.value = ''
    }

    const handleFileDrop = (e) => {
        e.preventDefault()

        if (textInput.trim()) {
            setInputModeNotice('IOC/Target mode is active. Clear it to upload file evidence.')
            return
        }

        if (e.dataTransfer.files?.length) {
            const droppedFiles = Array.from(e.dataTransfer.files)
            const firstFile = droppedFiles[0]

            setFiles([mapToFileEntry(firstFile)])
            if (droppedFiles.length > 1) {
                setInputModeNotice('Only one file is accepted. The first dropped file was kept.')
            } else {
                setInputModeNotice('')
            }
        }
    }

    const handleUploadZoneClick = () => {
        if (running) return

        if (textInput.trim()) {
            setInputModeNotice('IOC/Target mode is active. Clear it to upload file evidence.')
            return
        }

        setInputModeNotice('')
        fileInputRef.current?.click()
    }

    const removeFile = (index) => {
        const nextFiles = files.filter((_, i) => i !== index)
        setFiles(nextFiles)
        if (nextFiles.length === 0) {
            setInputModeNotice('')
        }
    }

    const handleTextInputChange = (e) => {
        const nextValue = e.target.value

        if (files.length > 0) {
            setInputModeNotice('File Evidence mode is active. Clear files to use IOC/Target input.')
            return
        }

        setTextInput(nextValue)
        setInputModeNotice('')
    }

    const clearActiveInputForSwitch = () => {
        if (files.length > 0) {
            setFiles([])
        }
        if (textInput.trim()) {
            setTextInput('')
        }
        setInputModeNotice('')
    }

    const detectAnalyzers = () => {
        const detected = new Set()
        files.forEach(f => {
            ANALYZERS.forEach(a => {
                if (a.accepts.includes(f.type)) detected.add(a.key)
            })
        })
        if (textInput.trim()) {
            const val = textInput.trim().toLowerCase()
            if (val.startsWith('http://') || val.startsWith('https://') || val.includes('www.')) {
                detected.add('web')
            } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) {
                detected.add('recon')
            } else if (val.includes('@')) {
                detected.add('recon')
            } else if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(val)) {
                detected.add('web')
                detected.add('recon')
            }
        }
        if (detected.size === 0 && files.length > 0) {
            detected.add('malware')
        }
        return Array.from(detected)
    }

    const runSmartPipeline = async () => {
        setRunning(true)
        setLogs([])
        setResults(null)

        const detectedKeys = detectAnalyzers()
        const fallbackKeys = detectedKeys.length > 0 ? detectedKeys : ['malware']

        setPipelineSteps(buildPipelineSteps(fallbackKeys, 'pending'))

        addLog('[+] Smart Pipeline initialized...', 'text-emerald-400')
        addLog(`[+] Processing ${files.length === 1 ? '1 file' : `${files.length} files`} and ${textInput ? '1 text input' : '0 text inputs'}...`)

        await delay(300)
        updateStep('input', 'running')
        addLog('[*] Classifying input types...')
        await delay(450)
        files.forEach(f => addLog(`    ├─ ${f.name} → ${f.type.toUpperCase()}`, 'text-foreground/50'))
        if (textInput) addLog(`    └─ Text: "${textInput.substring(0, 40)}..."`, 'text-foreground/50')
        updateStep('input', 'complete')

        await delay(220)
        updateStep('routing', 'running')
        addLog('[*] Routing to analyzers...')
        await delay(350)
        fallbackKeys.forEach(key => {
            const a = ANALYZERS.find(x => x.key === key)
            addLog(`    ├─ ${a.label} selected`, 'text-amber-400')
        })
        updateStep('routing', 'complete')

        fallbackKeys.forEach((key) => updateStep(key, 'running'))
        updateStep('report', 'running')
        addLog(`[+] Dispatching request to orchestrator (passes=${ORCHESTRATOR_MAX_PASSES})...`, 'text-cyan-300')

        try {
            const requestUrl = `${API_ENDPOINTS.orchestrator.smartAnalyze}?passes=${ORCHESTRATOR_MAX_PASSES}`
            let response

            if (files.length > 0) {
                const formData = new FormData()
                formData.append('file', files[0].rawFile)
                response = await fetch(requestUrl, { method: 'POST', body: formData })
            } else {
                response = await fetch(requestUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: textInput.trim() }),
                })
            }

            const payload = await response.json().catch(() => null)
            if (!response.ok) {
                throw new Error(payload?.error || `Orchestrator API error (${response.status})`)
            }

            const findingsSummary = Array.isArray(payload?.findings_summary) ? payload.findings_summary : []
            const orderedAnalyzerKeys = findingsSummary
                .map((entry) => normalizeAnalyzerKey(entry?.analyzer))
                .filter(Boolean)

            const uniqueAnalyzerKeys = []
            orderedAnalyzerKeys.forEach((key) => {
                if (!uniqueAnalyzerKeys.includes(key)) uniqueAnalyzerKeys.push(key)
            })

            const analyzerKeysForUi = uniqueAnalyzerKeys.length > 0 ? uniqueAnalyzerKeys : fallbackKeys
            const completedPipeline = buildPipelineSteps(analyzerKeysForUi, 'complete')
            setPipelineSteps(completedPipeline)

            if (payload?.job_id) {
                addLog(`[+] Job ID: ${payload.job_id}`, 'text-cyan-300')
            }

            findingsSummary.forEach((entry, index) => {
                const analyzerKey = normalizeAnalyzerKey(entry?.analyzer)
                const analyzerName = ANALYZERS.find((item) => item.key === analyzerKey)?.label || entry?.analyzer || 'Analyzer'
                const findingCount = Array.isArray(entry?.findings) ? entry.findings.length : 0
                const risk = typeof entry?.risk_score === 'number' ? entry.risk_score.toFixed(2) : '0.00'
                addLog(`[✓] Pass ${entry?.pass || index + 1}: ${analyzerName} completed (${findingCount} findings, risk ${risk})`, 'text-emerald-400')
            })

            const orchestratorRisk = Number(payload?.overall_risk_score || 0)
            const boundedRisk = Number.isFinite(orchestratorRisk) ? Math.min(10, Math.max(0, orchestratorRisk)) : 0
            const totalFindings = findingsSummary.reduce((acc, entry) => {
                const count = Array.isArray(entry?.findings) ? entry.findings.length : 0
                return acc + count
            }, 0)

            setResults({
                analyzersRun: analyzerKeysForUi.length,
                filesProcessed: files.length > 0 || textInput.trim() ? 1 : 0,
                findings: totalFindings,
                riskScore: Math.round(boundedRisk * 10),
                orchestratorRisk: boundedRisk,
                timestamp: new Date().toLocaleString(),
                reportUrls: {
                    json: resolveReportUrl(payload?.report_urls?.json),
                    html: resolveReportUrl(payload?.report_urls?.html),
                },
            })

            addLog('[✓] Smart Pipeline run complete! All analyzers finished.', 'text-emerald-400')
        } catch (error) {
            setPipelineSteps((prev) => prev.map((step) => {
                if (step.key === 'report') return { ...step, status: 'error' }
                if (step.status === 'running') return { ...step, status: 'error' }
                return step
            }))
            addLog(`[!] Pipeline failed: ${error.message}`, 'text-red-500')
        } finally {
            setRunning(false)
        }
    }

    const updateStep = (key, status) => {
        setPipelineSteps(prev => prev.map(s => s.key === key ? { ...s, status } : s))
    }

    const delay = ms => new Promise(r => setTimeout(r, ms))

    const clearAll = () => {
        setFiles([])
        setTextInput('')
        setLogs([])
        setPipelineSteps([])
        setResults(null)
        setInputModeNotice('')
    }

    const hasFiles = files.length > 0
    const selectedFile = files[0]
    const hasTextInput = textInput.trim().length > 0
    const hasInput = hasFiles || hasTextInput
    const fileInputLocked = hasTextInput || running
    const textInputLocked = hasFiles || running
    const getThreatColor = (score) => score > 70 ? 'text-red-400' : score > 40 ? 'text-amber-400' : 'text-emerald-400'
    const getThreatLevel = (score) => score > 70 ? 'CRITICAL' : score > 40 ? 'MEDIUM' : 'LOW'
    const getThreatBg = (score) => score > 70 ? 'bg-red-500/10 border-red-500/20' : score > 40 ? 'bg-amber-500/10 border-amber-500/20' : 'bg-emerald-500/10 border-emerald-500/20'

    return (
        <div className="max-w-7xl mx-auto space-y-6 pb-20">

            {/* ─── SOC Header Bar ─── */}
            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-6 py-4">
                    <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-md bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
                            <Shield size={22} className="text-amber-400" />
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-white tracking-tight">
                                SecFlow Smart Pipeline
                            </h2>
                            <p className="text-xs text-foreground/40 font-mono">SOC Evidence Submission & Automated Analysis Pipeline</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-3">
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                            <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                            <span className="text-[10px] font-mono text-emerald-400 font-bold tracking-wider">SYSTEMS NOMINAL</span>
                        </div>
                    </div>
                </div>
                {/* Thin progress bar */}
                {running && (
                    <motion.div
                        className="h-0.5 bg-gradient-to-r from-amber-500 via-emerald-400 to-amber-500"
                        style={{ backgroundSize: '200% 100%' }}
                        animate={{ backgroundPosition: ['0% 0', '200% 0'] }}
                        transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
                    />
                )}
            </div>

            {/* ─── Main Grid ─── */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

                {/* ═══ LEFT: Evidence Submission Panel ═══ */}
                <div className={`${pipelineSteps.length > 0 ? 'lg:col-span-5' : 'lg:col-span-6 lg:col-start-4'} space-y-4`}>

                    {/* Section label */}
                    <div className="flex items-center gap-2 mb-1">
                        <Crosshair size={12} className="text-amber-400" />
                        <span className="text-[10px] font-mono text-foreground/30 uppercase tracking-widest font-bold">Evidence Submission</span>
                        <div className="flex-1 h-px bg-white/5" />
                    </div>

                    <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileSelect} disabled={fileInputLocked} />

                    {/* Upload Zone */}
                    <motion.div
                        layout
                        className={`border rounded-lg transition-all cursor-pointer relative overflow-hidden
                            ${hasFiles ? 'border-amber-500/30 bg-amber-500/[0.03]' : 'border-white/[0.06] bg-[#0c1120]'}
                            ${hasTextInput && !running ? 'border-white/[0.12] bg-white/[0.01] cursor-not-allowed opacity-80' : 'hover:border-white/10'}
                            ${running ? 'pointer-events-none opacity-50' : ''}`}
                        onDragOver={(e) => e.preventDefault()}
                        onDrop={handleFileDrop}
                        onClick={handleUploadZoneClick}
                    >
                        {/* Top bar */}
                        <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                            <div className="flex items-center gap-2">
                                <Upload size={12} className="text-foreground/30" />
                                <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">File Evidence</span>
                            </div>
                            {hasFiles && (
                                <span className="text-[10px] font-mono text-amber-400 bg-amber-400/10 px-2 py-0.5 rounded">
                                    1 FILE
                                </span>
                            )}
                        </div>

                        <div className="p-6">
                            {hasFiles ? (
                                <div className="w-full" onClick={(e) => e.stopPropagation()}>
                                    <div className="space-y-1.5">
                                        <div className="flex items-center justify-between px-3 py-2 rounded bg-black/30 border border-white/[0.04] group">
                                            <div className="flex items-center gap-3 min-w-0">
                                                <div className="w-7 h-7 rounded bg-white/5 flex items-center justify-center flex-shrink-0">
                                                    <FileText size={13} className="text-foreground/40" />
                                                </div>
                                                <div className="min-w-0">
                                                    <div className="text-xs font-mono text-white truncate">{selectedFile?.name}</div>
                                                    <div className="text-[10px] text-foreground/30 font-mono">{selectedFile?.size} · .{selectedFile?.type}</div>
                                                </div>
                                            </div>
                                            <button onClick={() => removeFile(0)} className="text-foreground/20 hover:text-red-400 transition-colors p-1 opacity-0 group-hover:opacity-100">
                                                <Trash2 size={12} />
                                            </button>
                                        </div>
                                    </div>
                                    <div className="flex gap-2 mt-4">
                                        <button onClick={handleUploadZoneClick} className="flex-1 py-2 rounded bg-white/5 border border-white/[0.06] text-[10px] font-mono text-foreground/50 hover:text-white hover:bg-white/10 transition-all">
                                            REPLACE FILE
                                        </button>
                                        <button onClick={clearAll} className="py-2 px-4 rounded bg-red-500/5 border border-red-500/10 text-[10px] font-mono text-red-400/60 hover:text-red-400 hover:bg-red-500/10 transition-all">
                                            CLEAR
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <div className="text-center py-4">
                                    <div className="w-12 h-12 rounded-lg bg-white/[0.03] border border-white/[0.06] flex items-center justify-center mx-auto mb-4">
                                        <Upload className="w-5 h-5 text-foreground/20" />
                                    </div>
                                    <div className="text-sm text-foreground/50 mb-1">Drop one evidence file here</div>
                                    <div className="text-[10px] text-foreground/25 font-mono mb-5">CLICK TO BROWSE · ALL FORMATS ACCEPTED</div>
                                    <div className="flex flex-wrap gap-1 justify-center">
                                        {['DOCM', 'XLSM', 'PPTM', 'DOCX', 'XLSX', 'EXE', 'DLL', 'PNG', 'JPG', 'BIN', 'LOG'].map(ext => (
                                            <span key={ext} className="text-[8px] font-mono px-1.5 py-0.5 rounded bg-white/[0.03] border border-white/[0.04] text-foreground/20">
                                                .{ext}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </motion.div>

                    {hasTextInput && !running && (
                        <div className="px-3 py-2 rounded border border-amber-500/20 bg-amber-500/5 text-[10px] font-mono text-amber-300/90">
                            IOC/Target mode is active. File upload is disabled until IOC input is cleared.
                        </div>
                    )}

                    <div className="flex items-center gap-3 px-1">
                        <div className="h-px flex-1 bg-white/[0.08]" />
                        <span className="text-[10px] font-mono uppercase tracking-[0.22em] text-amber-300/70">OR</span>
                        <div className="h-px flex-1 bg-white/[0.08]" />
                    </div>

                    {/* IOC / Target Input */}
                    <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                            <Crosshair size={12} className="text-foreground/30" />
                            <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">IOC / Target Indicator</span>
                        </div>
                        <div className="p-3">
                            <input
                                type="text"
                                placeholder={hasFiles ? 'File Evidence mode active. Clear files to enter IOC/target.' : 'Enter URL, IP address, domain, or email...'}
                                value={textInput}
                                onChange={handleTextInputChange}
                                disabled={textInputLocked}
                                className="w-full bg-black/30 border border-white/[0.06] rounded px-3 py-2.5 font-mono text-sm text-white placeholder:text-foreground/20 focus:outline-none focus:border-amber-500/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                            />
                            {hasFiles && !running && (
                                <div className="mt-2 text-[10px] font-mono text-amber-300/85">
                                    File Evidence mode is active. Clear uploaded files to use IOC/Target input.
                                </div>
                            )}
                            {textInput && (
                                <div className="mt-2 flex items-center gap-2">
                                    <Hash size={10} className="text-amber-400" />
                                    <span className="text-[10px] font-mono text-amber-400">AUTO-CLASSIFIED</span>
                                    <ChevronRight size={10} className="text-foreground/20" />
                                    <span className="text-[10px] font-mono text-foreground/50">
                                        {detectAnalyzers().map(k => ANALYZERS.find(a => a.key === k)?.label).join(' + ')}
                                    </span>
                                </div>
                            )}
                        </div>
                    </div>

                    {inputModeNotice && (
                        <div className="px-3 py-2 rounded border border-amber-500/20 bg-amber-500/5 text-[10px] font-mono text-amber-300/90">
                            <div className="flex items-center justify-between gap-3">
                                <span>{inputModeNotice}</span>
                                <button
                                    type="button"
                                    onClick={clearActiveInputForSwitch}
                                    className="px-2 py-1 rounded border border-amber-500/25 text-amber-300 hover:text-amber-200 hover:border-amber-400/40 transition-colors"
                                >
                                    CLEAR TO SWITCH
                                </button>
                            </div>
                        </div>
                    )}

                    {/* Detected Pipeline Preview */}
                    {hasInput && !running && pipelineSteps.length === 0 && (
                        <motion.div
                            initial={{ opacity: 0, y: 8 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden"
                        >
                            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                                <GitBranch size={12} className="text-foreground/30" />
                                <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">Detected Analysis Modules</span>
                            </div>
                            <div className="p-3 space-y-1">
                                {detectAnalyzers().map(key => {
                                    const a = ANALYZERS.find(x => x.key === key)
                                    return (
                                        <div key={key} className="flex items-center gap-3 px-3 py-2 rounded bg-black/20 border border-white/[0.03]">
                                            <div className="w-6 h-6 rounded bg-emerald-500/10 flex items-center justify-center">
                                                <a.icon size={13} className="text-emerald-400" />
                                            </div>
                                            <span className="font-mono text-xs text-white flex-1">{a.label}</span>
                                            <span className="text-[9px] font-mono text-foreground/25">{a.desc}</span>
                                        </div>
                                    )
                                })}
                            </div>
                        </motion.div>
                    )}

                    {/* Submit Button */}
                    <button
                        className={`w-full py-3.5 rounded-lg font-mono text-sm font-bold tracking-wider transition-all relative overflow-hidden
                            ${!hasInput || running
                                ? 'bg-white/5 border border-white/[0.06] text-foreground/20 cursor-not-allowed'
                                : 'bg-gradient-to-r from-amber-500/20 to-emerald-500/20 border border-amber-500/30 text-amber-400 hover:border-amber-400/50 hover:shadow-[0_0_30px_rgba(245,158,11,0.1)]'
                            }`}
                        disabled={!hasInput || running}
                        onClick={runSmartPipeline}
                    >
                        {running ? (
                            <span className="flex items-center justify-center gap-2">
                                <Loader2 size={16} className="animate-spin" />
                                ANALYSIS IN PROGRESS...
                            </span>
                        ) : (
                            <span className="flex items-center justify-center gap-2">
                                <Shield size={16} />
                                SUBMIT FOR ANALYSIS
                            </span>
                        )}
                    </button>

                    {/* Console Output */}
                    {(running || results) && (
                        <motion.div
                            initial={{ opacity: 0, y: 8 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="bg-[#080b14] border border-white/[0.06] rounded-lg overflow-hidden"
                        >
                            <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                                <div className="flex items-center gap-2">
                                    <Terminal size={12} className="text-foreground/30" />
                                    <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">Analysis Console</span>
                                </div>
                                <div className="flex items-center gap-1.5">
                                    <div className="w-2 h-2 rounded-full bg-red-500/60" />
                                    <div className="w-2 h-2 rounded-full bg-amber-500/60" />
                                    <div className="w-2 h-2 rounded-full bg-emerald-500/60" />
                                </div>
                            </div>
                            <div className="p-4 font-mono h-[260px] overflow-y-auto custom-scrollbar">
                                <div className="space-y-1">
                                    {logs.map((log, i) => <TerminalLine key={i} text={log.text} color={log.color} />)}
                                    {running && <motion.div animate={{ opacity: [0, 1, 0] }} transition={{ duration: 0.8, repeat: Infinity }} className="w-2 h-4 bg-amber-400 mt-1 inline-block" />}
                                </div>
                            </div>
                        </motion.div>
                    )}
                </div>

                {/* ═══ RIGHT: Pipeline & Report Panel ═══ */}
                {pipelineSteps.length > 0 && (
                    <div className="lg:col-span-7 space-y-4">

                        {/* Section label */}
                        <div className="flex items-center gap-2 mb-1">
                            <Server size={12} className="text-emerald-400" />
                            <span className="text-[10px] font-mono text-foreground/30 uppercase tracking-widest font-bold">Analysis Pipeline</span>
                            <div className="flex-1 h-px bg-white/5" />
                            {running && (
                                <span className="text-[10px] font-mono text-amber-400 animate-pulse">● PROCESSING</span>
                            )}
                        </div>

                        {/* Pipeline Steps */}
                        <motion.div
                            initial={{ opacity: 0, x: 20 }}
                            animate={{ opacity: 1, x: 0 }}
                            className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden"
                        >
                            <div className="divide-y divide-white/[0.03]">
                                {pipelineSteps.map((step, index) => (
                                    <motion.div
                                        key={step.key}
                                        initial={{ opacity: 0 }}
                                        animate={{ opacity: 1 }}
                                        transition={{ delay: index * 0.06 }}
                                        className={`flex items-center gap-4 px-5 py-3.5 transition-colors ${step.status === 'running' ? 'bg-amber-500/[0.04]' :
                                                step.status === 'complete' ? 'bg-emerald-500/[0.02]' : ''
                                            }`}
                                    >
                                        {/* Step number */}
                                        <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-mono font-bold flex-shrink-0 ${step.status === 'complete' ? 'bg-emerald-500/20 text-emerald-400' :
                                                step.status === 'running' ? 'bg-amber-500/20 text-amber-400' :
                                                    'bg-white/5 text-foreground/20'
                                            }`}>
                                            {step.status === 'complete' ? '✓' : index + 1}
                                        </div>

                                        {/* Icon */}
                                        <div className={`w-8 h-8 rounded bg-white/[0.03] border flex items-center justify-center flex-shrink-0 ${step.status === 'running' ? 'border-amber-500/20' :
                                                step.status === 'complete' ? 'border-emerald-500/20' :
                                                    'border-white/[0.04]'
                                            }`}>
                                            <step.icon size={15} className={
                                                step.status === 'running' ? 'text-amber-400' :
                                                    step.status === 'complete' ? 'text-emerald-400' :
                                                        'text-foreground/20'
                                            } />
                                        </div>

                                        {/* Label */}
                                        <div className="flex-1 min-w-0">
                                            <div className={`text-xs font-mono font-bold ${step.status === 'complete' ? 'text-white' :
                                                    step.status === 'running' ? 'text-amber-400' :
                                                        'text-foreground/30'
                                                }`}>{step.label}</div>
                                            <div className="text-[10px] text-foreground/25 font-mono">{step.desc}</div>
                                        </div>

                                        {/* Status */}
                                        <StatusBadge status={step.status} />
                                    </motion.div>
                                ))}
                            </div>
                        </motion.div>

                        {/* ─── Incident Report ─── */}
                        <AnimatePresence>
                            {results && (
                                <motion.div
                                    initial={{ opacity: 0, y: 16 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    exit={{ opacity: 0 }}
                                    className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden"
                                >
                                    {/* Report header */}
                                    <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/[0.04] bg-white/[0.02]">
                                        <div className="flex items-center gap-3">
                                            <div className={`w-8 h-8 rounded flex items-center justify-center ${getThreatBg(results.riskScore)}`}>
                                                <AlertTriangle size={16} className={getThreatColor(results.riskScore)} />
                                            </div>
                                            <div>
                                                <div className="text-xs font-mono font-bold text-white">Incident Report</div>
                                                <div className="text-[10px] text-foreground/30 font-mono">{results.timestamp}</div>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            {results.reportUrls?.html && (
                                                <a
                                                    href={results.reportUrls.html}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="px-3 py-1.5 rounded text-[10px] font-mono font-bold tracking-wider border border-cyan-400/25 text-cyan-300 bg-cyan-500/10 hover:border-cyan-300/40 transition-colors"
                                                >
                                                    OPEN HTML
                                                </a>
                                            )}
                                            {results.reportUrls?.json && (
                                                <a
                                                    href={results.reportUrls.json}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="px-3 py-1.5 rounded text-[10px] font-mono font-bold tracking-wider border border-indigo-400/25 text-indigo-300 bg-indigo-500/10 hover:border-indigo-300/40 transition-colors"
                                                >
                                                    DOWNLOAD JSON
                                                </a>
                                            )}
                                            <div className={`px-3 py-1.5 rounded text-[10px] font-mono font-bold tracking-wider border ${getThreatBg(results.riskScore)} ${getThreatColor(results.riskScore)}`}>
                                                THREAT: {getThreatLevel(results.riskScore)}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Risk Score Visual */}
                                    <div className="px-5 py-5">
                                        <div className="flex items-center gap-6 mb-6">
                                            <div className="relative">
                                                <svg width="80" height="80" viewBox="0 0 80 80">
                                                    <circle cx="40" cy="40" r="34" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
                                                    <circle
                                                        cx="40" cy="40" r="34" fill="none"
                                                        stroke={results.riskScore > 70 ? '#f87171' : results.riskScore > 40 ? '#fbbf24' : '#34d399'}
                                                        strokeWidth="6"
                                                        strokeDasharray={`${(results.riskScore / 100) * 213.6} 213.6`}
                                                        strokeLinecap="round"
                                                        transform="rotate(-90 40 40)"
                                                        className="drop-shadow-lg"
                                                    />
                                                </svg>
                                                <div className="absolute inset-0 flex items-center justify-center">
                                                    <span className={`text-xl font-bold font-mono ${getThreatColor(results.riskScore)}`}>{results.riskScore}</span>
                                                </div>
                                            </div>
                                            <div className="flex-1">
                                                <div className="text-[10px] font-mono text-foreground/30 uppercase tracking-wider mb-1">Risk Assessment</div>
                                                <div className={`text-lg font-bold font-mono ${getThreatColor(results.riskScore)}`}>
                                                    {getThreatLevel(results.riskScore)} RISK
                                                </div>
                                                <div className="text-[10px] text-foreground/30 font-mono mt-1">
                                                    Based on {results.analyzersRun} analyzer(s) scanning {results.filesProcessed} input(s)
                                                </div>
                                                <div className="text-[10px] text-foreground/30 font-mono mt-1">
                                                    Orchestrator risk score: {Number(results.orchestratorRisk || 0).toFixed(2)} / 10
                                                </div>
                                            </div>
                                        </div>

                                        {/* Stats Grid */}
                                        <div className="grid grid-cols-4 gap-3">
                                            {[
                                                { label: 'Modules', value: results.analyzersRun, color: 'text-cyan-400', icon: Server },
                                                { label: 'Evidence', value: results.filesProcessed, color: 'text-amber-400', icon: FileCode },
                                                { label: 'Findings', value: results.findings, color: 'text-white', icon: AlertTriangle },
                                                { label: 'Risk', value: results.riskScore + '/100', color: getThreatColor(results.riskScore), icon: Shield },
                                            ].map((stat, i) => (
                                                <div key={i} className="bg-black/20 border border-white/[0.04] rounded-lg p-3 text-center">
                                                    <stat.icon size={14} className={`${stat.color} mx-auto mb-2 opacity-60`} />
                                                    <div className={`text-lg font-bold font-mono ${stat.color}`}>{stat.value}</div>
                                                    <div className="text-[9px] font-mono text-foreground/25 uppercase tracking-wider mt-0.5">{stat.label}</div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>
                )}
            </div>
        </div>
    )
}
