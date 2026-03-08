import { useState, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, FileImage, ShieldAlert, ImageIcon, Terminal, Activity, Eye, Download, AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp, Lock, Loader2 } from 'lucide-react'
import { Button } from '../../components/ui/Button'
import { API_ENDPOINTS } from '../../config/api'

const TerminalLine = ({ text, delay = 0, color = 'text-foreground/70' }) => (
    <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay, duration: 0.3 }} className={`font-mono text-[10px] ${color}`}>
        <span className="text-foreground/20 mr-2">$</span>{text}
    </motion.div>
)

const ToolResultCard = ({ toolName, result }) => {
    const [isExpanded, setIsExpanded] = useState(false)
    const isOk = result.status === 'ok'
    const hasOutput = result.output || result.images || result.download
    const displayName = toolName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())

    const renderOutput = () => {
        if (result.error) return <pre className="text-red-400 text-[10px] font-mono whitespace-pre-wrap">{result.error}</pre>
        if (result.images) {
            return (
                <div className="space-y-3">
                    {Object.entries(result.images).map(([category, urls]) => (
                        <div key={category}>
                            <div className="text-[10px] text-foreground/40 mb-1.5 font-mono uppercase">{category}</div>
                            <div className="grid grid-cols-4 gap-2">
                                {urls.slice(0, 8).map((url, i) => (
                                    <a key={i} href={API_ENDPOINTS.steg.image(url)} target="_blank" rel="noopener noreferrer" className="aspect-square bg-black/30 rounded border border-white/[0.06] overflow-hidden hover:border-purple-500/30 transition-colors">
                                        <img src={API_ENDPOINTS.steg.image(url)} alt={`${category} ${i}`} className="w-full h-full object-cover" onError={(e) => { e.target.style.display = 'none' }} />
                                    </a>
                                ))}
                            </div>
                            {urls.length > 8 && <div className="text-[10px] text-foreground/20 mt-1 font-mono">+{urls.length - 8} more</div>}
                        </div>
                    ))}
                </div>
            )
        }
        if (typeof result.output === 'object' && !Array.isArray(result.output)) {
            return (
                <div className="space-y-0.5">
                    {Object.entries(result.output).map(([key, value]) => (
                        <div key={key} className="flex text-[10px] font-mono">
                            <span className="text-foreground/30 w-44 flex-shrink-0">{key}:</span>
                            <span className="text-gray-400">{String(value)}</span>
                        </div>
                    ))}
                </div>
            )
        }
        if (Array.isArray(result.output)) return <pre className="text-gray-400 text-[10px] font-mono whitespace-pre-wrap max-h-[280px] overflow-y-auto custom-scrollbar">{result.output.join('\n')}</pre>
        if (typeof result.output === 'string') return <pre className="text-gray-400 text-[10px] font-mono whitespace-pre-wrap max-h-[280px] overflow-y-auto custom-scrollbar">{result.output}</pre>
        return <span className="text-foreground/20 text-[10px] font-mono">No output data</span>
    }

    return (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
            <button onClick={() => setIsExpanded(!isExpanded)} className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-white/[0.02] transition-colors">
                <div className="flex items-center gap-3">
                    {isOk ? <CheckCircle size={12} className="text-emerald-400" /> : <XCircle size={12} className="text-red-400" />}
                    <span className="font-mono text-xs text-white">{displayName}</span>
                    <span className={`text-[9px] px-2 py-0.5 rounded font-mono font-bold ${isOk ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>{result.status.toUpperCase()}</span>
                </div>
                <div className="flex items-center gap-2">
                    {result.download && (
                        <a href={API_ENDPOINTS.steg.image(result.download)} onClick={(e) => e.stopPropagation()} className="text-[10px] text-purple-400 hover:underline flex items-center gap-1 font-mono">
                            <Download size={10} /> Download
                        </a>
                    )}
                    {isExpanded ? <ChevronUp size={14} className="text-foreground/20" /> : <ChevronDown size={14} className="text-foreground/20" />}
                </div>
            </button>
            <AnimatePresence>
                {isExpanded && hasOutput && (
                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="border-t border-white/[0.04]">
                        <div className="p-4 bg-black/20">{renderOutput()}</div>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    )
}

export default function StegAnalysisPage() {
    const [file, setFile] = useState(null)
    const [password, setPassword] = useState('')
    const [analyzing, setAnalyzing] = useState(false)
    const [status, setStatus] = useState(null)
    const [results, setResults] = useState(null)
    const [logs, setLogs] = useState([])
    const [error, setError] = useState(null)
    const [submissionHash, setSubmissionHash] = useState(null)
    const fileInputRef = useRef(null)
    const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'pdf']

    const validateFile = (fileName) => {
        const extension = fileName.split('.').pop().toLowerCase()
        if (!allowedExtensions.includes(extension)) { setError(`Invalid file type. Allowed: ${allowedExtensions.join(', ').toUpperCase()}`); return false }
        setError(null); return true
    }

    const handleFileSelect = (e) => {
        if (e.target.files && e.target.files[0]) {
            const selectedFile = e.target.files[0]
            if (validateFile(selectedFile.name)) {
                setFile({ name: selectedFile.name, size: (selectedFile.size / (1024 * 1024)).toFixed(2) + ' MB', rawFile: selectedFile })
                setResults(null); setError(null)
            }
        }
    }

    const handleFileDrop = (e) => {
        e.preventDefault()
        const droppedFile = e.dataTransfer.files[0]
        if (droppedFile && validateFile(droppedFile.name)) {
            setFile({ name: droppedFile.name, size: (droppedFile.size / (1024 * 1024)).toFixed(2) + ' MB', rawFile: droppedFile })
            setResults(null); setError(null)
        }
    }

    const addLog = (text, color = 'text-foreground/70') => setLogs(prev => [...prev, { text, color }])
    const clearFile = () => { setFile(null); setPassword(''); setResults(null); setError(null); setLogs([]); setStatus(null); setSubmissionHash(null) }

    const pollStatus = async (hash) => {
        const maxAttempts = 120; let attempts = 0
        while (attempts < maxAttempts) {
            try {
                const res = await fetch(API_ENDPOINTS.steg.status(hash))
                if (!res.ok) throw new Error(`Status check failed: ${res.statusText}`)
                const data = await res.json()
                if (data.status === 'completed') return true
                else if (data.status === 'error' || data.status === 'failed') throw new Error(data.error || 'Analysis failed')
                addLog(`[*] Analysis in progress... (${attempts + 1}s)`)
                await new Promise(resolve => setTimeout(resolve, 1000)); attempts++
            } catch (err) { throw err }
        }
        throw new Error('Analysis timed out after 2 minutes')
    }

    const handleScan = async () => {
        if (!file) return
        setAnalyzing(true); setLogs([]); setResults(null); setError(null); setStatus('uploading')
        try {
            addLog(`[+] Initializing steganography analysis...`); addLog(`[+] Uploading ${file.name}...`)
            const formData = new FormData(); formData.append('image', file.rawFile)
            if (password) formData.append('password', password)
            const uploadRes = await fetch(API_ENDPOINTS.steg.upload, { method: 'POST', body: formData })
            if (!uploadRes.ok) throw new Error(`Upload failed: ${uploadRes.statusText}`)
            const uploadData = await uploadRes.json(); const hash = uploadData.submission_hash; setSubmissionHash(hash)
            addLog(`[+] File uploaded successfully`, 'text-emerald-400'); addLog(`[*] Submission hash: ${hash.substring(0, 16)}...`)
            setStatus('polling'); addLog(`[*] Starting analysis pipeline...`); addLog(`[*] Running: binwalk, strings, exiftool, steghide, zsteg...`)
            await pollStatus(hash); addLog(`[+] Analysis complete!`, 'text-emerald-400')
            addLog(`[*] Fetching results...`)
            const resultRes = await fetch(API_ENDPOINTS.steg.result(hash))
            if (!resultRes.ok) throw new Error(`Failed to fetch results: ${resultRes.statusText}`)
            const resultData = await resultRes.json(); setResults(resultData.results); setStatus('completed'); addLog(`[+] Results loaded successfully`, 'text-emerald-400')
        } catch (err) { addLog(`[!] Error: ${err.message}`, 'text-red-500'); setError(err.message); setStatus('error') } finally { setAnalyzing(false) }
    }

    const getStats = () => {
        if (!results) return { ok: 0, error: 0, total: 0 }
        const entries = Object.entries(results)
        return { ok: entries.filter(([_, r]) => r.status === 'ok').length, error: entries.filter(([_, r]) => r.status === 'error').length, total: entries.length }
    }
    const stats = getStats()

    return (
        <div className="max-w-7xl mx-auto space-y-6 pb-20">

            {/* ─── SOC Header ─── */}
            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-6 py-4">
                    <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-md bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
                            <Eye size={22} className="text-purple-400" />
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-white tracking-tight">Steg Analyzer</h2>
                            <p className="text-xs text-foreground/40 font-mono">Steganography Detection & Analysis</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="px-3 py-1.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400 text-[10px] font-mono font-bold flex items-center gap-2 tracking-wider">
                            <ImageIcon size={12} /> HIDDEN DATA DETECTION
                        </div>
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                            <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                            <span className="text-[10px] font-mono text-emerald-400 font-bold tracking-wider">API ONLINE</span>
                        </div>
                    </div>
                </div>
                {analyzing && (
                    <motion.div className="h-0.5 bg-gradient-to-r from-purple-500 via-pink-400 to-purple-500" style={{ backgroundSize: '200% 100%' }} animate={{ backgroundPosition: ['0% 0', '200% 0'] }} transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }} />
                )}
            </div>

            {/* Dynamic Layout Container */}
            <div className={analyzing || results ? "grid grid-cols-1 lg:grid-cols-12 gap-6" : "max-w-xl mx-auto mt-12"}>

                {/* Left Column: Upload & Control */}
                <div className={analyzing || results ? "lg:col-span-4 space-y-4" : "space-y-4"}>
                    <input type="file" ref={fileInputRef} className="hidden" onChange={handleFileSelect} accept="image/*,.pdf" />

                    {/* Upload Zone */}
                    <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                            <Upload size={12} className="text-purple-400" />
                            <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">Image Evidence</span>
                        </div>
                        <motion.div
                            layout
                            className={`p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-all
                                ${file ? 'bg-emerald-500/[0.03]' : 'hover:bg-white/[0.01]'}
                                ${analyzing ? 'pointer-events-none opacity-50' : ''}`}
                            onDragOver={(e) => e.preventDefault()}
                            onDrop={handleFileDrop}
                            onClick={() => !file && fileInputRef.current?.click()}
                        >
                            {file ? (
                                <>
                                    <FileImage className="w-10 h-10 text-purple-400 mb-3" />
                                    <div className="font-mono text-white text-sm mb-0.5">{file.name}</div>
                                    <div className="text-[10px] text-foreground/30 font-mono">{file.size}</div>
                                    <button onClick={(e) => { e.stopPropagation(); clearFile(); }} className="mt-3 px-3 py-1 text-[10px] font-mono text-foreground/40 border border-white/[0.06] rounded hover:text-red-400 hover:border-red-500/20 transition-all">
                                        Remove
                                    </button>
                                </>
                            ) : (
                                <>
                                    <Upload className="w-10 h-10 text-foreground/10 mb-3" />
                                    <div className="text-foreground/40 mb-1 text-sm">Drop image to analyze</div>
                                    <div className="text-[10px] text-foreground/20 font-mono mb-4">OR CLICK TO UPLOAD</div>
                                    <div className="text-[9px] text-foreground/20 font-mono border border-white/[0.04] px-2 py-1 rounded">
                                        SUPPORTED: {allowedExtensions.map(e => e.toUpperCase()).join(', ')}
                                    </div>
                                </>
                            )}
                        </motion.div>
                    </div>

                    {/* Password Field */}
                    {file && (
                        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
                            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                <div className="flex items-center gap-2 px-4 py-2 border-b border-white/[0.04] bg-white/[0.02]">
                                    <Lock size={10} className="text-foreground/30" />
                                    <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">Password (optional)</span>
                                </div>
                                <div className="p-3">
                                    <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="For steghide/openstego extraction" className="w-full px-3 py-2 bg-black/30 border border-white/[0.06] rounded text-white placeholder:text-foreground/15 font-mono text-xs focus:outline-none focus:border-purple-500/30 transition-colors" />
                                </div>
                            </div>
                        </motion.div>
                    )}

                    {/* Error Display */}
                    {error && !analyzing && (
                        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="p-3 rounded-lg border border-red-500/20 bg-red-500/10 text-red-400 text-[10px] flex items-start gap-2 font-mono">
                            <AlertTriangle size={12} className="mt-0.5 flex-shrink-0" /> {error}
                        </motion.div>
                    )}

                    {/* Submit Button */}
                    <button
                        disabled={!file || analyzing}
                        onClick={handleScan}
                        className={`w-full py-3 rounded-lg font-mono text-xs font-bold tracking-wider transition-all ${!file || analyzing
                            ? 'bg-white/5 border border-white/[0.06] text-foreground/20 cursor-not-allowed'
                            : 'bg-gradient-to-r from-purple-500/20 to-pink-500/20 border border-purple-500/30 text-purple-400 hover:border-purple-400/50'
                            }`}
                    >
                        {analyzing ? <span className="flex items-center justify-center gap-2"><Activity className="animate-spin" size={14} /> ANALYZING...</span> : 'ANALYZE IMAGE'}
                    </button>

                    {/* Terminal Log */}
                    {(analyzing || results) && (
                        <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                            <div className="flex items-center gap-2 px-4 py-2 border-b border-white/[0.04] bg-white/[0.02]">
                                <div className="flex gap-1.5">
                                    <div className="w-2 h-2 rounded-full bg-red-500/60" />
                                    <div className="w-2 h-2 rounded-full bg-amber-500/60" />
                                    <div className="w-2 h-2 rounded-full bg-emerald-500/60" />
                                </div>
                                <span className="text-[10px] font-mono text-foreground/20 ml-2">STEG ANALYSIS LOG</span>
                            </div>
                            <div className="p-3 h-[260px] overflow-y-auto custom-scrollbar bg-black/20">
                                <div className="space-y-0.5">
                                    {logs.map((log, i) => <TerminalLine key={i} text={log.text} color={log.color} />)}
                                    {analyzing && <motion.div animate={{ opacity: [0, 1, 0] }} transition={{ duration: 0.8, repeat: Infinity }} className="w-2 h-3 bg-purple-400 mt-1 inline-block" />}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Analysis Summary */}
                    {results && (
                        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                                <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                                    <Eye size={12} className="text-purple-400" />
                                    <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">Analysis Summary</span>
                                </div>
                                <div className="p-4">
                                    <div className="grid grid-cols-3 gap-3 mb-4">
                                        <div className="text-center p-2 bg-emerald-500/5 border border-emerald-500/10 rounded">
                                            <div className="text-xl font-bold text-emerald-400 font-mono">{stats.ok}</div>
                                            <div className="text-[9px] text-foreground/30 uppercase font-mono">Success</div>
                                        </div>
                                        <div className="text-center p-2 bg-red-500/5 border border-red-500/10 rounded">
                                            <div className="text-xl font-bold text-red-400 font-mono">{stats.error}</div>
                                            <div className="text-[9px] text-foreground/30 uppercase font-mono">Failed</div>
                                        </div>
                                        <div className="text-center p-2 bg-white/[0.02] border border-white/[0.04] rounded">
                                            <div className="text-xl font-bold text-white font-mono">{stats.total}</div>
                                            <div className="text-[9px] text-foreground/30 uppercase font-mono">Total</div>
                                        </div>
                                    </div>
                                    {submissionHash && (
                                        <div className="text-[10px] font-mono text-foreground/25 border-t border-white/[0.04] pt-3">
                                            <div className="flex justify-between"><span>Hash:</span><span className="text-white">{submissionHash.substring(0, 16)}...</span></div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </motion.div>
                    )}
                </div>

                {/* Right Column: Results */}
                {(analyzing || results) && (
                    <div className="lg:col-span-8 space-y-3">
                        {!results ? (
                            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg flex flex-col items-center justify-center text-foreground/15 animate-pulse min-h-[500px]">
                                <Eye size={48} className="mb-4 opacity-20" />
                                <p className="font-mono text-xs">Analyzing image for hidden data...</p>
                                <p className="text-[10px] mt-1 font-mono">Running steganography detection tools</p>
                            </div>
                        ) : (
                            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-3">
                                <div className="flex items-center justify-between mb-2">
                                    <h3 className="text-sm font-bold text-white">Tool Results</h3>
                                    <span className="text-[10px] text-foreground/20 font-mono">{stats.total} tools executed</span>
                                </div>
                                {Object.entries(results)
                                    .sort(([, a], [, b]) => { if (a.status === 'ok' && b.status !== 'ok') return -1; if (a.status !== 'ok' && b.status === 'ok') return 1; return 0 })
                                    .map(([toolName, result]) => <ToolResultCard key={toolName} toolName={toolName} result={result} />)
                                }
                            </motion.div>
                        )}
                    </div>
                )}
            </div>
        </div>
    )
}
