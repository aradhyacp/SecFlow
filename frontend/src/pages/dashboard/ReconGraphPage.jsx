import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    Radar, Search, Globe, Shield, MapPin, Server, Users, Mail, Phone,
    AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp, Loader2,
    Eye, EyeOff, Activity, Wifi, Lock, Unlock, ExternalLink, Crosshair
} from 'lucide-react'
import { Button } from '../../components/ui/Button'
import { API_ENDPOINTS } from '../../config/api'

const InfoRow = ({ label, value, icon: Icon, color = 'white' }) => (
    <div className="flex items-center justify-between py-1.5 border-b border-white/[0.03] last:border-0 text-xs">
        <span className="text-foreground/40 font-mono flex items-center gap-2">
            {Icon && <Icon size={11} className="text-foreground/25" />} {label}
        </span>
        <span className={`text-${color} font-mono`}>{value || 'N/A'}</span>
    </div>
)

const RiskBadge = ({ level }) => {
    const colors = {
        low: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
        medium: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
        high: 'bg-red-500/10 text-red-400 border-red-500/20',
    }
    return (
        <span className={`px-3 py-1 rounded text-[10px] font-mono uppercase font-bold border ${colors[level] || colors.low} tracking-wider`}>
            {level} Risk
        </span>
    )
}

const ResultCard = ({ title, icon: Icon, children, color = 'amber', collapsed = false }) => {
    const [isOpen, setIsOpen] = useState(!collapsed)
    const colorMap = {
        amber: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20' },
        red: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20' },
        emerald: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20' },
        'foreground': { bg: 'bg-white/5', text: 'text-foreground/40', border: 'border-white/10' },
    }
    const c = colorMap[color] || colorMap.amber
    return (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 cursor-pointer hover:bg-white/[0.02] transition-colors" onClick={() => setIsOpen(!isOpen)}>
                <div className="flex items-center gap-2.5">
                    <div className={`w-7 h-7 rounded ${c.bg} border ${c.border} flex items-center justify-center`}>
                        <Icon size={14} className={c.text} />
                    </div>
                    <h3 className="font-bold text-white text-sm">{title}</h3>
                </div>
                {isOpen ? <ChevronUp size={14} className="text-foreground/20" /> : <ChevronDown size={14} className="text-foreground/20" />}
            </div>
            <AnimatePresence>
                {isOpen && (
                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="px-4 pb-4">
                        {children}
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    )
}

export default function ReconGraphPage() {
    const [mode, setMode] = useState('threat')
    const [query, setQuery] = useState('')
    const [footprintType, setFootprintType] = useState('username')
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState(null)
    const [results, setResults] = useState(null)
    const [healthStatus, setHealthStatus] = useState(null)

    useEffect(() => {
        fetch(API_ENDPOINTS.recon.health).then(res => res.json()).then(data => setHealthStatus(data.status)).catch(() => setHealthStatus('unhealthy'))
    }, [])

    const handleThreatScan = async () => {
        if (!query.trim()) return; setLoading(true); setError(null); setResults(null)
        try {
            const res = await fetch(API_ENDPOINTS.recon.scan, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: query.trim() }) })
            if (!res.ok) throw new Error('Scan failed'); const data = await res.json(); setResults({ type: 'threat', data })
        } catch (e) { setError(e.message || 'Failed to perform threat scan') } finally { setLoading(false) }
    }

    const handleFootprintScan = async () => {
        if (!query.trim()) return; setLoading(true); setError(null); setResults(null)
        try {
            const res = await fetch(API_ENDPOINTS.recon.footprint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: query.trim(), type: footprintType }) })
            if (!res.ok) throw new Error('Footprint analysis failed'); const data = await res.json(); setResults({ type: 'footprint', subtype: footprintType, data })
        } catch (e) { setError(e.message || 'Failed to analyze footprint') } finally { setLoading(false) }
    }

    const handleSubmit = () => { if (mode === 'threat') handleThreatScan(); else handleFootprintScan() }
    const calculateRisk = (data) => { if (!data) return 'low'; if (data.talos?.blacklisted || data.tor?.is_tor_exit) return 'high'; return 'low' }

    return (
        <div className="max-w-7xl mx-auto space-y-6 pb-20">

            {/* ─── SOC Header ─── */}
            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-6 py-4">
                    <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-md bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
                            <Radar size={22} className="text-amber-400" />
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-white tracking-tight">Recon Analysis</h2>
                            <p className="text-xs text-foreground/40 font-mono">OSINT & Threat Intelligence</p>
                        </div>
                    </div>
                    {healthStatus && (
                        <div className={`flex items-center gap-2 px-3 py-1.5 rounded text-[10px] font-mono font-bold tracking-wider ${healthStatus === 'healthy'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-red-500/10 text-red-400 border border-red-500/20'
                            }`}>
                            <div className={`w-1.5 h-1.5 rounded-full ${healthStatus === 'healthy' ? 'bg-emerald-400' : 'bg-red-400'} animate-pulse`} />
                            {healthStatus === 'healthy' ? 'SYSTEM ONLINE' : 'SYSTEM OFFLINE'}
                        </div>
                    )}
                </div>
                {loading && (
                    <motion.div className="h-0.5 bg-gradient-to-r from-amber-500 via-yellow-400 to-amber-500" style={{ backgroundSize: '200% 100%' }} animate={{ backgroundPosition: ['0% 0', '200% 0'] }} transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }} />
                )}
            </div>

            {/* ─── Mode Toggle ─── */}
            <div className="flex gap-2 p-1 bg-[#0c1120] rounded-lg border border-white/[0.06] w-fit">
                <button
                    onClick={() => { setMode('threat'); setResults(null); setQuery('') }}
                    className={`px-4 py-2 rounded font-mono text-[10px] font-bold tracking-wider transition-all ${mode === 'threat'
                        ? 'bg-amber-500/15 text-amber-400 border border-amber-500/20' : 'text-foreground/30 hover:text-foreground/60 border border-transparent'
                        }`}
                >
                    <Globe size={12} className="inline mr-2" /> THREAT INTEL
                </button>
                <button
                    onClick={() => { setMode('footprint'); setResults(null); setQuery('') }}
                    className={`px-4 py-2 rounded font-mono text-[10px] font-bold tracking-wider transition-all ${mode === 'footprint'
                        ? 'bg-amber-500/15 text-amber-400 border border-amber-500/20' : 'text-foreground/30 hover:text-foreground/60 border border-transparent'
                        }`}
                >
                    <Users size={12} className="inline mr-2" /> FOOTPRINT
                </button>
            </div>

            {/* ─── Input Panel ─── */}
            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                    <Crosshair size={12} className="text-amber-400" />
                    <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">
                        {mode === 'threat' ? 'Target Query' : `${footprintType} Lookup`}
                    </span>
                </div>
                <div className="p-4 flex flex-col md:flex-row gap-3">
                    {mode === 'footprint' && (
                        <select value={footprintType} onChange={(e) => setFootprintType(e.target.value)} disabled={loading} className="px-3 py-2.5 rounded bg-black/30 border border-white/[0.06] text-white font-mono text-xs focus:outline-none focus:border-amber-500/30 disabled:opacity-50">
                            <option value="username">Username</option>
                            <option value="email">Email</option>
                            <option value="phone">Phone</option>
                        </select>
                    )}
                    <div className="flex-1 relative">
                        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-foreground/20" />
                        <input type="text" value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleSubmit()} disabled={loading}
                            placeholder={mode === 'threat' ? 'Enter IP address or domain...' : `Enter ${footprintType}...`}
                            className="w-full pl-9 pr-4 py-2.5 rounded bg-black/30 border border-white/[0.06] text-sm text-white placeholder:text-foreground/20 font-mono focus:outline-none focus:border-amber-500/30 disabled:opacity-50"
                        />
                    </div>
                    <button onClick={handleSubmit} disabled={loading || !query.trim()}
                        className={`px-5 py-2.5 rounded font-mono text-[10px] font-bold tracking-wider transition-all ${loading || !query.trim()
                            ? 'bg-white/5 border border-white/[0.06] text-foreground/20 cursor-not-allowed'
                            : 'bg-gradient-to-r from-amber-500/20 to-yellow-500/20 border border-amber-500/30 text-amber-400 hover:border-amber-400/50'
                            }`}
                    >
                        {loading ? <><Loader2 size={12} className="animate-spin inline mr-1" /> SCANNING...</> : mode === 'threat' ? <><Shield size={12} className="inline mr-1" /> RUN SCAN</> : <><Eye size={12} className="inline mr-1" /> ANALYZE</>}
                    </button>
                </div>
            </div>

            {/* Error State */}
            {error && (
                <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 flex items-center gap-2 text-xs font-mono">
                    <AlertTriangle size={14} /> {error}
                </motion.div>
            )}

            {/* Loading State */}
            {loading && (
                <div className="flex flex-col items-center justify-center py-16 space-y-3">
                    <motion.div animate={{ rotate: 360 }} transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}>
                        <Radar size={40} className="text-amber-400" />
                    </motion.div>
                    <p className="text-foreground/30 font-mono text-xs">Gathering intelligence...</p>
                </div>
            )}

            {/* ─── Threat Intel Results ─── */}
            {results?.type === 'threat' && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="grid grid-cols-1 lg:grid-cols-2 gap-4">

                    {/* Summary Card */}
                    <div className="lg:col-span-2 bg-[#0c1120] border border-white/[0.06] rounded-lg p-5">
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                            <div>
                                <p className="text-foreground/30 text-[10px] mb-1 font-mono uppercase">Target</p>
                                <h2 className="text-xl font-bold text-white font-mono">{results.data.query}</h2>
                            </div>
                            <RiskBadge level={calculateRisk(results.data)} />
                        </div>
                    </div>

                    {/* IP Intelligence */}
                    {results.data.ipapi?.ip_info?.[0] && (
                        <ResultCard title="IP Intelligence" icon={MapPin} color="amber">
                            <div className="space-y-0">
                                <InfoRow label="ISP" value={results.data.ipapi.ip_info[0].isp} icon={Wifi} />
                                <InfoRow label="Organization" value={results.data.ipapi.ip_info[0].org} icon={Server} />
                                <InfoRow label="AS" value={results.data.ipapi.ip_info[0].as} />
                                <InfoRow label="Location" value={`${results.data.ipapi.ip_info[0].city}, ${results.data.ipapi.ip_info[0].country}`} icon={MapPin} />
                                <InfoRow label="Timezone" value={results.data.ipapi.ip_info[0].timezone} />
                                <InfoRow label="Zip" value={results.data.ipapi.ip_info[0].zip} />
                            </div>
                        </ResultCard>
                    )}

                    {/* Threat Signals */}
                    <ResultCard title="Threat Signals" icon={Shield} color={calculateRisk(results.data) === 'high' ? 'red' : 'emerald'}>
                        <div className="space-y-3">
                            <div className="grid grid-cols-2 gap-3">
                                <div className={`p-3 rounded text-center border ${results.data.talos?.blacklisted ? 'bg-red-500/5 border-red-500/15' : 'bg-emerald-500/5 border-emerald-500/15'}`}>
                                    <div className="text-[9px] font-mono mb-1 text-foreground/30">Cisco Talos</div>
                                    <div className={`font-bold text-xs font-mono ${results.data.talos?.blacklisted ? 'text-red-400' : 'text-emerald-400'}`}>
                                        {results.data.talos?.blacklisted ? 'BLACKLISTED' : 'CLEAN'}
                                    </div>
                                </div>
                                <div className={`p-3 rounded text-center border ${results.data.tor?.is_tor_exit ? 'bg-red-500/5 border-red-500/15' : 'bg-emerald-500/5 border-emerald-500/15'}`}>
                                    <div className="text-[9px] font-mono mb-1 text-foreground/30">TOR Node</div>
                                    <div className={`font-bold text-xs font-mono ${results.data.tor?.is_tor_exit ? 'text-red-400' : 'text-emerald-400'}`}>
                                        {results.data.tor?.is_tor_exit ? 'EXIT NODE' : 'FALSE'}
                                    </div>
                                </div>
                            </div>
                            {results.data.threatfox && (
                                <div className="pt-2 border-t border-white/[0.04]">
                                    <div className="flex items-center justify-between mb-2">
                                        <span className="text-foreground/40 text-[10px] font-mono">ThreatFox Analysis</span>
                                        {results.data.threatfox.found
                                            ? <span className="text-[9px] font-bold text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded font-mono">DETECTED</span>
                                            : <span className="text-[9px] font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded font-mono">CLEAN</span>
                                        }
                                    </div>
                                    {results.data.threatfox.found && (
                                        <div className="space-y-1 mt-2 bg-red-500/5 p-3 rounded border border-red-500/10">
                                            <div className="grid grid-cols-2 gap-2 text-[10px]">
                                                <div><span className="text-foreground/25 block font-mono">Type</span><span className="text-white font-mono">{results.data.threatfox.threat_type?.replace('_', ' ').toUpperCase()}</span></div>
                                                <div><span className="text-foreground/25 block font-mono">Malware</span><span className="text-white font-mono">{results.data.threatfox.malware}</span></div>
                                                <div className="col-span-2"><span className="text-foreground/25 block font-mono">IOC</span><span className="text-white font-mono break-all">{results.data.threatfox.ioc}</span></div>
                                                <div><span className="text-foreground/25 block font-mono">Conf. Level</span><span className="text-amber-400 font-mono">{results.data.threatfox.confidence_level}%</span></div>
                                                <div><span className="text-foreground/25 block font-mono">ID</span><span className="text-foreground/40 font-mono">#{results.data.threatfox.id}</span></div>
                                            </div>
                                            {results.data.threatfox.link && <a href={results.data.threatfox.link} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-[9px] text-cyan-400 hover:underline mt-1 font-mono">View Report <ExternalLink size={8} /></a>}
                                        </div>
                                    )}
                                    {results.data.threatfox.error && <div className="text-[10px] text-foreground/25 mt-1 italic font-mono">API Note: {results.data.threatfox.error}</div>}
                                </div>
                            )}
                        </div>
                    </ResultCard>

                    {/* Tranco Rank */}
                    {results.data.tranco && (
                        <ResultCard title="Web Ranking" icon={Activity} color="amber">
                            <div className="space-y-2">
                                <div className={`px-4 py-3 rounded border ${results.data.tranco.found ? 'bg-amber-500/5 border-amber-500/15' : 'bg-white/[0.02] border-white/[0.04]'}`}>
                                    <div className="text-[9px] text-foreground/30 font-mono uppercase mb-1">Tranco Global Rank</div>
                                    <div className={`text-xl font-bold font-mono ${results.data.tranco.found ? 'text-amber-400' : 'text-foreground/25'}`}>
                                        {results.data.tranco.found ? `#${results.data.tranco.rank.toLocaleString()}` : 'Unranked'}
                                    </div>
                                </div>
                                <p className="text-[10px] text-foreground/25 font-mono">Research-oriented top 1M sites ranking.</p>
                            </div>
                        </ResultCard>
                    )}

                    {/* Raw Data */}
                    <ResultCard title="Raw Response" icon={Activity} color="foreground" collapsed>
                        <pre className="text-[10px] text-foreground/50 font-mono bg-black/20 p-3 rounded border border-white/[0.04] overflow-auto max-h-[280px] custom-scrollbar">
                            {JSON.stringify(results.data, null, 2)}
                        </pre>
                    </ResultCard>
                </motion.div>
            )}

            {/* ─── Footprint Results ─── */}
            {results?.type === 'footprint' && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="grid grid-cols-1 lg:grid-cols-2 gap-4">

                    {/* Username Results */}
                    {results.subtype === 'username' && (
                        <>
                            <div className="lg:col-span-2 bg-[#0c1120] border border-white/[0.06] rounded-lg p-5">
                                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                                    <div>
                                        <p className="text-foreground/30 text-[10px] mb-1 font-mono uppercase">Username</p>
                                        <h2 className="text-xl font-bold text-white font-mono">@{results.data.query || query}</h2>
                                    </div>
                                    <div className="text-right">
                                        <p className="text-2xl font-bold text-amber-400 font-mono">
                                            {Array.isArray(results.data.username_scan) ? results.data.username_scan.length : 0}
                                        </p>
                                        <p className="text-foreground/30 text-[10px] font-mono">Platforms Found</p>
                                    </div>
                                </div>
                            </div>
                            <div className="lg:col-span-2">
                                <ResultCard title="Platform Presence" icon={Users} color="amber">
                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                                        {Array.isArray(results.data.username_scan) && results.data.username_scan.map((item, i) => (
                                            <a key={i} href={item.url} target="_blank" rel="noopener noreferrer"
                                                className="flex items-center justify-between p-2.5 rounded bg-black/20 border border-white/[0.04] hover:border-amber-500/20 hover:bg-amber-500/[0.03] transition-all group">
                                                <span className="text-xs font-mono text-white group-hover:text-amber-400">{item.site}</span>
                                                <ExternalLink size={10} className="text-foreground/15 group-hover:text-amber-400" />
                                            </a>
                                        ))}
                                        {(!results.data.username_scan || results.data.username_scan.length === 0) && (
                                            <div className="text-foreground/25 col-span-full py-4 text-center italic text-xs font-mono">No accounts found</div>
                                        )}
                                    </div>
                                </ResultCard>
                            </div>
                        </>
                    )}

                    {/* Email Results */}
                    {results.subtype === 'email' && results.data.email_scan && (
                        <>
                            <div className="lg:col-span-2 bg-[#0c1120] border border-white/[0.06] rounded-lg p-5">
                                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                                    <div>
                                        <p className="text-foreground/30 text-[10px] mb-1 font-mono uppercase">Email Address</p>
                                        <h2 className="text-xl font-bold text-white font-mono">{results.data.query || query}</h2>
                                    </div>
                                    <div className="flex items-center gap-4">
                                        <RiskBadge level={results.data.email_scan.risk?.[0]?.risk_label?.toLowerCase() || (results.data.email_scan.breach_count > 0 ? 'high' : 'low')} />
                                        <div className="text-right pl-4 border-l border-white/[0.06]">
                                            <p className={`text-2xl font-bold font-mono ${results.data.email_scan.breach_count > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                                {results.data.email_scan.breach_count || 0}
                                            </p>
                                            <p className="text-foreground/30 text-[10px] font-mono">Breaches</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div className="lg:col-span-2">
                                <ResultCard title="Data Breaches" icon={AlertTriangle} color={results.data.email_scan.breach_count > 0 ? 'red' : 'emerald'}>
                                    <div className="space-y-3">
                                        {results.data.email_scan.breaches?.map((breach, i) => (
                                            <div key={i} className="p-3 rounded bg-black/20 border border-white/[0.04] flex flex-col md:flex-row gap-3">
                                                {breach.logo && !breach.logo.includes('[') && (
                                                    <div className="w-12 h-12 shrink-0 bg-white/5 rounded p-1.5 flex items-center justify-center">
                                                        <img src={breach.logo} alt={breach.breach} className="max-w-full max-h-full" onError={(e) => e.target.style.display = 'none'} />
                                                    </div>
                                                )}
                                                <div className="flex-1">
                                                    <div className="flex items-center justify-between mb-1.5">
                                                        <h4 className="font-bold text-white text-sm">{breach.breach}</h4>
                                                        <span className="text-[9px] px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-mono">{breach.xposed_date}</span>
                                                    </div>
                                                    <p className="text-[10px] text-foreground/40 mb-2 leading-relaxed font-mono">{breach.details?.length > 200 ? breach.details.substring(0, 200) + '...' : breach.details}</p>
                                                    <div className="flex flex-wrap gap-1">
                                                        <span className="text-[9px] text-foreground/25 uppercase font-mono mr-1 pt-0.5">Compromised:</span>
                                                        {breach.xposed_data?.split(';').map((item, j) => (
                                                            <span key={j} className="px-1.5 py-0.5 rounded bg-white/5 text-[9px] text-foreground/50 font-mono">{item.trim()}</span>
                                                        ))}
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                        {(!results.data.email_scan.breaches || results.data.email_scan.breaches.length === 0) && (
                                            <div className="flex flex-col items-center justify-center py-6 text-center">
                                                <CheckCircle size={36} className="text-emerald-500/20 mb-3" />
                                                <h4 className="text-emerald-400 font-bold text-xs mb-0.5">No Breaches Found</h4>
                                                <p className="text-foreground/25 text-[10px] font-mono">This email does not appear in known breaches.</p>
                                            </div>
                                        )}
                                    </div>
                                </ResultCard>
                            </div>
                        </>
                    )}

                    {/* Phone Results */}
                    {results.subtype === 'phone' && results.data.phone_scan && (
                        <>
                            <div className="lg:col-span-2 bg-[#0c1120] border border-white/[0.06] rounded-lg p-5">
                                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                                    <div>
                                        <p className="text-foreground/30 text-[10px] mb-1 font-mono uppercase">Phone Number</p>
                                        <h2 className="text-xl font-bold text-white font-mono">{results.data.query || query}</h2>
                                    </div>
                                    <div className={`px-3 py-1.5 rounded text-[10px] font-mono font-bold ${results.data.phone_scan.valid
                                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                                        {results.data.phone_scan.valid ? 'VALID' : 'INVALID'}
                                    </div>
                                </div>
                            </div>
                            <ResultCard title="Phone Metadata" icon={Phone} color="amber">
                                <div className="space-y-0">
                                    <InfoRow label="Country" value={results.data.phone_scan.country_name} />
                                    <InfoRow label="Country Code" value={results.data.phone_scan.country_code} />
                                    <InfoRow label="Location" value={results.data.phone_scan.location || 'N/A'} />
                                    <InfoRow label="Carrier" value={results.data.phone_scan.carrier || 'N/A'} />
                                    <InfoRow label="Line Type" value={results.data.phone_scan.line_type?.replace(/_/g, ' ').toUpperCase()} />
                                </div>
                            </ResultCard>
                        </>
                    )}

                    {/* Raw Data */}
                    <ResultCard title="Raw Response" icon={Activity} color="foreground" collapsed>
                        <pre className="text-[10px] text-foreground/50 font-mono bg-black/20 p-3 rounded border border-white/[0.04] overflow-auto max-h-[280px] custom-scrollbar">
                            {JSON.stringify(results.data, null, 2)}
                        </pre>
                    </ResultCard>
                </motion.div>
            )}
        </div>
    )
}
