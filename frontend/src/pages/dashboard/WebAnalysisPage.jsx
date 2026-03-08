import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Search, Globe, Shield, ShieldAlert, Activity, List, Server, TriangleAlert, CheckCircle, Clock, MapPin, Lock, FileText, Share2, Info, ChevronDown, ChevronUp, AlertCircle, Wifi, Mail, Link2, Cookie, ExternalLink, Crosshair } from 'lucide-react'
import { Button } from '../../components/ui/Button'
import { API_ENDPOINTS as SERVICE_ENDPOINTS, WEB_ANALYZER_PATHS } from '../../config/api'

const API_ENDPOINTS = [
    { key: 'status', endpoint: WEB_ANALYZER_PATHS.status, name: 'Status Check' },
    { key: 'dns', endpoint: WEB_ANALYZER_PATHS.dns, name: 'DNS Records' },
    { key: 'headers', endpoint: WEB_ANALYZER_PATHS.headers, name: 'HTTP Headers' },
    { key: 'securityHeaders', endpoint: WEB_ANALYZER_PATHS.securityHeaders, name: 'Security Headers' },
    { key: 'securityTxt', endpoint: WEB_ANALYZER_PATHS.securityTxt, name: 'Security.txt' },
    { key: 'techStack', endpoint: WEB_ANALYZER_PATHS.techStack, name: 'Tech Stack' },
    { key: 'whois', endpoint: WEB_ANALYZER_PATHS.whois, name: 'WHOIS' },
    { key: 'robotsTxt', endpoint: WEB_ANALYZER_PATHS.robotsTxt, name: 'Robots.txt' },
    { key: 'sitemap', endpoint: WEB_ANALYZER_PATHS.sitemap, name: 'Sitemap' },
    { key: 'cookies', endpoint: WEB_ANALYZER_PATHS.cookies, name: 'Cookies' },
    { key: 'hsts', endpoint: WEB_ANALYZER_PATHS.hsts, name: 'HSTS' },
    { key: 'redirects', endpoint: WEB_ANALYZER_PATHS.redirects, name: 'Redirects' },
    { key: 'ports', endpoint: WEB_ANALYZER_PATHS.ports, name: 'Port Scan' },
    { key: 'getIp', endpoint: WEB_ANALYZER_PATHS.getIp, name: 'IP Lookup' },
    { key: 'socialTags', endpoint: WEB_ANALYZER_PATHS.socialTags, name: 'Social Tags' },
    { key: 'txtRecords', endpoint: WEB_ANALYZER_PATHS.txtRecords, name: 'TXT Records' },
    { key: 'linkedPages', endpoint: WEB_ANALYZER_PATHS.linkedPages, name: 'Linked Pages' },
    { key: 'mailConfig', endpoint: WEB_ANALYZER_PATHS.mailConfig, name: 'Mail Config' },
    { key: 'dnssec', endpoint: WEB_ANALYZER_PATHS.dnssec, name: 'DNSSEC' },
    { key: 'firewall', endpoint: WEB_ANALYZER_PATHS.firewall, name: 'Firewall' },
    { key: 'dnsServer', endpoint: WEB_ANALYZER_PATHS.dnsServer, name: 'DNS Server' },
    { key: 'traceRoute', endpoint: WEB_ANALYZER_PATHS.traceRoute, name: 'Trace Route' },
    { key: 'tls', endpoint: WEB_ANALYZER_PATHS.tls, name: 'TLS Configuration' },
    { key: 'rank', endpoint: WEB_ANALYZER_PATHS.rank, name: 'Domain Rank' },
    { key: 'carbon', endpoint: WEB_ANALYZER_PATHS.carbon, name: 'Carbon' },
    { key: 'blockLists', endpoint: WEB_ANALYZER_PATHS.blockLists, name: 'Block Lists' },
]

// ─── SOC Panel Card ───
const PanelCard = ({ title, icon: Icon, status, children }) => (
    <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
            <div className="flex items-center gap-2">
                {Icon && <Icon size={12} className="text-foreground/30" />}
                <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">{title}</span>
            </div>
            <div className="flex gap-2 items-center">
                {status === 'loading' && <Activity size={10} className="animate-spin text-amber-400" />}
                {status === 'success' && <CheckCircle size={10} className="text-emerald-400" />}
                {status === 'error' && <AlertCircle size={10} className="text-red-400" />}
            </div>
        </div>
        <div className="p-4">{children}</div>
    </div>
)

const InfoRow = ({ label, value, flag }) => (
    <div className="flex justify-between items-center py-1.5 text-xs border-b border-white/[0.03] last:border-0">
        <span className="text-foreground/40 font-mono">{label}</span>
        <div className="flex items-center gap-2 text-white font-mono text-right max-w-[60%] truncate">
            {value || '-'}
            {flag && <span className="text-sm leading-none">{flag}</span>}
        </div>
    </div>
)

const StatusRow = ({ label, value, status }) => (
    <div className="flex justify-between items-center py-1.5 text-xs border-b border-white/[0.03] last:border-0">
        <span className="text-foreground/40 font-mono">{label}</span>
        <div className="flex items-center gap-2">
            {status === 'pass' ? (
                <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px] font-bold font-mono border border-emerald-500/20">PASS</span>
            ) : status === 'fail' ? (
                <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 text-[10px] font-bold font-mono border border-red-500/20">FAIL</span>
            ) : (
                <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 text-[10px] font-bold font-mono border border-amber-500/20">N/A</span>
            )}
            <span className="text-white font-mono text-[10px]">{value}</span>
        </div>
    </div>
)

export default function WebAnalysisPage() {
    const [url, setUrl] = useState('instagram.com')
    const [loading, setLoading] = useState(false)
    const [results, setResults] = useState({})
    const [progress, setProgress] = useState({ completed: 0, total: 0, successful: 0, failed: 0 })
    const [startTime, setStartTime] = useState(null)
    const [duration, setDuration] = useState(null)

    const handleScan = async () => {
        if (!url.trim()) return
        const startedAt = Date.now()
        setLoading(true)
        setResults({})
        setProgress({ completed: 0, total: API_ENDPOINTS.length, successful: 0, failed: 0 })
        setStartTime(startedAt)
        setDuration(null)
        const cleanUrl = url.replace(/^https?:\/\//, '').replace(/\/$/, '')
        const promises = API_ENDPOINTS.map(async ({ key, endpoint, name }) => {
            try {
                const res = await fetch(`${SERVICE_ENDPOINTS.web.route(endpoint)}?url=${encodeURIComponent(cleanUrl)}`)
                if (!res.ok) throw new Error(`HTTP ${res.status}`)
                const data = await res.json()
                setResults(prev => ({ ...prev, [key]: { data, status: 'success' } }))
                setProgress(prev => ({ ...prev, completed: prev.completed + 1, successful: prev.successful + 1 }))
                return { key, success: true, data }
            } catch (error) {
                setResults(prev => ({ ...prev, [key]: { error: error.message, status: 'error' } }))
                setProgress(prev => ({ ...prev, completed: prev.completed + 1, failed: prev.failed + 1 }))
                return { key, success: false, error }
            }
        })
        await Promise.allSettled(promises)
        setLoading(false)
        setDuration(((Date.now() - startedAt) / 1000).toFixed(2))
    }

    const hasResults = Object.keys(results).length > 0
    const getData = (key) => results[key]?.data
    const getStatus = (key) => results[key]?.status || 'loading'
    const formatResponseTime = (ms) => !ms ? '-' : ms > 1000 ? `${(ms / 1000).toFixed(2)}s` : `${Math.round(ms)}ms`

    return (
        <div className="max-w-7xl mx-auto space-y-6 pb-20">

            {/* ─── SOC Header ─── */}
            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-6 py-4">
                    <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-md bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                            <Globe size={22} className="text-cyan-400" />
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-white tracking-tight">Web Analysis</h2>
                            <p className="text-xs text-foreground/40 font-mono">Advanced Intelligence Scanner · {API_ENDPOINTS.length} Modules</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-emerald-500/10 border border-emerald-500/20">
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                        <span className="text-[10px] font-mono text-emerald-400 font-bold tracking-wider">API ONLINE</span>
                    </div>
                </div>
                {loading && (
                    <motion.div
                        className="h-0.5 bg-gradient-to-r from-cyan-500 via-emerald-400 to-cyan-500"
                        style={{ backgroundSize: '200% 100%' }}
                        animate={{ backgroundPosition: ['0% 0', '200% 0'] }}
                        transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
                    />
                )}
            </div>

            {/* ─── Target Input ─── */}
            <div className="bg-[#0c1120] border border-white/[0.06] rounded-lg overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
                    <Crosshair size={12} className="text-cyan-400" />
                    <span className="text-[10px] font-mono text-foreground/40 uppercase tracking-wider">Target Domain</span>
                </div>
                <div className="p-4 flex items-center gap-3">
                    <input
                        value={url}
                        onChange={e => setUrl(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && handleScan()}
                        placeholder="Enter domain (e.g., instagram.com)"
                        className="flex-1 bg-black/30 border border-white/[0.06] rounded px-4 py-2.5 text-sm text-white font-mono focus:border-cyan-500/30 outline-none transition-colors placeholder:text-foreground/20"
                    />
                    <button
                        onClick={handleScan}
                        disabled={loading}
                        className={`px-6 py-2.5 rounded font-mono text-[10px] font-bold tracking-wider transition-all ${loading
                            ? 'bg-white/5 border border-white/[0.06] text-foreground/20 cursor-not-allowed'
                            : 'bg-gradient-to-r from-cyan-500/20 to-emerald-500/20 border border-cyan-500/30 text-cyan-400 hover:border-cyan-400/50'
                            }`}
                    >
                        {loading ? 'SCANNING...' : 'RUN ANALYSIS'}
                    </button>
                </div>
            </div>

            {/* ─── Progress Bar ─── */}
            {(loading || hasResults) && (
                <motion.div
                    initial={{ opacity: 0, y: -8 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="bg-[#0c1120] border border-white/[0.06] rounded-lg p-4"
                >
                    <div className="flex justify-between text-[10px] font-mono mb-2">
                        <div className="flex gap-4">
                            <span className="text-emerald-400">{progress.successful} successful</span>
                            <span className="text-red-400">{progress.failed} failed</span>
                        </div>
                        <span className="text-foreground/30">
                            {loading ? `${progress.completed}/${progress.total} completed` : `Finished`}
                        </span>
                    </div>
                    <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
                        <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${(progress.completed / progress.total) * 100}%` }}
                            transition={{ duration: 0.3 }}
                            className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400"
                        />
                    </div>
                </motion.div>
            )}

            {/* ─── Results Grid ─── */}
            {hasResults && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">

                    {/* Status & Response Time */}
                    <PanelCard title="Status" icon={Activity} status={getStatus('status')}>
                        {getData('status') ? (
                            <div className="space-y-0">
                                <InfoRow label="Is Up" value={getData('status').isUp ? '✓ Online' : '✗ Offline'} />
                                <InfoRow label="Response Code" value={getData('status').responseCode} />
                                <InfoRow label="Response Time" value={formatResponseTime(getData('status').responseTime)} />
                                <InfoRow label="DNS Lookup" value={formatResponseTime(getData('status').dnsLookupTime)} />
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* IP & Server Info */}
                    <PanelCard title="Server Info" icon={Server} status={getStatus('getIp')}>
                        {getData('getIp') ? (
                            <div className="space-y-0">
                                <InfoRow label="IP Address" value={getData('getIp').ip} />
                                <InfoRow label="IP Family" value={`IPv${getData('getIp').family}`} />
                                {getData('dnsServer')?.dns?.[0] && <InfoRow label="DoH Support" value={getData('dnsServer').dns[0].dohDirectSupports ? 'Yes' : 'No'} />}
                                {getData('ports') && (
                                    <div className="mt-3 pt-2 border-t border-white/[0.04]">
                                        <div className="text-[10px] text-foreground/30 mb-2 font-mono uppercase">Open Ports</div>
                                        <div className="flex flex-wrap gap-1">
                                            {getData('ports').openPorts?.map(port => (
                                                <span key={port} className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 text-[10px] font-mono rounded border border-emerald-500/20">{port}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* WHOIS */}
                    <PanelCard title="Domain WHOIS" icon={FileText} status={getStatus('whois')}>
                        {getData('whois') ? (
                            getData('whois').whois_data?.error ? (
                                <div className="space-y-0">
                                    <InfoRow label="Domain" value={getData('whois').domain} />
                                    <InfoRow label="Source" value={getData('whois').source} />
                                    <div className="mt-3 p-3 rounded bg-amber-500/10 border border-amber-500/20 text-center">
                                        <div className="text-amber-400 font-bold text-xs font-mono">{getData('whois').whois_data.error}</div>
                                    </div>
                                </div>
                            ) : (
                                <div className="space-y-0">
                                    <InfoRow label="Domain" value={getData('whois').domain} />
                                    <InfoRow label="Source" value={getData('whois').source} />
                                    <InfoRow label="Registrar" value={getData('whois').whois_data?.registrar || getData('whois').registrar} />
                                    <InfoRow label="Created" value={getData('whois').whois_data?.creationDate || getData('whois').creationDate} />
                                    <InfoRow label="Updated" value={getData('whois').whois_data?.updatedDate || getData('whois').updatedDate} />
                                    <InfoRow label="Expires" value={getData('whois').whois_data?.expiryDate || getData('whois').expiryDate} />
                                    <div className="mt-2 text-[10px] font-mono text-foreground/25 break-all">
                                        Registrant: {getData('whois').whois_data?.registrantOrg || getData('whois').whois_data?.registrant || getData('whois').registrantOrg || getData('whois').registrant || '-'}
                                    </div>
                                </div>
                            )
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* DNS Records */}
                    <PanelCard title="DNS Records" icon={Wifi} status={getStatus('dns')}>
                        {getData('dns') ? (
                            <div className="space-y-2 max-h-[220px] overflow-y-auto custom-scrollbar">
                                {getData('dns').A?.length > 0 && (
                                    <div className="flex flex-col gap-0.5 border-b border-white/[0.03] pb-2">
                                        <span className="text-amber-400 font-bold text-[10px] font-mono">A</span>
                                        {getData('dns').A.map((v, i) => <span key={i} className="font-mono text-xs text-white/80 break-all">{v}</span>)}
                                    </div>
                                )}
                                {getData('dns').AAAA?.length > 0 && (
                                    <div className="flex flex-col gap-0.5 border-b border-white/[0.03] pb-2">
                                        <span className="text-amber-400 font-bold text-[10px] font-mono">AAAA</span>
                                        {getData('dns').AAAA.map((v, i) => <span key={i} className="font-mono text-xs text-white/80 break-all">{v}</span>)}
                                    </div>
                                )}
                                {getData('dns').MX?.length > 0 && (
                                    <div className="flex flex-col gap-0.5 border-b border-white/[0.03] pb-2">
                                        <span className="text-amber-400 font-bold text-[10px] font-mono">MX</span>
                                        {getData('dns').MX.map((mx, i) => <span key={i} className="font-mono text-xs text-white/80 break-all">{mx.exchange} (pri: {mx.preference})</span>)}
                                    </div>
                                )}
                                {getData('dns').NS?.length > 0 && (
                                    <div className="flex flex-col gap-0.5">
                                        <span className="text-amber-400 font-bold text-[10px] font-mono">NS</span>
                                        {getData('dns').NS.map((v, i) => <span key={i} className="font-mono text-xs text-white/80 break-all">{v}</span>)}
                                    </div>
                                )}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* HTTP Security */}
                    <PanelCard title="HTTP Headers" icon={Shield} status={getStatus('headers')}>
                        {getData('headers') ? (
                            <div className="space-y-0 max-h-[220px] overflow-y-auto custom-scrollbar">
                                {Object.entries(getData('headers')).slice(0, 8).map(([key, value], i) => (
                                    <StatusRow key={i} label={key.replace(/-/g, ' ')} value={typeof value === 'string' ? (value.length > 20 ? value.substring(0, 20) + '...' : value) : 'Yes'} status={value ? 'pass' : 'fail'} />
                                ))}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* HSTS */}
                    <PanelCard title="HSTS Policy" icon={Lock} status={getStatus('hsts')}>
                        {getData('hsts') ? (
                            <div className="space-y-0">
                                <InfoRow label="HSTS Enabled" value={getData('hsts').present ? 'Yes' : 'No'} />
                                {getData('hsts').policy && (
                                    <>
                                        <InfoRow label="Max Age" value={`${getData('hsts').policy.max_age}s`} />
                                        <InfoRow label="Include Subdomains" value={getData('hsts').policy.includeSubDomains ? 'Yes' : 'No'} />
                                        <InfoRow label="Preload" value={getData('hsts').policy.preload ? 'Yes' : 'No'} />
                                    </>
                                )}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Tech Stack */}
                    <PanelCard title="Tech Stack" status={getStatus('techStack')}>
                        {getData('techStack')?.technologies ? (
                            <div className="space-y-2">
                                {Object.entries(getData('techStack').technologies).map(([category, techs]) => (
                                    techs?.length > 0 && (
                                        <div key={category} className="flex flex-col gap-1">
                                            <span className="text-foreground/30 text-[10px] uppercase font-mono">{category}</span>
                                            <div className="flex flex-wrap gap-1">
                                                {techs.map((tech, i) => (
                                                    <span key={i} className="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 text-[10px] font-mono rounded border border-cyan-500/20">{tech}</span>
                                                ))}
                                            </div>
                                        </div>
                                    )
                                ))}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Cookies */}
                    <PanelCard title="Cookies" icon={Cookie} status={getStatus('cookies')}>
                        {getData('cookies') ? (
                            <div className="space-y-1.5 max-h-[220px] overflow-y-auto custom-scrollbar">
                                {getData('cookies').clientCookies?.map((cookie, i) => (
                                    <div key={i} className="p-2 bg-black/20 border border-white/[0.03] rounded">
                                        <div className="font-mono text-xs text-white">{cookie.name}</div>
                                        <div className="text-[10px] text-foreground/30 mt-1 flex gap-2 font-mono">
                                            {cookie.secure && <span className="text-emerald-400">Secure</span>}
                                            {cookie.httpOnly && <span className="text-amber-400">HttpOnly</span>}
                                            <span>{cookie.domain}</span>
                                        </div>
                                    </div>
                                ))}
                                {(!getData('cookies').clientCookies || getData('cookies').clientCookies.length === 0) && (
                                    <div className="text-foreground/20 text-xs font-mono">No cookies found</div>
                                )}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Redirects */}
                    <PanelCard title="Redirects" icon={ExternalLink} status={getStatus('redirects')}>
                        {getData('redirects') ? (
                            <div className="space-y-1.5">
                                {getData('redirects').redirects?.map((redirect, i) => (
                                    <div key={i} className="flex items-center gap-2">
                                        <span className="text-amber-400 font-mono text-[10px] w-4">{i + 1}</span>
                                        <span className="font-mono text-xs text-white/80 break-all">{redirect}</span>
                                    </div>
                                ))}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Social Tags */}
                    <PanelCard title="Social Tags" status={getStatus('socialTags')}>
                        {getData('socialTags') ? (
                            <div className="space-y-1.5">
                                <div className="flex flex-col gap-0.5">
                                    <span className="text-foreground/30 font-mono text-[10px]">Title</span>
                                    <span className="text-white text-xs break-words">{getData('socialTags').title || '-'}</span>
                                </div>
                                <div className="flex flex-col gap-0.5">
                                    <span className="text-foreground/30 font-mono text-[10px]">OG Title</span>
                                    <span className="text-white text-xs break-words">{getData('socialTags').ogTitle || '-'}</span>
                                </div>
                                <InfoRow label="OG Site" value={getData('socialTags').ogSiteName} />
                                <div className="mt-2 pt-2 border-t border-white/[0.04]">
                                    <span className="text-foreground/30 font-mono text-[10px]">Description</span>
                                    <p className="text-foreground/40 text-[10px] break-words mt-0.5">{getData('socialTags').description || 'No description'}</p>
                                </div>
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Firewall */}
                    <PanelCard title="Firewall Detection" icon={Shield} status={getStatus('firewall')}>
                        {getData('firewall') ? (
                            <div className="space-y-2">
                                <InfoRow label="WAF Detected" value={getData('firewall').hasWaf ? 'Yes' : 'No'} />
                                {getData('firewall').waf && <InfoRow label="WAF Provider" value={getData('firewall').waf} />}
                                <div className={`mt-2 p-2.5 rounded text-center border ${getData('firewall').hasWaf ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-red-500/10 border-red-500/20'}`}>
                                    <div className={`font-bold text-xs font-mono ${getData('firewall').hasWaf ? 'text-emerald-400' : 'text-red-400'}`}>
                                        {getData('firewall').hasWaf ? `Protected by ${getData('firewall').waf}` : (getData('firewall').message || 'No WAF detected')}
                                    </div>
                                </div>
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Sitemap */}
                    <PanelCard title="Sitemap" icon={List} status={getStatus('sitemap')}>
                        {getData('sitemap') ? (
                            <div className="space-y-1.5">
                                <InfoRow label="Entries found" value={getData('sitemap').count} />
                                <div className="text-[10px] text-foreground/25 truncate font-mono" title={getData('sitemap').url}>{getData('sitemap').url}</div>
                                {getData('sitemap').entries?.length > 0 && (
                                    <div className="max-h-[80px] overflow-y-auto custom-scrollbar mt-2 bg-black/20 border border-white/[0.03] p-2 rounded">
                                        {getData('sitemap').entries.slice(0, 50).map((u, i) => (
                                            <div key={i} className="text-[10px] text-foreground/40 truncate font-mono">{u}</div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Block Lists */}
                    <PanelCard title="Block Lists" icon={Shield} status={getStatus('blockLists')}>
                        {getData('blockLists') ? (
                            <div className="space-y-2">
                                <div className="flex items-center gap-2">
                                    <span className={`text-sm font-bold font-mono ${getData('blockLists').blocked ? 'text-red-400' : 'text-emerald-400'}`}>
                                        {getData('blockLists').blocked ? 'BLOCKED' : 'CLEAN'}
                                    </span>
                                    {getData('blockLists').blocked && <ShieldAlert className="text-red-400" size={14} />}
                                </div>
                                {getData('blockLists').lists && (
                                    <div className="text-[10px] text-foreground/30 font-mono">Checked {Object.keys(getData('blockLists').lists).length} lists</div>
                                )}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Security Headers (Detailed) */}
                    <PanelCard title="Security Headers" icon={Shield} status={getStatus('securityHeaders')}>
                        {getData('securityHeaders') ? (
                            <div className="space-y-3">
                                <div className="flex items-center justify-between mb-1">
                                    <span className="text-xs font-mono text-foreground/40">Score</span>
                                    <span className={`text-lg font-bold font-mono ${getData('securityHeaders').score >= 70 ? 'text-emerald-400' : getData('securityHeaders').score >= 40 ? 'text-amber-400' : 'text-red-400'}`}>
                                        {getData('securityHeaders').score}/100
                                    </span>
                                </div>
                                <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden">
                                    <div className={`h-full ${getData('securityHeaders').score >= 70 ? 'bg-emerald-400' : getData('securityHeaders').score >= 40 ? 'bg-amber-400' : 'bg-red-400'}`} style={{ width: `${getData('securityHeaders').score}%` }} />
                                </div>
                                <div className="pt-1">
                                    <div className="text-[10px] text-foreground/30 mb-1.5 font-mono uppercase">Missing</div>
                                    <div className="flex flex-wrap gap-1">
                                        {getData('securityHeaders').missing?.length > 0 ? getData('securityHeaders').missing.map(h => (
                                            <span key={h} className="px-1.5 py-0.5 bg-red-500/10 border border-red-500/20 text-red-400 text-[9px] rounded font-mono">{h}</span>
                                        )) : <span className="text-emerald-400 text-[10px] font-mono">None!</span>}
                                    </div>
                                </div>
                                <div className="pt-1">
                                    <div className="text-[10px] text-foreground/30 mb-1.5 font-mono uppercase">Present</div>
                                    <div className="max-h-[100px] overflow-y-auto custom-scrollbar space-y-1">
                                        {Object.entries(getData('securityHeaders').present || {}).map(([key, val]) => (
                                            <div key={key} className="text-[10px]">
                                                <span className="text-emerald-400 font-mono block">{key}</span>
                                                <span className="text-white/40 truncate block font-mono" title={val}>{val.length > 50 ? val.substring(0, 50) + '...' : val}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Security.txt */}
                    <PanelCard title="Security.txt" icon={FileText} status={getStatus('securityTxt')}>
                        {getData('securityTxt') ? (
                            <div className="space-y-1.5">
                                <InfoRow label="Found" value={getData('securityTxt').found ? 'Yes' : 'No'} />
                                {getData('securityTxt').found && (
                                    <>
                                        {getData('securityTxt').fields?.contact && (
                                            <div className="flex flex-col gap-0.5">
                                                <span className="text-foreground/30 font-mono text-[10px]">Contact</span>
                                                {getData('securityTxt').fields.contact.map((c, i) => (
                                                    <a key={i} href={c} target="_blank" rel="noopener noreferrer" className="text-cyan-400 text-[10px] hover:underline truncate font-mono">{c}</a>
                                                ))}
                                            </div>
                                        )}
                                        {getData('securityTxt').fields?.expires && <InfoRow label="Expires" value={new Date(getData('securityTxt').fields.expires[0]).toLocaleDateString()} />}
                                    </>
                                )}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* TLS */}
                    <PanelCard title="TLS Configuration" icon={Lock} status={getStatus('tls')}>
                        {getData('tls') ? (
                            <div className="space-y-0">
                                <InfoRow label="Valid Cert" value={getData('tls').validCertificate ? 'Yes' : 'No'} />
                                <InfoRow label="Version" value={getData('tls').tlsVersion} />
                                <InfoRow label="Cipher" value={getData('tls').cipher?.name?.replace(/_/g, ' ')} />
                                {getData('tls').certificateIssuer && (
                                    <div className="mt-2 pt-2 border-t border-white/[0.04]">
                                        <div className="text-[10px] text-foreground/30 mb-1 font-mono">Issuer</div>
                                        <div className="text-xs text-white font-mono">{getData('tls').certificateIssuer.organizationName}</div>
                                        <div className="text-[10px] text-foreground/30 font-mono">{getData('tls').certificateIssuer.commonName}</div>
                                    </div>
                                )}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Trace Route */}
                    <div className="md:col-span-2">
                        <PanelCard title="Trace Route" icon={Share2} status={getStatus('traceRoute')}>
                            {getData('traceRoute') ? (
                                <div className="space-y-2">
                                    <div className="text-[10px] text-foreground/30 mb-2 font-mono">Resolved IP: {getData('traceRoute').resolved_ip}</div>
                                    {getData('traceRoute').hops?.length > 0 ? (
                                        <div className="relative pt-1">
                                            <div className="absolute left-2 top-0 bottom-0 w-px bg-white/[0.06]" />
                                            {getData('traceRoute').hops.map((hop, i) => (
                                                <div key={i} className="flex items-start gap-4 mb-2 relative pl-7">
                                                    <div className="absolute left-[5px] top-[6px] w-1.5 h-1.5 rounded-full bg-cyan-400" />
                                                    <span className="text-amber-400 font-mono text-[10px] w-5">{hop.hop}</span>
                                                    <div className="flex-1">
                                                        <div className="text-white text-xs font-mono">{hop.ip || hop.info}</div>
                                                        {hop.hostname && <div className="text-[10px] text-foreground/25 font-mono">{hop.hostname}</div>}
                                                    </div>
                                                    <div className="text-[10px] text-foreground/20 uppercase font-mono">{hop.type}</div>
                                                </div>
                                            ))}
                                        </div>
                                    ) : <div className="text-[10px] text-foreground/30 italic font-mono">{getData('traceRoute').message}</div>}
                                </div>
                            ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                        </PanelCard>
                    </div>

                    {/* Rank */}
                    <PanelCard title="Domain Rank" icon={Activity} status={getStatus('rank')}>
                        {getData('rank') ? (
                            <div className="space-y-2">
                                <div className="flex items-baseline gap-2">
                                    <span className="text-2xl font-bold text-white font-mono">#{getData('rank').ranks?.[0]?.rank || 'N/A'}</span>
                                    <span className="text-[10px] text-foreground/30 font-mono">Global</span>
                                </div>
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Mail Config */}
                    <PanelCard title="Mail Configuration" icon={Mail} status={getStatus('mailConfig')}>
                        {getData('mailConfig') ? (
                            <div className="space-y-2">
                                {getData('mailConfig').mailServices?.length > 0 && (
                                    <div>
                                        <div className="text-[10px] text-foreground/30 mb-1 font-mono uppercase">Services</div>
                                        {getData('mailConfig').mailServices.map((s, i) => (
                                            <div key={i} className="px-2 py-1 bg-black/20 border border-white/[0.03] rounded text-[10px] text-white font-mono">{s.provider}</div>
                                        ))}
                                    </div>
                                )}
                                <div className="border-t border-white/[0.04] pt-2">
                                    <div className="text-[10px] text-foreground/30 mb-1 font-mono uppercase">MX Records</div>
                                    {getData('mailConfig').mxRecords?.length > 0 ? getData('mailConfig').mxRecords.map((mx, i) => (
                                        <div key={i} className="text-[10px] font-mono text-white/80">{mx.exchange}</div>
                                    )) : <div className="text-[10px] text-foreground/20 font-mono">No MX records</div>}
                                </div>
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* DNSSEC */}
                    <PanelCard title="DNSSEC" icon={Lock} status={getStatus('dnssec')}>
                        {getData('dnssec') ? (
                            <div className="space-y-0">
                                <InfoRow label="DNSKEY" value={getData('dnssec').DNSKEY?.isFound ? 'Found' : 'Not Found'} />
                                <InfoRow label="DS Record" value={getData('dnssec').DS?.isFound ? 'Found' : 'Not Found'} />
                                <InfoRow label="RRSIG" value={getData('dnssec').RRSIG?.isFound ? 'Found' : 'Not Found'} />
                                {getData('dnssec').DS?.response?.Status === 0 && (
                                    <div className="mt-2 text-center">
                                        <span className="px-2 py-1 bg-emerald-500/10 text-emerald-400 text-[10px] rounded border border-emerald-500/20 font-mono font-bold">DNSSEC VALIDATED</span>
                                    </div>
                                )}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Linked Pages */}
                    <PanelCard title="Linked Pages" icon={Link2} status={getStatus('linkedPages')}>
                        {getData('linkedPages') ? (
                            getData('linkedPages').skipped ? (
                                <div className="text-foreground/30 italic text-[10px] p-2 bg-black/20 border border-white/[0.03] rounded font-mono">{getData('linkedPages').skipped}</div>
                            ) : (
                                <div className="space-y-0">
                                    <InfoRow label="Internal" value={getData('linkedPages').internal?.length || 0} />
                                    <InfoRow label="External" value={getData('linkedPages').external?.length || 0} />
                                </div>
                            )
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Robots.txt */}
                    <PanelCard title="Robots.txt" icon={FileText} status={getStatus('robotsTxt')}>
                        {getData('robotsTxt') ? (
                            <div className="text-[10px] font-mono">
                                {getData('robotsTxt').robots ? (
                                    <div className="max-h-[120px] overflow-y-auto custom-scrollbar bg-black/20 border border-white/[0.03] p-2 rounded">
                                        {getData('robotsTxt').robots.slice(0, 10).map((r, i) => (
                                            <div key={i} className={r.type === 'Disallow' ? 'text-red-400' : 'text-emerald-400'}>
                                                <span className="opacity-50">{r.type}: </span>{r.value}
                                            </div>
                                        ))}
                                        {getData('robotsTxt').robots.length > 10 && (
                                            <div className="text-foreground/20 italic pt-1">...{getData('robotsTxt').robots.length - 10} more rules</div>
                                        )}
                                    </div>
                                ) : <div className="text-foreground/20">No robots.txt found</div>}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* TXT Records */}
                    <PanelCard title="TXT Records" icon={List} status={getStatus('txtRecords')}>
                        {getData('txtRecords') ? (
                            <div className="max-h-[180px] overflow-y-auto custom-scrollbar space-y-1">
                                {(getData('txtRecords')['adobe-idp-site-verification'] || getData('txtRecords').data || []).toString().split(' ').map((txt, i) => (
                                    <div key={i} className="p-1.5 bg-black/20 border border-white/[0.03] rounded text-[10px] font-mono text-foreground/60 break-all">{txt.replace(/"/g, '')}</div>
                                ))}
                                {Object.keys(getData('txtRecords')).length === 0 && <div className="text-foreground/20 text-[10px] font-mono">No TXT records</div>}
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                    {/* Carbon */}
                    <PanelCard title="Carbon Footprint" status={getStatus('carbon')}>
                        {getData('carbon') ? (
                            <div className="space-y-0">
                                <InfoRow label="Rating" value={getData('carbon').rating} />
                                <InfoRow label="CO2 (g)" value={getData('carbon').gco2e?.toFixed(4)} />
                                <InfoRow label="Cleaner Than" value={`${(getData('carbon').cleanerThan * 100).toFixed(0)}% of sites`} />
                                <InfoRow label="Green Hosting" value={getData('carbon').green ? 'Yes' : 'No'} />
                            </div>
                        ) : <div className="text-foreground/20 text-xs font-mono">Scanning...</div>}
                    </PanelCard>

                </motion.div>
            )}

            {/* Empty State */}
            {!loading && !hasResults && (
                <div className="h-[50vh] flex flex-col items-center justify-center text-foreground/15">
                    <Globe size={64} strokeWidth={0.5} className="mb-4" />
                    <p className="font-mono tracking-wider text-xs">ENTER DOMAIN TO BEGIN ANALYSIS</p>
                </div>
            )}
        </div>
    )
}
