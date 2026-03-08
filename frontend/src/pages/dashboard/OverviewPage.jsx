import { motion } from 'framer-motion'
import { Globe, Bug, FileCode, Radar, Eye, Shield, Server, Activity, Workflow, ChevronRight } from 'lucide-react'
import { Link } from 'react-router-dom'

const MODULE_CARDS = [
    { title: 'Smart Pipeline', desc: 'Universal multi-tool analysis pipeline', icon: Workflow, to: '/dashboard/smart-pipeline', accent: 'blueStrong' },
    { title: 'Web Analysis', desc: 'DNS, headers, TLS, tech stack scanner', icon: Globe, to: '/dashboard/web', accent: 'cyan' },
    { title: 'Malware Analysis', desc: 'Static & dynamic binary inspection', icon: Bug, to: '/dashboard/malware', accent: 'indigo' },
    { title: 'Macro Analysis', desc: 'Office macro and VBA threat triage', icon: FileCode, to: '/dashboard/macro', accent: 'amber' },
    { title: 'Steg Analysis', desc: 'Hidden data detection in media files', icon: Eye, to: '/dashboard/steg', accent: 'sky' },
    { title: 'Recon Analysis', desc: 'OSINT & digital footprint tracking', icon: Radar, to: '/dashboard/recon', accent: 'blueStrong' },
]

const accentMap = {
    blueStrong: { icon: 'text-neon-blue', bg: 'bg-neon-blue/12', border: 'border-neon-blue/28', hoverBorder: 'hover:border-neon-blue/45' },
    cyan: { icon: 'text-neon-cyan', bg: 'bg-neon-cyan/10', border: 'border-neon-cyan/25', hoverBorder: 'hover:border-neon-cyan/40' },
    sky: { icon: 'text-sky-300', bg: 'bg-sky-500/10', border: 'border-sky-400/25', hoverBorder: 'hover:border-sky-400/40' },
    indigo: { icon: 'text-indigo-300', bg: 'bg-indigo-500/10', border: 'border-indigo-400/25', hoverBorder: 'hover:border-indigo-400/40' },
    amber: { icon: 'text-amber-300', bg: 'bg-amber-500/10', border: 'border-amber-400/25', hoverBorder: 'hover:border-amber-400/40' },
}

export default function OverviewPage() {
    return (
        <div className="space-y-6 pb-20">

            {/* ─── SOC Command Center Header ─── */}
            <div className="soc-panel overflow-hidden">
                <div className="flex items-center justify-between px-6 py-5">
                    <div className="flex items-center gap-4">
                        <div className="w-11 h-11 rounded-md bg-neon-blue/12 border border-neon-blue/25 flex items-center justify-center shadow-[0_0_28px_rgba(41,197,255,0.12)]">
                            <Shield size={24} className="text-neon-blue" />
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-white tracking-tight">
                                Welcome Back, <span className="text-neon-blue">Analyst</span>
                            </h2>
                            <p className="text-xs text-foreground/40 font-mono">SecFlow SOC Command Center · {MODULE_CARDS.length} modules ready for deployment</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-3">
                        <div className="text-right mr-3 hidden md:block">
                            <div className="text-[10px] text-foreground/30 font-mono uppercase">Status</div>
                            <div className="text-xs font-mono text-neon-cyan font-bold">ALL SYSTEMS GO</div>
                        </div>
                        <div className="h-8 w-px bg-white/10 hidden md:block" />
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-neon-blue/10 border border-neon-blue/25">
                            <div className="w-1.5 h-1.5 rounded-full bg-neon-blue animate-pulse" />
                            <span className="text-[10px] font-mono text-neon-cyan font-bold tracking-wider">API ONLINE</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* ─── Section Label ─── */}
            <div className="flex items-center gap-2">
                <Server size={12} className="text-neon-cyan" />
                <span className="text-[10px] font-mono text-foreground/30 uppercase tracking-widest font-bold">Analysis Modules</span>
                <div className="flex-1 h-px bg-white/5" />
                <span className="text-[10px] font-mono text-foreground/20">{MODULE_CARDS.length} AVAILABLE</span>
            </div>

            {/* ─── Module Cards Grid ─── */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {MODULE_CARDS.map((mod, i) => {
                    const a = accentMap[mod.accent]
                    return (
                        <Link key={i} to={mod.to} className="block group">
                            <motion.div
                                whileHover={{ y: -2 }}
                                className={`soc-panel ${a.hoverBorder} overflow-hidden transition-all h-full`}
                            >
                                <div className="p-5">
                                    <div className="flex items-start justify-between mb-4">
                                        <div className={`w-10 h-10 rounded-md ${a.bg} border ${a.border} flex items-center justify-center`}>
                                            <mod.icon size={20} className={a.icon} />
                                        </div>
                                        <ChevronRight size={16} className="text-foreground/10 group-hover:text-foreground/30 transition-colors mt-1" />
                                    </div>
                                    <h3 className="text-sm font-bold text-white mb-1 tracking-tight">{mod.title}</h3>
                                    <p className="text-[11px] text-foreground/35 font-mono leading-relaxed">{mod.desc}</p>
                                </div>
                                <div className={`h-px bg-gradient-to-r from-transparent via-white/[0.04] to-transparent`} />
                                <div className="px-5 py-2.5 flex items-center justify-between bg-white/[0.01]">
                                    <span className="text-[9px] font-mono text-foreground/20 uppercase tracking-wider">Launch Module</span>
                                    <div className="flex items-center gap-1.5">
                                        <div className="w-1.5 h-1.5 rounded-full bg-neon-blue/80" />
                                        <span className="text-[9px] font-mono text-neon-cyan/80">READY</span>
                                    </div>
                                </div>
                            </motion.div>
                        </Link>
                    )
                })}
            </div>

            {/* ─── System Info Footer ─── */}
            <div className="flex items-center justify-between pt-2">
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2">
                        <Activity size={12} className="text-foreground/15" />
                        <span className="text-[10px] font-mono text-foreground/20">SecFlow Platform v2.1</span>
                    </div>
                </div>
                <div className="text-[10px] font-mono text-foreground/15">
                    {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
                </div>
            </div>
        </div>
    )
}
