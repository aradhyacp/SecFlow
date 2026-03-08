import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { Globe, Bug, FileCode, Eye, Radar, ArrowRight, BookOpen } from 'lucide-react'

const tools = [
    {
        icon: Globe,
        title: 'Web Analysis',
        desc: 'Deep inspection of web headers, DNS, technologies, and vulnerabilities.',
        link: '/docs/web-analyzer',
        glowClass: 'bg-neon-blue/8',
        iconClass: 'bg-neon-blue/12 text-neon-cyan border-neon-blue/30',
        linkClass: 'text-neon-cyan'
    },
    {
        icon: Bug,
        title: 'Malware Analysis',
        desc: 'Static and dynamic analysis of suspicious files with AI insights.',
        link: '/docs/malware-analysis',
        glowClass: 'bg-blue-500/8',
        iconClass: 'bg-blue-500/12 text-blue-300 border-blue-400/30',
        linkClass: 'text-blue-300'
    },
    {
        icon: FileCode,
        title: 'Macro Analysis',
        desc: 'Office document macro inspection with VBA extraction and IOC scoring.',
        link: '/docs/macro-analysis',
        glowClass: 'bg-amber-500/8',
        iconClass: 'bg-amber-500/12 text-amber-300 border-amber-400/30',
        linkClass: 'text-amber-300'
    },
    {
        icon: Eye,
        title: 'Steg Analysis',
        desc: 'Forensic tools to detect hidden data within images and files.',
        link: '/docs/steg-analysis',
        glowClass: 'bg-indigo-500/8',
        iconClass: 'bg-indigo-500/12 text-indigo-300 border-indigo-400/30',
        linkClass: 'text-indigo-300'
    },
    {
        icon: Radar,
        title: 'Recon Analysis',
        desc: 'OSINT gathering and digital footprint investigation.',
        link: '/docs/recon-analysis',
        glowClass: 'bg-cyan-500/8',
        iconClass: 'bg-cyan-500/12 text-cyan-300 border-cyan-400/30',
        linkClass: 'text-cyan-300'
    }
]

export default function DocsHub() {
    return (
        <div className="space-y-12">
            {/* Hero */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="text-center space-y-4"
            >
                <div className="mx-auto w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center mb-6">
                    <BookOpen size={32} className="text-white" />
                </div>
                <span className="soc-kicker">Knowledge Center</span>
                <h1 className="text-4xl md:text-5xl font-bold text-white font-mono">
                    Documentation <span className="text-neon-blue">Hub</span>
                </h1>
                <p className="text-foreground/60 max-w-2xl mx-auto text-lg">
                    Comprehensive guides and reference material for the SecFlow platform tools.
                    Select a module below to get started.
                </p>
            </motion.div>

            {/* Tool Selection Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {tools.map((tool, i) => (
                    <Link key={i} to={tool.link}>
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ delay: i * 0.1 }}
                            whileHover={{ scale: 1.02 }}
                            className="soc-panel h-full p-6 hover:border-neon-blue/35 group relative overflow-hidden"
                        >
                            {/* Hover Glow */}
                            <div className={`absolute inset-0 ${tool.glowClass} opacity-0 group-hover:opacity-100 transition-opacity duration-500`} />

                            <div className="relative z-10 flex items-start gap-4">
                                <div className={`p-4 rounded-xl border ${tool.iconClass} group-hover:scale-110 transition-transform duration-300`}>
                                    <tool.icon size={24} />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold text-white mb-2 group-hover:text-neon-blue transition-colors">
                                        {tool.title}
                                    </h3>
                                    <p className="text-foreground/60 text-sm mb-4 leading-relaxed">
                                        {tool.desc}
                                    </p>
                                    <div className={`flex items-center gap-2 ${tool.linkClass} text-sm font-mono font-bold`}>
                                        Read Docs <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" />
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    </Link>
                ))}
            </div>

            {/* Quick Start Note */}
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.6 }}
                className="soc-panel p-6 text-center"
            >
                <h4 className="text-neon-blue font-bold mb-2 font-mono">Need technical support?</h4>
                <p className="text-sm text-foreground/70">
                    Backend docs are the canonical source for API and integration details. Refer to backend/Readme.md and backend/Web-Analyzer/* docs for the latest technical documentation.
                </p>
            </motion.div>
        </div>
    )
}
