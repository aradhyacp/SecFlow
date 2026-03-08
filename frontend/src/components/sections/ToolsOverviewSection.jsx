import { motion, useInView } from 'framer-motion'
import { useRef } from 'react'
import { Link } from 'react-router-dom'
import { Globe, Bug, FileCode, Eye, Radar, ArrowRight } from 'lucide-react'

const tools = [
    {
        icon: Globe,
        title: 'Web Analysis',
        subtitle: 'Web Security and Exposure',
        description:
            'SecFlow Web Analyzer inspects URLs and web endpoints for security posture, misconfiguration, and infrastructure risk.',
        highlight: 'Headers, TLS, fingerprinting, and endpoint context in one pass',
        features: [
            'Security header and TLS posture checks',
            'DNS, IP, and hosting intelligence',
            'Cookies, redirects, and crawl controls',
            'Tech stack and endpoint fingerprinting',
            'Trace route and exposure clues',
        ],
        accent: {
            text: 'text-cyan-300',
            badge: 'text-cyan-300',
            iconPanel: 'bg-cyan-500/10 border-cyan-500/30',
            border: 'hover:border-cyan-500/35',
            topBar: 'via-cyan-400',
        },
        link: '/docs/web-analyzer'
    },
    {
        icon: Bug,
        title: 'Malware Analysis',
        subtitle: 'Binary Threat Triage',
        description:
            'SecFlow Malware Analyzer triages suspicious binaries and extracted payloads for signatures, code indicators, and threat signals.',
        highlight: 'Hash intel, decompilation, strings, and risk scoring',
        features: [
            'SHA256/MD5 fingerprinting and intel lookup',
            'Decompiler and disassembly inspection',
            'Suspicious strings and callout extraction',
            'Indicator-based risk scoring',
        ],
        accent: {
            text: 'text-blue-300',
            badge: 'text-blue-300',
            iconPanel: 'bg-blue-500/10 border-blue-500/30',
            border: 'hover:border-blue-500/35',
            topBar: 'via-blue-400',
        },
        link: '/docs/malware-analysis'
    },
    {
        icon: FileCode,
        title: 'Macro Analysis',
        subtitle: 'Document Macro Threat Triage',
        description:
            'SecFlow Macro Analyzer triages Office documents for VBA/XLM macro behavior, suspicious execution paths, and extracted IOCs.',
        highlight: 'Macro extraction, IOC flags, and risk scoring',
        features: [
            'Macro extraction from DOC/XLS/PPT families',
            'AutoExec and suspicious indicator detection',
            'IOC extraction for URLs, domains, and artifacts',
            'Risk classification: clean to malicious',
        ],
        accent: {
            text: 'text-blue-300',
            badge: 'text-blue-300',
            iconPanel: 'bg-blue-500/10 border-blue-500/30',
            border: 'hover:border-blue-500/35',
            topBar: 'via-blue-400',
        },
        link: '/docs/macro-analysis'
    },
    {
        icon: Radar,
        title: 'Recon Analysis',
        subtitle: 'OSINT Intelligence Correlation',
        description: 'SecFlow Recon Analyzer enriches IPs, domains, usernames, emails, and phones with actionable intelligence.',
        highlight: 'WHOIS, DNS, ASN, reputation, and breach context',
        features: [
            'WHOIS, ASN, and geolocation profiling',
            'DNS and blacklist intelligence checks',
            'Username, email, and phone correlation',
            'Breach and exposure signal mapping',
        ],
        accent: {
            text: 'text-sky-300',
            badge: 'text-sky-300',
            iconPanel: 'bg-sky-500/10 border-sky-500/30',
            border: 'hover:border-sky-500/35',
            topBar: 'via-sky-400',
        },
        link: '/docs/recon-analysis'
    },
    {
        icon: Eye,
        title: 'Steg Analysis',
        subtitle: 'Image Steganography Forensics',
        description: 'SecFlow Steg Analyzer detects and extracts concealed artifacts from images and media using dedicated forensic tooling.',
        highlight: 'Embedded data detection and artifact extraction',
        features: [
            'Binwalk and foremost artifact extraction',
            'Steghide and OpenStego probing',
            'EXIF and metadata anomaly checks',
            'Bit-plane and hidden-content analysis',
        ],
        accent: {
            text: 'text-indigo-300',
            badge: 'text-indigo-300',
            iconPanel: 'bg-indigo-500/10 border-indigo-500/30',
            border: 'hover:border-indigo-500/35',
            topBar: 'via-indigo-400',
        },
        link: '/docs/steg-analysis'
    },
]

export function ToolsOverviewSection() {
    const ref = useRef(null)
    const isInView = useInView(ref, { once: true, margin: '-50px' })

    const containerVariants = {
        hidden: { opacity: 0 },
        visible: {
            opacity: 1,
            transition: {
                staggerChildren: 0.2,
            },
        },
    }

    const cardVariants = {
        hidden: { opacity: 0, y: 60, rotateX: -10 },
        visible: {
            opacity: 1,
            y: 0,
            rotateX: 0,
            transition: { duration: 0.8, ease: [0.25, 0.46, 0.45, 0.94] },
        },
    }

    return (
        <section id="tools" ref={ref} className="soc-section relative overflow-hidden bg-[#0c1120]">
            <div className="absolute inset-0 bg-gradient-to-b from-[#0c1120] via-[#0f1628] to-[#0c1120]" />

            <motion.div
                className="absolute top-1/4 -left-20 w-64 h-64 bg-cyan-500/10 rounded-full blur-[100px]"
                animate={{ y: [0, 30, 0], opacity: [0.3, 0.5, 0.3] }}
                transition={{ duration: 8, repeat: Infinity }}
            />
            <motion.div
                className="absolute bottom-1/4 -right-20 w-64 h-64 bg-blue-500/10 rounded-full blur-[100px]"
                animate={{ y: [0, -30, 0], opacity: [0.3, 0.5, 0.3] }}
                transition={{ duration: 10, repeat: Infinity, delay: 2 }}
            />

            <motion.div
                className="soc-section-inner max-w-6xl"
                variants={containerVariants}
                initial="hidden"
                animate={isInView ? 'visible' : 'hidden'}
            >
                <motion.div className="mx-auto mb-16 max-w-5xl text-center" variants={cardVariants}>
                    <motion.span className="soc-kicker mb-4">
                        Core Capabilities
                    </motion.span>
                    <h2 className="font-mono text-4xl font-bold leading-[1.04] tracking-[-0.02em] text-foreground sm:text-5xl md:text-6xl lg:text-[5.15rem]">
                        <span className="block text-foreground/95">Five Tools,</span>
                        <span
                            className="mt-2 block text-neon-blue"
                            style={{ textShadow: '0 0 44px rgba(41, 197, 255, 0.38)' }}
                        >
                            One Smart Pipeline
                        </span>
                    </h2>
                    <div
                        className="mx-auto mt-5 h-px w-44 bg-gradient-to-r from-transparent via-neon-blue/80 to-transparent"
                        aria-hidden="true"
                    />
                    <p className="mx-auto mt-6 max-w-3xl text-lg text-foreground/60">
                        Any input in, one unified investigation report out (JSON, PDF, HTML).
                    </p>
                </motion.div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8">
                    {tools.map((tool, index) => (
                        <motion.div
                            key={index}
                            variants={cardVariants}
                            className="h-full"
                        >
                            <motion.div
                                className={`soc-panel relative h-full overflow-hidden group ${tool.accent.border}`}
                                whileHover={{
                                    y: -8,
                                    transition: { duration: 0.4 }
                                }}
                            >
                                <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent ${tool.accent.topBar} to-transparent opacity-60`} />

                                <div className="relative z-10 p-8 flex flex-col h-full">
                                    <div className="mb-6">
                                        <motion.div
                                            className={`inline-flex p-4 rounded-md border ${tool.accent.iconPanel}`}
                                            whileHover={{ scale: 1.1, rotate: 5 }}
                                        >
                                            <tool.icon size={32} className={tool.accent.text} />
                                        </motion.div>
                                    </div>

                                    <h3 className="text-2xl font-bold text-foreground font-mono mb-1">{tool.title}</h3>
                                    <p className={`text-sm font-mono mb-4 ${tool.accent.badge}`}>
                                        {tool.subtitle}
                                    </p>

                                    <p className="text-foreground/70 text-sm leading-relaxed mb-6 flex-grow">
                                        {tool.description}
                                    </p>

                                    <motion.div
                                        className="mb-6 p-4 rounded-md border border-white/[0.08] bg-white/[0.03] relative overflow-hidden"
                                        whileHover={{ borderColor: 'rgba(255, 255, 255, 0.2)' }}
                                    >
                                        <div className="absolute inset-0 bg-gradient-to-r from-white/[0.05] via-transparent to-white/[0.05] animate-pulse" />
                                        <p className="text-neon-cyan text-sm font-mono font-bold relative z-10">{tool.highlight}</p>
                                    </motion.div>

                                    <div className="space-y-3 mb-6">
                                        {tool.features.slice(0, 4).map((feature, i) => (
                                            <motion.div
                                                key={i}
                                                className="flex items-start gap-3 text-sm text-foreground/60 group/item"
                                                whileHover={{ x: 4, color: 'rgba(224, 224, 224, 0.9)' }}
                                            >
                                                <span className={`${tool.accent.text} mt-0.5`}>◆</span>
                                                <span className="group-hover/item:text-foreground/90 transition-colors">{feature}</span>
                                            </motion.div>
                                        ))}
                                    </div>

                                    <Link to={tool.link}>
                                        <motion.button
                                            className={`mt-auto flex items-center gap-2 font-mono text-sm group/btn ${tool.accent.text}`}
                                            whileHover={{ x: 4 }}
                                        >
                                            Learn More
                                            <ArrowRight size={16} className="group-hover/btn:translate-x-1 transition-transform" />
                                        </motion.button>
                                    </Link>
                                </div>
                            </motion.div>
                        </motion.div>
                    ))}
                </div>
            </motion.div>
        </section>
    )
}
