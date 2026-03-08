import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { Button } from '../ui/Button'
import { Zap, Shield, Search, Eye, FileCode, Workflow, Layers, GitBranch, FileOutput } from 'lucide-react'

// Animated background component with particles and grid
function AnimatedBackground() {
    return (
        <div className="absolute inset-0 overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-b from-[#0c1120] via-[#0f1628] to-[#0c1120]" />
            <div className="absolute top-[-140px] right-[-80px] w-[460px] h-[460px] bg-cyan-500/10 rounded-full blur-[120px]" />
            <div className="absolute bottom-[-170px] left-[-90px] w-[420px] h-[420px] bg-blue-500/10 rounded-full blur-[120px]" />

            <svg className="absolute inset-0 w-full h-full opacity-20" preserveAspectRatio="none">
                <defs>
                    <pattern id="soc-grid" width="56" height="56" patternUnits="userSpaceOnUse">
                        <path d="M 60 0 L 0 0 0 60" fill="none" stroke="url(#grid-gradient)" strokeWidth="0.5" />
                    </pattern>
                    <linearGradient id="grid-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor="#8ea3c4" stopOpacity="0.25" />
                        <stop offset="100%" stopColor="#8ea3c4" stopOpacity="0.05" />
                    </linearGradient>
                </defs>
                <rect width="100%" height="100%" fill="url(#soc-grid)" />
            </svg>

            {[...Array(20)].map((_, i) => (
                <motion.div
                    key={i}
                    className={`absolute rounded-full ${i % 3 === 0 ? 'bg-blue-300/70' : 'bg-cyan-300/70'}`}
                    style={{
                        width: Math.random() * 4 + 2,
                        height: Math.random() * 4 + 2,
                        left: `${Math.random() * 100}%`,
                        top: `${Math.random() * 100}%`,
                    }}
                    animate={{
                        y: [0, -30, 0],
                        opacity: [0.2, 0.8, 0.2],
                        scale: [1, 1.2, 1],
                    }}
                    transition={{
                        duration: 3 + Math.random() * 4,
                        repeat: Infinity,
                        delay: Math.random() * 2,
                    }}
                />
            ))}

            <div className="absolute inset-0 pointer-events-none">
                {[...Array(5)].map((_, i) => (
                    <motion.div
                        key={i}
                        className="absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/20 to-transparent"
                        initial={{ top: `${i * 25}%`, opacity: 0 }}
                        animate={{
                            top: [`${i * 25}%`, `${(i * 25 + 100) % 100}%`],
                            opacity: [0, 0.5, 0]
                        }}
                        transition={{
                            duration: 8,
                            repeat: Infinity,
                            delay: i * 1.5,
                            ease: 'linear'
                        }}
                    />
                ))}
            </div>

            <div className="absolute top-0 left-0 w-32 h-32 border-l-2 border-t-2 border-white/15" />
            <div className="absolute top-0 right-0 w-32 h-32 border-r-2 border-t-2 border-white/15" />
            <div className="absolute bottom-0 left-0 w-32 h-32 border-l-2 border-b-2 border-white/15" />
            <div className="absolute bottom-0 right-0 w-32 h-32 border-r-2 border-b-2 border-white/15" />
        </div>
    )
}

export function HeroSection() {
    const containerVariants = {
        hidden: { opacity: 0 },
        visible: {
            opacity: 1,
            transition: {
                staggerChildren: 0.15,
                delayChildren: 0.3,
            },
        },
    }

    const itemVariants = {
        hidden: { opacity: 0, y: 30 },
        visible: {
            opacity: 1,
            y: 0,
            transition: { duration: 0.8, ease: [0.25, 0.46, 0.45, 0.94] },
        },
    }

    const pipelineCapabilities = [
        { icon: Layers, label: 'Automated Pipeline', desc: 'Chain analyzers in sequence or parallel' },
        { icon: GitBranch, label: 'Smart Routing', desc: 'Auto-detects input type and selects tools' },
        { icon: Workflow, label: 'Parallel Execution', desc: 'Run multiple scans simultaneously' },
        { icon: FileOutput, label: 'Unified Reporting', desc: 'Consolidated findings across all tools' },
    ]

    const offerings = [
        { icon: Zap, label: 'Web Analysis', desc: 'Deep website intelligence', link: '/dashboard/web' },
        { icon: Shield, label: 'Malware Analysis', desc: 'Forensic file inspection', link: '/dashboard/malware' },
        { icon: FileCode, label: 'Macro Analysis', desc: 'Office macro threat triage', link: '/dashboard/macro' },
        { icon: Search, label: 'Recon Analysis', desc: 'Digital footprint tracking', link: '/dashboard/recon' },
        { icon: Eye, label: 'Steganography Analysis', desc: 'Hidden Data Detection', link: '/dashboard/steg' },
    ]

    return (
        <section className="soc-section relative min-h-screen flex items-center justify-center overflow-hidden bg-[#0c1120] pt-24" id="home">
            <AnimatedBackground />

            <motion.div
                className="soc-section-inner max-w-6xl text-center"
                variants={containerVariants}
                initial="hidden"
                animate="visible"
            >
                <motion.div variants={itemVariants} className="mb-8">
                    <motion.span
                        className="inline-block text-neon-cyan text-xs sm:text-sm font-mono tracking-[0.4em] uppercase px-4 py-2 border border-neon-blue/35 rounded-full bg-neon-blue/10"
                        whileHover={{ scale: 1.05, borderColor: 'rgba(41, 197, 255, 0.55)' }}
                    >
                        ◈ Security Analysis Platform ◈
                    </motion.span>
                </motion.div>

                <motion.div variants={itemVariants} className="relative mb-8">
                    <motion.h1
                        className="text-7xl sm:text-8xl md:text-9xl lg:text-[10rem] font-bold text-foreground font-mono relative z-10"
                        style={{
                            textShadow: '0 0 50px rgba(41, 197, 255, 0.3), 0 0 90px rgba(115, 230, 255, 0.1)'
                        }}
                    >
                        Sec<span className="text-neon-blue">Flow</span>
                    </motion.h1>
                    <div className="absolute inset-0 blur-3xl opacity-20 bg-gradient-to-r from-cyan-400 via-blue-300 to-cyan-400 -z-10" />
                </motion.div>

                <motion.div variants={itemVariants} className="mb-4">
                    <p className="text-xl sm:text-2xl md:text-3xl lg:text-4xl text-foreground/90 font-medium">
                        "Built for SOC teams."
                        <motion.span
                            className="inline-block w-0.5 h-8 bg-neon-blue ml-2 align-middle"
                            animate={{ opacity: [1, 0] }}
                            transition={{ duration: 0.8, repeat: Infinity }}
                        />
                    </p>
                </motion.div>

                <motion.p
                    variants={itemVariants}
                    className="text-base sm:text-lg text-foreground/60 mb-14 max-w-xl mx-auto"
                >
                    Analyze files, URLs, IPs, domains, and images; triage threats and deliver clear reports from one workflow.
                </motion.p>

                <motion.div variants={itemVariants} className="mb-8 flex flex-wrap items-center justify-center gap-2">
                    <span className="soc-chip">Live Threat Context</span>
                    <span className="soc-chip">Multi-Analyzer Routing</span>
                    <span className="soc-chip">PWNDoc Reporting</span>
                    <span className="soc-chip">AI Decision Engine</span>
                </motion.div>

                <motion.div variants={itemVariants} className="mb-14 mx-auto max-w-4xl flex flex-col lg:flex-row gap-6">

                    <Link to="/dashboard/smart-pipeline" className="flex-1">
                        <motion.div
                            className="soc-panel relative h-full overflow-hidden p-8"
                            style={{
                                boxShadow: '0 0 28px rgba(59, 130, 246, 0.12)',
                            }}
                            whileHover={{
                                boxShadow: '0 0 42px rgba(41, 197, 255, 0.2)',
                            }}
                        >
                            <motion.div
                                className="absolute inset-0 rounded-lg"
                                style={{
                                    background: 'linear-gradient(90deg, transparent, rgba(41, 197, 255, 0.22), transparent)',
                                    backgroundSize: '200% 100%',
                                }}
                                animate={{ backgroundPosition: ['200% 0', '-200% 0'] }}
                                transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
                            />

                            <div className="relative z-10 flex h-full flex-col">
                                <div className="mb-6 min-h-[128px] lg:min-h-[140px]">
                                    <h3 className="mb-6 flex items-center justify-center gap-2 text-xl font-bold font-mono tracking-wider text-neon-cyan">
                                        <span className="w-8 h-px bg-gradient-to-r from-transparent to-neon-cyan" />
                                        Smart Pipeline
                                        <span className="w-8 h-px bg-gradient-to-l from-transparent to-neon-cyan" />
                                    </h3>
                                    <p className="text-center text-sm leading-relaxed text-foreground/60">
                                        Our intelligent Smart Pipeline engine coordinates multi-tool analysis pipelines automatically - feed it any target and watch SecFlow work.
                                    </p>
                                </div>
                                <div className="grid gap-2">
                                    {pipelineCapabilities.map((item, index) => (
                                        <motion.div
                                            key={index}
                                            className="group flex min-h-[96px] items-start gap-4 rounded-lg border border-white/[0.08] bg-[#12192c]/60 p-4 transition-all hover:border-neon-blue/35"
                                            whileHover={{ x: 8, backgroundColor: 'rgba(41, 197, 255, 0.08)' }}
                                            initial={{ opacity: 0, x: -20 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            transition={{ delay: 0.8 + index * 0.1 }}
                                        >
                                            <span className="mt-0.5 flex h-11 w-11 shrink-0 items-center justify-center rounded-md bg-neon-blue/10 text-neon-cyan transition-colors group-hover:bg-neon-blue/20">
                                                <item.icon size={22} />
                                            </span>
                                            <div className="min-w-0 text-left">
                                                <span className="block font-mono text-base leading-tight text-foreground">{item.label}</span>
                                                <span className="mt-1 block text-xs leading-snug text-foreground/50">{item.desc}</span>
                                            </div>
                                        </motion.div>
                                    ))}
                                </div>
                            </div>
                        </motion.div>
                    </Link>

                    <motion.div
                        className="soc-panel relative flex-1 overflow-hidden p-8"
                        style={{
                            boxShadow: '0 0 28px rgba(34, 211, 238, 0.12)',
                        }}
                        whileHover={{
                            boxShadow: '0 0 42px rgba(34, 211, 238, 0.16)',
                        }}
                    >
                        <motion.div
                            className="absolute inset-0 rounded-lg"
                            style={{
                                background: 'linear-gradient(90deg, transparent, rgba(34, 211, 238, 0.22), transparent)',
                                backgroundSize: '200% 100%',
                            }}
                            animate={{ backgroundPosition: ['200% 0', '-200% 0'] }}
                            transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
                        />

                        <motion.div
                            className="absolute inset-0 bg-gradient-to-b from-cyan-500/15 via-transparent to-transparent pointer-events-none"
                            animate={{ y: ['0%', '200%'] }}
                            transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
                        />

                        <div className="relative z-10 flex h-full flex-col">
                            <div className="mb-6 min-h-[128px] lg:min-h-[140px]">
                                <h3 className="mb-6 flex items-center justify-center gap-2 text-xl font-bold font-mono tracking-wider text-neon-blue">
                                    <span className="w-8 h-px bg-gradient-to-r from-transparent to-neon-blue" />
                                    What We Offer
                                    <span className="w-8 h-px bg-gradient-to-l from-transparent to-neon-blue" />
                                </h3>
                                <p className="text-center text-sm leading-relaxed text-foreground/60">
                                    Explore dedicated analyzers tuned for web, malware, macro, recon, and steganography investigations.
                                </p>
                            </div>
                            <div className="grid gap-2">
                                {offerings.map((item, index) => (
                                    <Link key={index} to={item.link}>
                                        <motion.div
                                            className="group flex min-h-[96px] items-start gap-4 rounded-lg border border-white/[0.08] bg-[#12192c]/60 p-4 transition-all hover:border-neon-blue/35"
                                            whileHover={{ x: 8, backgroundColor: 'rgba(41, 197, 255, 0.07)' }}
                                            initial={{ opacity: 0, x: -20 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            transition={{ delay: 0.8 + index * 0.1 }}
                                        >
                                            <span className="mt-0.5 flex h-11 w-11 shrink-0 items-center justify-center rounded-md bg-cyan-500/10 text-cyan-300 transition-colors group-hover:bg-cyan-500/20">
                                                <item.icon size={22} />
                                            </span>
                                            <div className="min-w-0 text-left">
                                                <span className="block font-mono text-base leading-tight text-foreground">{item.label}</span>
                                                <span className="mt-1 block text-xs leading-snug text-foreground/50">{item.desc}</span>
                                            </div>
                                            <motion.span
                                                className="ml-auto text-neon-cyan opacity-0 transition-opacity group-hover:opacity-100"
                                                initial={{ x: -10 }}
                                                whileHover={{ x: 0 }}
                                            >
                                                →
                                            </motion.span>
                                        </motion.div>
                                    </Link>
                                ))}
                            </div>
                        </div>
                    </motion.div>
                </motion.div>

                <motion.div variants={itemVariants} className="flex flex-col sm:flex-row gap-5 justify-center">
                    <motion.div
                        whileHover={{ scale: 1.05, y: -2 }}
                        whileTap={{ scale: 0.95 }}
                    >
                        <Link to="/dashboard">
                            <Button variant="primary" className="text-base px-10 py-5 !bg-neon-blue !text-[#041024] hover:!bg-neon-cyan shadow-[0_0_30px_rgba(41,197,255,0.3)]">
                                Get Started
                            </Button>
                        </Link>
                    </motion.div>
                    <motion.div
                        whileHover={{ scale: 1.05, y: -2 }}
                        whileTap={{ scale: 0.95 }}
                    >
                        <Button
                            variant="outline"
                            className="text-base px-10 py-5 !border-neon-blue/35 !text-neon-cyan hover:!bg-neon-blue/10"
                            onClick={() => {
                                document.getElementById('tools')?.scrollIntoView({ behavior: 'smooth' })
                            }}
                        >
                            Explore Tools
                        </Button>
                    </motion.div>
                </motion.div>
            </motion.div>
        </section>
    )
}
