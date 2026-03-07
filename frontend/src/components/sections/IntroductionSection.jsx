import { motion, useInView } from 'framer-motion'
import { useRef } from 'react'
import { Target, Shield, Network, AlertTriangle, Code, Server, Search, Lock, Users, ChevronRight } from 'lucide-react'

export function IntroductionSection() {
    const ref = useRef(null)
    const isInView = useInView(ref, { once: true, margin: '-50px' })

    const containerVariants = {
        hidden: { opacity: 0 },
        visible: {
            opacity: 1,
            transition: {
                staggerChildren: 0.1,
            },
        },
    }

    const itemVariants = {
        hidden: { opacity: 0, x: -30 },
        visible: {
            opacity: 1,
            x: 0,
            transition: { duration: 0.6, ease: [0.25, 0.46, 0.45, 0.94] },
        },
    }

    const identifyItems = [
        { icon: Target, text: 'Web attack surface and misconfigurations' },
        { icon: Shield, text: 'Malware indicators and suspicious binaries' },
        { icon: Network, text: 'Infrastructure exposure and DNS relationships' },
        { icon: AlertTriangle, text: 'Hidden payloads and OSINT risk signals' },
    ]

    const builtForItems = [
        { icon: Code, text: 'SOC Analysts' },
        { icon: Server, text: 'System administrators' },
        { icon: Search, text: 'Security researchers' },
        { icon: Lock, text: 'Penetration testers' },
        { icon: Users, text: 'Curious technologists' },
    ]

    return (
        <section ref={ref} className="soc-section relative overflow-hidden bg-[#0c1120]">
            <div className="absolute inset-0 bg-gradient-to-b from-[#0c1120] via-[#0f1628] to-[#0c1120]" />
            <div className="absolute left-0 top-1/4 w-32 h-px bg-gradient-to-r from-cyan-400/30 to-transparent" />
            <div className="absolute left-0 top-1/4 w-px h-32 bg-gradient-to-b from-cyan-400/30 to-transparent" />
            <div className="absolute right-0 bottom-1/4 w-32 h-px bg-gradient-to-l from-blue-400/30 to-transparent" />
            <div className="absolute right-0 bottom-1/4 w-px h-32 bg-gradient-to-t from-blue-400/30 to-transparent" />

            <motion.div
                className="soc-section-inner max-w-6xl"
                variants={containerVariants}
                initial="hidden"
                animate={isInView ? 'visible' : 'hidden'}
            >
                <motion.div variants={itemVariants} className="mb-12">
                    <motion.span className="soc-kicker mb-4">
                        About
                    </motion.span>
                    <h2 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold text-foreground font-mono">
                        What is{' '}
                        <span className="text-neon-blue" style={{ textShadow: '0 0 40px rgba(41, 197, 255, 0.4)' }}>
                            SecFlow
                        </span>
                        ?
                    </h2>
                </motion.div>

                <motion.div
                    variants={itemVariants}
                    className="soc-panel relative mb-12 p-6 overflow-hidden"
                    style={{
                        boxShadow: '0 0 32px rgba(41, 197, 255, 0.08)',
                    }}
                >
                    <div className="flex items-center gap-2 mb-4 pb-4 border-b border-foreground/10">
                        <div className="w-3 h-3 rounded-full bg-red-500/80" />
                        <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                        <div className="w-3 h-3 rounded-full bg-green-500/80" />
                        <span className="ml-4 text-foreground/40 font-mono text-xs">SecFlow --about</span>
                    </div>

                    <div className="space-y-5 text-lg md:text-xl text-foreground/80 leading-relaxed font-mono">
                        <p className="flex items-start gap-3">
                            <span className="text-neon-blue shrink-0 pt-0.5">→</span>
                            <span>SecFlow is a fully automated, end-to-end threat analysis pipeline with integrated PWNDoc reporting.</span>
                        </p>

                        <p className="flex items-start gap-3">
                            <span className="text-neon-blue shrink-0 pt-0.5">→</span>
                            <span>It targets security analysts and SOC teams who currently deal with fragmented tooling, manually correlating data from multiple sources to investigate threats. This fragmentation slows incident response and increases the risk of missing critical indicators.</span>
                        </p>

                        <p className="flex items-start gap-3">
                            <span className="text-neon-blue shrink-0 pt-0.5">→</span>
                            <span>SecFlow solves this by accepting any input - file, URL, IP, domain, or image - and routing it through specialized analyzers via an intelligent AI-driven Smart Pipeline.</span>
                        </p>

                        <p className="flex items-start gap-3">
                            <span className="text-neon-blue shrink-0 pt-0.5">→</span>
                            <span>Findings from all analyzers are aggregated and rendered into a single, industry-grade PWNDoc report (JSON / PDF / HTML), giving analysts instant visibility into threats, risk scores, and actionable recommendations.</span>
                        </p>
                    </div>
                </motion.div>

                <div className="grid md:grid-cols-2 gap-8">
                    <motion.div
                        variants={itemVariants}
                        className="soc-panel p-6"
                        style={{
                            boxShadow: '0 0 24px rgba(41, 197, 255, 0.08)',
                        }}
                    >
                        <h3 className="text-xl md:text-2xl font-mono text-neon-cyan mb-6 font-bold flex items-center gap-2">
                            <ChevronRight className="text-neon-blue" size={20} />
                            SecFlow helps identify
                        </h3>
                        <ul className="space-y-3">
                            {identifyItems.map((item, index) => (
                                <motion.li
                                    key={index}
                                    className="flex items-center gap-4 p-3 rounded-lg hover:bg-neon-blue/10 transition-all group cursor-pointer border border-transparent hover:border-neon-blue/20"
                                    whileHover={{ x: 8 }}
                                >
                                    <span className="text-neon-cyan p-2 rounded-md bg-neon-blue/10 group-hover:bg-neon-blue/20 transition-colors">
                                        <item.icon size={18} />
                                    </span>
                                    <span className="text-foreground/80 group-hover:text-foreground transition-colors">
                                        {item.text}
                                    </span>
                                </motion.li>
                            ))}
                        </ul>
                    </motion.div>

                    <motion.div
                        variants={itemVariants}
                        className="soc-panel p-6"
                        style={{
                            boxShadow: '0 0 24px rgba(34, 211, 238, 0.08)',
                        }}
                    >
                        <h3 className="text-xl md:text-2xl font-mono text-neon-blue mb-6 font-bold flex items-center gap-2">
                            <ChevronRight className="text-cyan-300" size={20} />
                            Built for
                        </h3>
                        <ul className="space-y-3">
                            {builtForItems.map((item, index) => (
                                <motion.li
                                    key={index}
                                    className="flex items-center gap-4 p-3 rounded-lg hover:bg-cyan-500/10 transition-all group cursor-pointer border border-transparent hover:border-cyan-500/20"
                                    whileHover={{ x: 8 }}
                                >
                                    <span className="text-cyan-300 p-2 rounded-md bg-cyan-500/10 group-hover:bg-cyan-500/20 transition-colors">
                                        <item.icon size={18} />
                                    </span>
                                    <span className="text-foreground/80 group-hover:text-foreground transition-colors">
                                        {item.text}
                                    </span>
                                </motion.li>
                            ))}
                        </ul>
                    </motion.div>
                </div>
            </motion.div>
        </section>
    )
}
