import { motion, useInView } from 'framer-motion'
import { useRef } from 'react'
import { Github, Star, GitFork, ExternalLink } from 'lucide-react'

export function OpenSourceSection() {
    const ref = useRef(null)
    const isInView = useInView(ref, { once: true, margin: '-50px' })

    const containerVariants = {
        hidden: { opacity: 0 },
        visible: {
            opacity: 1,
            transition: {
                staggerChildren: 0.15,
            },
        },
    }

    const itemVariants = {
        hidden: { opacity: 0, y: 30 },
        visible: {
            opacity: 1,
            y: 0,
            transition: { duration: 0.6, ease: [0.25, 0.46, 0.45, 0.94] },
        },
    }

    return (
        <section ref={ref} className="soc-section relative overflow-hidden bg-[#0c1120]">
            <div className="absolute inset-0 bg-gradient-to-b from-[#0c1120] via-[#10182b] to-[#0c1120]" />

            <div className="absolute inset-0 overflow-hidden opacity-5">
                {[...Array(8)].map((_, i) => (
                    <motion.div
                        key={i}
                        className="absolute left-0 right-0 font-mono text-xs text-neon-blue whitespace-nowrap"
                        style={{ top: `${i * 12}%` }}
                        animate={{ x: ['-100%', '100%'] }}
                        transition={{ duration: 20 + i * 2, repeat: Infinity, ease: 'linear' }}
                    >
                        {`const security = new SecFlow(); await security.analyze(target); // MIT Licensed `.repeat(10)}
                    </motion.div>
                ))}
            </div>

            <motion.div
                className="soc-section-inner max-w-5xl text-center"
                variants={containerVariants}
                initial="hidden"
                animate={isInView ? 'visible' : 'hidden'}
            >
                <motion.div variants={itemVariants} className="mb-8">
                    <motion.div
                        className="inline-flex p-6 rounded-lg bg-white/[0.03] border border-white/[0.1]"
                        whileHover={{
                            scale: 1.1,
                            boxShadow: '0 0 30px rgba(255, 255, 255, 0.1)',
                            borderColor: 'rgba(255, 255, 255, 0.2)'
                        }}
                    >
                        <Github className="w-12 h-12 text-foreground" />
                    </motion.div>
                </motion.div>

                <motion.span variants={itemVariants} className="soc-kicker mb-4">
                    Community Driven
                </motion.span>

                <motion.h2
                    variants={itemVariants}
                    className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold mb-8 text-foreground font-mono"
                >
                    Open Source &{' '}
                    <span className="text-neon-blue" style={{ textShadow: '0 0 40px rgba(41, 197, 255, 0.35)' }}>
                        Trust
                    </span>
                </motion.h2>

                <motion.p
                    variants={itemVariants}
                    className="text-lg md:text-xl text-foreground/70 mb-12 leading-relaxed max-w-2xl mx-auto"
                >
                    SecFlow embraces transparency and community-driven security tooling.
                    Parts of the platform are open-source and MIT licensed.
                    Source code and self-hosting documentation are available on GitHub.
                </motion.p>

                <motion.div variants={itemVariants} className="flex flex-wrap justify-center gap-4 mb-12">
                    {[
                        { icon: Star, label: 'Star on GitHub', value: 'Show Support', link: null },
                        { icon: GitFork, label: 'Fork & Contribute', value: 'Join Us', link: null },
                        { icon: ExternalLink, label: 'Documentation', value: 'Learn More', link: '/docs' },
                    ].map((item, i) => (
                        <motion.button
                            key={i}
                            onClick={() => item.link && (window.location.href = item.link)}
                            className="soc-panel-muted flex items-center gap-3 px-6 py-4 hover:bg-white/[0.06] hover:border-neon-blue/30 transition-all group"
                            whileHover={{ y: -4, scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                        >
                            <item.icon size={20} className="text-neon-cyan group-hover:scale-110 transition-transform" />
                            <div className="text-left">
                                <div className="text-foreground/60 text-xs">{item.label}</div>
                                <div className="text-foreground font-mono text-sm">{item.value}</div>
                            </div>
                        </motion.button>
                    ))}
                </motion.div>

                <motion.div
                    variants={itemVariants}
                    className="soc-panel relative p-8 overflow-hidden inline-block"
                    style={{
                        boxShadow: '0 0 32px rgba(41, 197, 255, 0.12)',
                    }}
                    whileHover={{
                        scale: 1.02,
                        boxShadow: '0 0 50px rgba(41, 197, 255, 0.24)',
                    }}
                >
                    <p className="text-neon-cyan font-mono font-bold text-lg md:text-xl max-w-lg">
                        "If you find SecFlow useful, consider supporting its development."
                    </p>
                </motion.div>
            </motion.div>
        </section>
    )
}
