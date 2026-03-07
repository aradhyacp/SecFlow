import { motion, useInView } from 'framer-motion'
import { useRef } from 'react'
import { Link } from 'react-router-dom'
import { Button } from '../ui/Button'
import { Rocket, FileText, Zap } from 'lucide-react'

export function CTASection() {
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
            transition: { duration: 0.7, ease: [0.25, 0.46, 0.45, 0.94] },
        },
    }

    return (
        <section ref={ref} className="soc-section relative overflow-hidden bg-[#0c1120]">
            <div className="absolute inset-0">
                <div className="absolute inset-0 bg-gradient-to-b from-[#0c1120] via-[#10182b] to-[#0c1120]" />

                <motion.div
                    className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-neon-blue/14 rounded-full blur-[150px]"
                    animate={{
                        scale: [1, 1.3, 1],
                        opacity: [0.3, 0.5, 0.3],
                    }}
                    transition={{ duration: 6, repeat: Infinity, ease: 'easeInOut' }}
                />
                <motion.div
                    className="absolute top-1/3 left-1/4 w-[400px] h-[400px] bg-blue-500/12 rounded-full blur-[120px]"
                    animate={{
                        scale: [1, 1.4, 1],
                        opacity: [0.2, 0.4, 0.2],
                        x: [0, 50, 0],
                    }}
                    transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut', delay: 1 }}
                />
                <motion.div
                    className="absolute bottom-1/3 right-1/4 w-[350px] h-[350px] bg-cyan-500/10 rounded-full blur-[100px]"
                    animate={{
                        scale: [1, 1.2, 1],
                        opacity: [0.15, 0.3, 0.15],
                    }}
                    transition={{ duration: 7, repeat: Infinity, ease: 'easeInOut', delay: 2 }}
                />

                <svg className="absolute inset-0 w-full h-full opacity-10">
                    <defs>
                        <pattern id="cta-grid" width="60" height="60" patternUnits="userSpaceOnUse">
                            <path d="M 60 0 L 0 0 0 60" fill="none" stroke="#9aa9c2" strokeWidth="0.3" />
                        </pattern>
                    </defs>
                    <rect width="100%" height="100%" fill="url(#cta-grid)" />
                </svg>

                {[...Array(15)].map((_, i) => (
                    <motion.div
                        key={i}
                        className="absolute w-1 h-1 bg-neon-cyan rounded-full"
                        style={{
                            left: `${10 + (i * 6)}%`,
                            top: `${20 + (i * 5) % 60}%`,
                        }}
                        animate={{
                            y: [0, -40, 0],
                            opacity: [0, 1, 0],
                            scale: [0.5, 1.5, 0.5],
                        }}
                        transition={{
                            duration: 4 + i * 0.3,
                            repeat: Infinity,
                            delay: i * 0.2,
                        }}
                    />
                ))}
            </div>

            <motion.div
                className="absolute top-0 left-0 right-0 h-px"
                style={{
                    background: 'linear-gradient(90deg, transparent, rgba(148, 163, 184, 0.6), transparent)',
                }}
                animate={{
                    opacity: [0.5, 1, 0.5],
                }}
                transition={{ duration: 3, repeat: Infinity }}
            />

            <motion.div
                className="soc-section-inner max-w-5xl"
                variants={containerVariants}
                initial="hidden"
                animate={isInView ? 'visible' : 'hidden'}
            >
                <motion.div variants={itemVariants} className="soc-panel text-center px-5 py-12 md:px-10 md:py-16">
                    <div className="mb-8">
                    <motion.div
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-neon-blue/30 bg-neon-blue/10"
                        animate={{ boxShadow: ['0 0 20px rgba(41, 197, 255, 0.2)', '0 0 40px rgba(41, 197, 255, 0.3)', '0 0 20px rgba(41, 197, 255, 0.2)'] }}
                        transition={{ duration: 2, repeat: Infinity }}
                    >
                        <Zap className="w-4 h-4 text-cyan-300" />
                        <span className="text-neon-cyan font-mono text-sm">Ready to Deploy</span>
                    </motion.div>
                    </div>

                <motion.h2
                    variants={itemVariants}
                    className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold mb-6 text-foreground font-mono leading-tight"
                >
                    Ready to see what the
                </motion.h2>

                <motion.h2
                    variants={itemVariants}
                    className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold mb-12 font-mono"
                    style={{
                        background: 'linear-gradient(135deg, #73e6ff 0%, #29c5ff 50%, #60a5fa 100%)',
                        WebkitBackgroundClip: 'text',
                        WebkitTextFillColor: 'transparent',
                        textShadow: '0 0 80px rgba(41, 197, 255, 0.35)',
                    }}
                >
                    internet reveals?
                </motion.h2>

                <motion.div variants={itemVariants} className="flex flex-col sm:flex-row gap-6 justify-center mb-16">
                    <motion.div
                        whileHover={{ scale: 1.05, y: -4 }}
                        whileTap={{ scale: 0.95 }}
                    >
                        <Link to="/dashboard">
                            <Button variant="primary" className="relative overflow-hidden group text-lg px-12 py-6 !bg-neon-blue !text-[#041024] hover:!bg-neon-cyan shadow-[0_0_32px_rgba(41,197,255,0.3)]">
                                <motion.span
                                    className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700"
                                />
                                <motion.span
                                    className="absolute inset-0 bg-neon-blue/30"
                                    animate={{ opacity: [0, 0.5, 0] }}
                                    transition={{ duration: 2, repeat: Infinity }}
                                />
                                <span className="relative flex items-center gap-3">
                                    <Rocket size={22} />
                                    Launch SecFlow
                                </span>
                            </Button>
                        </Link>
                    </motion.div>

                    <motion.div
                        whileHover={{ scale: 1.05, y: -4 }}
                        whileTap={{ scale: 0.95 }}
                    >
                        <Link to="/docs">
                            <Button variant="outline" className="text-lg px-12 py-6 flex items-center gap-3 !border-neon-blue/35 !text-neon-cyan hover:!bg-neon-blue/10">
                                <FileText size={22} />
                                View Documentation
                            </Button>
                        </Link>
                    </motion.div>
                </motion.div>

                <motion.div variants={itemVariants} className="relative">
                    <motion.div
                        className="h-px w-full bg-gradient-to-r from-transparent via-neon-blue to-transparent"
                        animate={{ opacity: [0.3, 1, 0.3] }}
                        transition={{ duration: 3, repeat: Infinity }}
                    />

                    <motion.p
                        className="mt-8 font-mono text-foreground/40 text-sm"
                        animate={{ opacity: [0.4, 0.8, 0.4] }}
                        transition={{ duration: 4, repeat: Infinity }}
                    >
                        <span className="text-neon-cyan">$</span> SecFlow --version 1.0.0 | Built with ♥ for the security community
                    </motion.p>
                </motion.div>
                </motion.div>
            </motion.div>
        </section>
    )
}
