import { motion, useInView } from 'framer-motion'
import { useRef } from 'react'
import { Check } from 'lucide-react'

const features = [
    // Column 1
    ['Archive History', 'Block List Check', 'Carbon Footprint', 'Cookies', 'DNS Server', 'DNS Records', 'Reverse Engineering', 'File Hash Analysis', 'API Key Detection', 'Redirect Chains'],
    // Column 2
    ['DNSSEC', 'Site Features', 'Firewall Types', 'Get IP Address', 'Headers', 'HSTS', 'HTTP Security', 'Username OSINT', 'Email Breach Check', 'Phone Validation'],
    // Column 3
    ['Linked Pages', 'Mail Config', 'Open Ports', 'Quality Check', 'Global Rank', 'Redirects', 'Robots.txt', 'Steghide Detection', 'Binwalk Extraction', 'EXIF Metadata'],
    // Column 4
    ['Screenshot', 'Security.txt', 'Sitemap', 'Social Tags', 'SSL Certificate', 'Uptime Status', 'Tech Stack', 'TOR Exit Detection', 'Blacklist Check', 'Threat Intelligence'],
    // Column 5
    ['Known Threats', 'TLS Version', 'Trace Route', 'TXT Records', 'Whois Lookup', 'VirusTotal Scan', 'Sandbox Analysis', 'Ghidra Decompile', 'Flow Diagrams', 'AI Summary'],
]

export function FeaturesHighlightSection() {
    const ref = useRef(null)
    const isInView = useInView(ref, { once: true, margin: '-50px' })

    const containerVariants = {
        hidden: { opacity: 0 },
        visible: {
            opacity: 1,
            transition: {
                staggerChildren: 0.02,
                delayChildren: 0.2,
            },
        },
    }

    const itemVariants = {
        hidden: { opacity: 0, y: 10 },
        visible: {
            opacity: 1,
            y: 0,
            transition: { duration: 0.4 },
        },
    }

    return (
        <section ref={ref} className="soc-section relative overflow-hidden bg-[#0c1120]">
            <div className="absolute inset-0 bg-gradient-to-b from-[#0c1120] via-[#10182b] to-[#0c1120]" />

            <motion.div
                className="soc-section-inner max-w-6xl"
                variants={containerVariants}
                initial="hidden"
                animate={isInView ? 'visible' : 'hidden'}
            >
                <motion.div className="text-center mb-12" variants={itemVariants}>
                    <span className="soc-kicker mb-4">Capability Matrix</span>
                    <p className="text-lg md:text-xl text-foreground/80">
                        With over <span className="text-neon-blue font-bold">50 supported checks</span> you can view and analyse key
                    </p>
                    <p className="text-lg md:text-xl text-foreground/80">
                        information in an instant
                    </p>
                </motion.div>

                <motion.div
                    className="w-16 h-0.5 bg-white/20 mx-auto mb-12"
                    variants={itemVariants}
                />

                <motion.div
                    className="soc-panel grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-x-8 gap-y-3 mb-12 p-5"
                    variants={containerVariants}
                >
                    {features.map((column, colIndex) => (
                        <div key={colIndex} className="space-y-3">
                            {column.map((feature, featureIndex) => (
                                <motion.div
                                    key={featureIndex}
                                    variants={itemVariants}
                                    className={`flex items-center gap-2 group cursor-pointer ${featureIndex >= 5 ? 'hidden md:flex' : ''
                                        } ${featureIndex >= 7 ? 'hidden lg:flex' : ''}`}
                                    whileHover={{ x: 4 }}
                                >
                                    <Check
                                        size={16}
                                        className="text-neon-cyan flex-shrink-0 group-hover:scale-110 transition-transform"
                                    />
                                    <span className="text-foreground/80 text-sm group-hover:text-foreground transition-colors">
                                        {feature}
                                    </span>
                                </motion.div>
                            ))}
                        </div>
                    ))}
                </motion.div>
            </motion.div>
        </section>
    )
}

