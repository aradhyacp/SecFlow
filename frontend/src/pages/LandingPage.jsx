import { Link } from 'react-router-dom'
import { Shield, FileText, LayoutGrid } from 'lucide-react'
import { IntroductionSection } from '../components/sections/IntroductionSection'
import { HeroSection } from '../components/sections/HeroSection'
import { ToolsOverviewSection } from '../components/sections/ToolsOverviewSection'
import { FeaturesHighlightSection } from '../components/sections/FeaturesHighlightSection'
import { OpenSourceSection } from '../components/sections/OpenSourceSection'
import { CTASection } from '../components/sections/CTASection'

export default function LandingPage() {
    return (
        <div className="soc-shell">
            <header className="sticky top-3 z-40 px-2 md:px-3">
                <div className="soc-command-bar flex flex-col gap-3 px-4 py-3 md:flex-row md:items-center md:px-5">
                    <div className="flex items-center gap-3 md:w-[260px] md:shrink-0">
                        <div className="w-9 h-9 rounded-md bg-neon-blue/15 border border-neon-blue/35 flex items-center justify-center text-neon-cyan font-mono font-bold text-lg">
                            S
                        </div>
                        <div>
                            <div className="text-white font-mono font-semibold text-lg tracking-wide">Sec<span className="text-neon-blue">Flow</span></div>
                            <div className="text-[10px] text-foreground/35 font-mono uppercase tracking-[0.2em]">SOC Threat Analysis Console</div>
                        </div>
                    </div>

                    <nav className="flex items-center flex-wrap gap-2 text-[11px] font-mono text-foreground/60 md:flex-1 md:justify-center">
                        <a href="#about" className="soc-nav-button">About</a>
                        <a href="#tools" className="soc-nav-button">Tools</a>
                        <a href="#checks" className="soc-nav-button">Checks</a>
                        <a href="#community" className="soc-nav-button">Community</a>
                    </nav>

                    <div className="flex items-center gap-2 md:w-[260px] md:shrink-0 md:justify-end">
                        <Link to="/docs" className="soc-nav-button"><FileText size={12} /> Docs</Link>
                        <Link to="/dashboard" className="soc-nav-button"><LayoutGrid size={12} /> Dashboard</Link>
                    </div>
                </div>
            </header>

            <main>
                <HeroSection />
                <div id="about">
                    <IntroductionSection />
                </div>
                <ToolsOverviewSection />
                <div id="checks">
                    <FeaturesHighlightSection />
                </div>
                <div id="community">
                    <OpenSourceSection />
                </div>
                <CTASection />
            </main>

            <footer className="py-8 px-4">
                <div className="soc-panel max-w-6xl mx-auto px-6 py-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-sm">
                    <p className="text-foreground/40">© 2026 SecFlow Platform. All rights reserved.</p>
                    <p className="text-foreground/30 font-mono text-xs flex items-center gap-2"><Shield size={12} /> Built for SOC teams and security researchers</p>
                </div>
            </footer>
        </div>
    )
}
