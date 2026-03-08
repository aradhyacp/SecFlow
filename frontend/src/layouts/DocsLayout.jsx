import { useState } from 'react'
import { Outlet, NavLink, Link } from 'react-router-dom'
import { Book, Globe, Bug, FileCode, Radar, Eye, ArrowLeft, Menu, ChevronRight } from 'lucide-react'

const DocLink = ({ to, icon: Icon, label }) => (
    <NavLink
        to={to}
        end
        className={({ isActive }) => `
            flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 group
            ${isActive
                ? 'bg-gradient-to-r from-neon-blue/20 to-neon-cyan/10 text-white border border-neon-blue/35 shadow-[0_0_20px_rgba(41,197,255,0.12)]'
                : 'text-foreground/60 hover:text-foreground hover:bg-white/[0.04]'
            }
        `}
    >
        <Icon size={18} />
        <span className="font-mono text-sm">{label}</span>
        <ChevronRight size={14} className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
    </NavLink>
)

export default function DocsLayout() {
    const [sidebarOpen, setSidebarOpen] = useState(false)

    return (
        <div className="min-h-screen bg-[#071022] text-foreground font-sans selection:bg-neon-blue/25">

            {/* Background Elements */}
            <div className="fixed inset-0 pointer-events-none z-0">
                <div className="absolute top-0 right-0 w-[520px] h-[520px] bg-neon-blue/10 rounded-full blur-[130px]" />
                <div className="absolute bottom-0 left-0 w-[520px] h-[520px] bg-neon-cyan/10 rounded-full blur-[130px]" />
            </div>

            {/* Sidebar (Desktop: Fixed, Mobile: Overlay) */}
            <aside className={`
                fixed top-0 bottom-0 left-0 z-40 w-72 bg-[#08142e]/95 backdrop-blur-xl border-r border-white/[0.08]
                transition-transform duration-300 transform
                ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
            `}>
                <div className="h-full flex flex-col p-6">
                    {/* Header */}
                    <Link to="/" className="flex items-center gap-3 mb-10 group">
                        <div className="w-8 h-8 rounded bg-neon-blue/15 border border-neon-blue/30 flex items-center justify-center text-neon-cyan font-mono font-bold text-xl group-hover:scale-110 transition-transform">
                            S
                        </div>
                        <span className="font-mono font-bold text-xl tracking-wider text-white">
                            Sec<span className="text-neon-blue">Flow</span>
                            <span className="text-xs text-foreground/40 ml-2">DOCS</span>
                        </span>
                    </Link>

                    {/* Navigation */}
                    <div className="space-y-2 flex-1 overflow-y-auto custom-scrollbar">
                        <div className="mb-6">
                            <div className="text-xs font-mono text-foreground/40 uppercase mb-3 px-4">Platform</div>
                            <DocLink to="/docs" icon={Book} label="Overview & Hub" />
                        </div>

                        <div>
                            <div className="text-xs font-mono text-foreground/40 uppercase mb-3 px-4">Tools</div>
                            <DocLink to="/docs/web-analyzer" icon={Globe} label="Web Analysis" />
                            <DocLink to="/docs/malware-analysis" icon={Bug} label="Malware Analysis" />
                            <DocLink to="/docs/macro-analysis" icon={FileCode} label="Macro Analysis" />
                            <DocLink to="/docs/steg-analysis" icon={Eye} label="Steg Analysis" />
                            <DocLink to="/docs/recon-analysis" icon={Radar} label="Recon Analysis" />
                        </div>
                    </div>

                    {/* Footer */}
                    <div className="pt-6 border-t border-white/[0.08]">
                        <Link to="/dashboard">
                            <button className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-neon-blue/20 to-neon-cyan/10 border border-neon-blue/30 text-neon-cyan font-mono text-sm hover:from-neon-blue/30 transition-all flex items-center justify-center gap-2 group">
                                <ArrowLeft size={16} className="group-hover:-translate-x-1 transition-transform" />
                                Back to Dashboard
                            </button>
                        </Link>
                    </div>
                </div>
            </aside>

            {/* Mobile Sidebar Toggle */}
            <button
                onClick={() => setSidebarOpen(true)}
                className="lg:hidden fixed top-4 right-4 z-50 p-2 bg-[#08142e]/80 border border-neon-blue/30 rounded-lg text-neon-cyan"
            >
                <Menu size={24} />
            </button>
            {sidebarOpen && (
                <div className="fixed inset-0 z-30 bg-black/80 lg:hidden" onClick={() => setSidebarOpen(false)} />
            )}

            {/* Main Content */}
            <main className={`
                transition-all duration-300 min-h-screen
                lg:pl-72
            `}>
                <div className="max-w-5xl mx-auto px-4 md:px-6 py-10 lg:py-14">
                    <div className="soc-panel-muted mb-6 px-4 py-3 flex flex-wrap items-center justify-between gap-2">
                        <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-foreground/40">Documentation Console</span>
                        <span className="soc-chip">Operational Knowledge Base</span>
                    </div>
                    <Outlet />
                </div>
            </main>
        </div>
    )
}
