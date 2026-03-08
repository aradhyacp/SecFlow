import { useState } from 'react'
import { motion } from 'framer-motion'
import { Outlet, NavLink, useLocation, Link } from 'react-router-dom'
import {
    LayoutDashboard,
    Globe,
    Bug,
    FileCode,
    Eye,
    Radar,
    Menu,
    PanelRightClose,
    Workflow
} from 'lucide-react'

const SidebarItem = ({ to, icon: Icon, label, collapsed, end }) => (
    <NavLink
        to={to}
        end={end}
        className={({ isActive }) => `
      flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-300 group relative border
      ${isActive
                ? 'bg-gradient-to-r from-neon-blue/20 to-neon-cyan/10 text-white border-neon-blue/40 shadow-[0_0_22px_rgba(41,197,255,0.16)]'
                : 'text-foreground/60 hover:text-foreground hover:bg-white/[0.03] border-transparent hover:border-white/[0.08]'
            }
    `}
    >
        {({ isActive }) => (
            <>
                <Icon size={19} className="stroke-[1.6]" />
                {!collapsed && (
                    <span className="font-mono text-sm tracking-wide">{label}</span>
                )}
                {isActive && !collapsed && (
                    <motion.div
                        layoutId="active-pill"
                        className="absolute left-0 w-1 h-8 bg-neon-blue rounded-r-full"
                    />
                )}
            </>
        )}
    </NavLink>
)

export default function DashboardLayout() {
    const [collapsed, setCollapsed] = useState(false)
    const location = useLocation()
    const sectionBadge = location.pathname
        .replace('/dashboard/', '')
        .replace('/dashboard', 'overview')
        .replace(/-/g, ' ')

    const getPageTitle = () => {
        switch (location.pathname) {
            case '/dashboard': return 'Overview'
            case '/dashboard/smart-pipeline': return 'Smart Pipeline'
            case '/dashboard/web': return 'Web Analysis'
            case '/dashboard/malware': return 'Malware Analysis'
            case '/dashboard/macro': return 'Macro Analysis'
            case '/dashboard/steg': return 'Steg Analysis'
            case '/dashboard/recon': return 'Recon Analysis'
            case '/dashboard/settings': return 'Settings'
            default: return 'Dashboard'
        }
    }

    return (
        <div className="min-h-screen bg-[#071022] flex text-foreground overflow-hidden font-sans">
            {/* Sidebar */}
            <motion.aside
                initial={false}
                className={`relative z-20 flex flex-col border-r border-white/[0.07] bg-[#08142e]/85 backdrop-blur-xl h-screen transition-all duration-300 ease-in-out ${collapsed ? 'w-20' : 'w-72'}`}
            >
                <div className="absolute inset-y-0 right-0 w-px bg-gradient-to-b from-transparent via-neon-blue/35 to-transparent" />

                {/* Logo */}
                <div className="h-16 flex items-center px-6 border-b border-white/[0.07]">
                    <Link to="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
                        <div className="w-8 h-8 rounded bg-neon-blue/15 border border-neon-blue/30 flex items-center justify-center text-neon-cyan font-mono font-bold text-xl">
                            S
                        </div>
                        {!collapsed && (
                            <div>
                                <span className="font-mono font-bold text-xl tracking-wider text-white">
                                    Sec<span className="text-neon-blue">Flow</span>
                                </span>
                                <p className="text-[10px] text-foreground/35 font-mono tracking-widest uppercase">SOC Console</p>
                            </div>
                        )}
                    </Link>
                </div>

                {/* Navigation */}
                <nav className="flex-1 py-6 px-3 space-y-2 overflow-y-auto">
                    <SidebarItem to="/dashboard" icon={LayoutDashboard} label="Overview" collapsed={collapsed} end />
                    <div className="my-4 h-px bg-white/[0.08] mx-2" />
                    {!collapsed && <div className="text-[10px] font-mono text-foreground/30 uppercase tracking-wider px-4 mb-2">Main</div>}
                    <SidebarItem to="/dashboard/smart-pipeline" icon={Workflow} label="Smart Pipeline" collapsed={collapsed} />
                    <div className="my-4 h-px bg-white/[0.08] mx-2" />
                    {!collapsed && <div className="text-[10px] font-mono text-foreground/30 uppercase tracking-wider px-4 mb-2">Analyzers</div>}
                    <SidebarItem to="/dashboard/web" icon={Globe} label="Web Analysis" collapsed={collapsed} />
                    <SidebarItem to="/dashboard/malware" icon={Bug} label="Malware Analysis" collapsed={collapsed} />
                    <SidebarItem to="/dashboard/macro" icon={FileCode} label="Macro Analysis" collapsed={collapsed} />
                    <SidebarItem to="/dashboard/steg" icon={Eye} label="Steg Analysis" collapsed={collapsed} />
                    <SidebarItem to="/dashboard/recon" icon={Radar} label="Recon Analysis" collapsed={collapsed} />
                </nav>

                {/* Bottom Actions */}
                <div className="p-3 border-t border-white/[0.07]">
                    <button
                        onClick={() => setCollapsed(!collapsed)}
                        className="w-full mt-2 flex items-center justify-center p-2 text-foreground/40 hover:text-foreground rounded-lg hover:bg-white/[0.03] transition-colors"
                    >
                        {collapsed ? <Menu size={20} /> : <div className="flex items-center gap-2 text-xs font-mono uppercase"><PanelRightClose size={14} /> Collapse Sidebar</div>}
                    </button>
                </div>
            </motion.aside>

            {/* Main Content */}
            <main className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden relative">
                {/* Background Gradients */}
                <div className="absolute inset-0 z-0 pointer-events-none">
                    <div className="absolute top-0 left-0 w-full h-[520px] bg-gradient-to-b from-[#0e1c42] to-transparent opacity-45" />
                    <div className="absolute top-[-220px] right-[-160px] w-[640px] h-[640px] bg-neon-blue/10 rounded-full blur-[170px]" />
                    <div className="absolute bottom-[-180px] left-[-160px] w-[560px] h-[560px] bg-neon-cyan/8 rounded-full blur-[170px]" />
                </div>

                {/* Top Bar */}
                <header className="h-[72px] flex items-center justify-between px-5 md:px-8 border-b border-white/[0.08] bg-[#08142e]/70 backdrop-blur-md relative z-10">
                    <div className="flex items-center gap-4">
                        <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                            <span className="text-neon-blue">/</span>
                            {getPageTitle()}
                        </h1>
                        <span className="hidden md:inline-flex px-2.5 py-1 rounded-full border border-neon-blue/30 bg-neon-blue/10 text-neon-cyan text-[10px] font-mono uppercase tracking-widest">
                            SOC Operations
                        </span>
                    </div>

                    <div className="flex items-center gap-3">
                        <span className="text-[11px] text-foreground/45 font-mono uppercase tracking-wider">{sectionBadge}</span>
                        <span className="hidden lg:inline-flex px-2 py-1 rounded-full border border-white/[0.1] bg-white/[0.03] text-[10px] font-mono text-foreground/55 uppercase tracking-wider">Aligned Workspace</span>
                    </div>
                </header>

                {/* Content Scroll Area */}
                <div className="flex-1 overflow-y-auto overflow-x-hidden p-4 md:p-8 relative z-10 custom-scrollbar">
                    <div className="w-full max-w-[1240px] mx-auto">
                        <Outlet />
                    </div>
                </div>
            </main>
        </div>
    )
}
