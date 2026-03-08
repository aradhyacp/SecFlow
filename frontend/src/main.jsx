import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './index.css'

// Layouts & Pages
import LandingPage from './pages/LandingPage'
import DashboardLayout from './layouts/DashboardLayout'
import OverviewPage from './pages/dashboard/OverviewPage'
import WebAnalysisPage from './pages/dashboard/WebAnalysisPage'
import MalwareAnalysisPage from './pages/dashboard/MalwareAnalysisPage'
import MacroAnalysisPage from './pages/dashboard/MacroAnalysisPage'
import StegAnalysisPage from './pages/dashboard/StegAnalysisPage'
import ReconGraphPage from './pages/dashboard/ReconGraphPage'
import SmartPipelinePage from './pages/dashboard/SmartPipelinePage'

// Docs
import DocsLayout from './layouts/DocsLayout'
import DocsHub from './pages/docs/DocsHub'
import WebDocs from './pages/docs/WebDocs'
import MalwareDocs from './pages/docs/MalwareDocs'
import MacroDocs from './pages/docs/MacroDocs'
import StegDocs from './pages/docs/StegDocs'
import ReconDocs from './pages/docs/ReconDocs'

createRoot(document.getElementById('root')).render(
    <StrictMode>
        <BrowserRouter>
            <Routes>
                <Route path="/" element={<LandingPage />} />

                {/* Dashboard Routes */}
                <Route path="/dashboard" element={<DashboardLayout />}>
                    <Route index element={<OverviewPage />} />
                    <Route path="smart-pipeline" element={<SmartPipelinePage />} />
                    <Route path="web" element={<WebAnalysisPage />} />
                    <Route path="malware" element={<MalwareAnalysisPage />} />
                    <Route path="macro" element={<MacroAnalysisPage />} />
                    <Route path="steg" element={<StegAnalysisPage />} />
                    <Route path="recon" element={<ReconGraphPage />} />
                    <Route path="settings" element={<div className="text-white p-8">Settings Panel (Placeholder)</div>} />
                </Route>

                {/* Documentation Routes */}
                <Route path="/docs" element={<DocsLayout />}>
                    <Route index element={<DocsHub />} />
                    <Route path="web-analyzer" element={<WebDocs />} />
                    <Route path="malware-analysis" element={<MalwareDocs />} />
                    <Route path="macro-analysis" element={<MacroDocs />} />
                    <Route path="steg-analysis" element={<StegDocs />} />
                    <Route path="recon-analysis" element={<ReconDocs />} />
                </Route>
            </Routes>
        </BrowserRouter>
    </StrictMode>,
)
