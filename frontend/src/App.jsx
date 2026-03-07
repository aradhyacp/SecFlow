import { HeroSection } from './components/sections/HeroSection'
import { IntroductionSection } from './components/sections/IntroductionSection'
import { ToolsOverviewSection } from './components/sections/ToolsOverviewSection'
import { FeaturesHighlightSection } from './components/sections/FeaturesHighlightSection'
import { OpenSourceSection } from './components/sections/OpenSourceSection'
import { CTASection } from './components/sections/CTASection'

function App() {
    return (
        <main className="overflow-hidden bg-background min-h-screen">
            <HeroSection />
            <IntroductionSection />
            <ToolsOverviewSection />
            <FeaturesHighlightSection />
            <OpenSourceSection />
            <CTASection />
        </main>
    )
}

export default App
