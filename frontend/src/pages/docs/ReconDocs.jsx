import { Radar, Search, UserCheck, Crosshair, AlertTriangle, AlertCircle, Globe, Shield } from 'lucide-react'

const Section = ({ title, icon: Icon, children }) => (
    <div className="mb-12">
        <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-neon-yellow/10 text-neon-yellow">
                <Icon size={20} />
            </div>
            <h2 className="text-2xl font-bold text-white">{title}</h2>
        </div>
        <div className="prose prose-invert prose-p:text-foreground/70 prose-headings:text-white max-w-none">
            {children}
        </div>
    </div>
)

export default function ReconDocs() {
    return (
        <div className="space-y-8">
            <div className="border-b border-white/10 pb-8">
                <h1 className="text-4xl font-bold text-white mb-4">Recon Analysis Documentation</h1>
                <p className="text-xl text-foreground/60">
                    Complete guide to Open Source Intelligence (OSINT) gathering, threat intelligence querying, and digital footprint investigation using SecFlow Recon Analyzer.
                </p>
            </div>

            <Section title="What is Reconnaissance?" icon={Radar}>
                <p>
                    Reconnaissance (Recon) is the first and most critical phase of any security assessment or investigation. The Recon Analyzer aggregates publicly available information from multiple sources to build comprehensive profiles of targets, including individuals, organizations, and infrastructure.
                </p>
                <p className="mt-3">
                    Unlike intrusive security testing, OSINT relies exclusively on public data: DNS records, WHOIS information, public databases, social media profiles, threat intelligence feeds, and more.
                </p>
                <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg my-6">
                    <div className="flex items-start gap-3">
                        <AlertCircle className="text-blue-400 mt-1 shrink-0" size={18} />
                        <div className="text-sm text-blue-300">
                            <strong>Legal Note:</strong> OSINT is entirely passive and uses only publicly available information. However, aggregating data for surveillance or unauthorized purposes may violate local laws. Always obtain proper authorization before conducting investigations on individuals or organizations.
                        </div>
                    </div>
                </div>
            </Section>

            <Section title="Analysis Modes" icon={Search}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Mode 1: Threat Intelligence (IP/Domain Scanning)</h3>
                <p>
                    Query infrastructure for threat indicators and reputation data:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">🌐 IP Address Intelligence</h4>
                        <ul className="list-disc pl-5 space-y-1 text-sm text-foreground/70">
                            <li>Geolocation (country, city, ISP)</li>
                            <li>Autonomous System Number (ASN)</li>
                            <li>Reverse DNS lookup</li>
                            <li>Hosting provider identification</li>
                            <li>ISP and organization details</li>
                        </ul>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">⚠️ Threat Indicators</h4>
                        <ul className="list-disc pl-5 space-y-1 text-sm text-foreground/70">
                            <li><strong>Cisco Talos:</strong> Blacklist status from major threat intel provider</li>
                            <li><strong>TOR Node Detection:</strong> Identifies Tor exit nodes</li>
                            <li><strong>ThreatFox:</strong> IOC (Indicator of Compromise) database</li>
                            <li><strong>Tranco Ranking:</strong> Website reputation and global ranking</li>
                        </ul>
                    </div>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Mode 2: Digital Footprint (Username/Email/Phone)</h3>
                <p>
                    Build profiles of individuals across the internet:
                </p>
                
                <h4 className="text-lg font-bold text-white mt-4 mb-2">📱 Username Search</h4>
                <p className="text-foreground/70">
                    Searches for a username across hundreds of social media platforms and websites:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>Social Networks:</strong> Facebook, Twitter, Instagram, TikTok, LinkedIn, Reddit</li>
                    <li><strong>Gaming Platforms:</strong> Steam, Epic Games, Twitch, Discord</li>
                    <li><strong>Professional Sites:</strong> GitHub, Stack Overflow, CodePen</li>
                    <li><strong>Other Services:</strong> Telegram, Medium, YouTube, Pinterest</li>
                    <li><strong>Results:</strong> Direct links to accounts where found (if username exists)</li>
                </ul>

                <h4 className="text-lg font-bold text-white mt-6 mb-2">📧 Email Address Search</h4>
                <p className="text-foreground/70">
                    Checks if an email has been compromised in known data breaches:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>Breach Detection:</strong> Identifies which data breaches exposed the email</li>
                    <li><strong>Breach Details:</strong> Name and date of the breach</li>
                    <li><strong>Exposed Data:</strong> What information was compromised (passwords, emails, credit cards, etc.)</li>
                    <li><strong>Risk Level:</strong> Assessment of threat based on breach severity</li>
                    <li><strong>Remediation:</strong> Recommendations for securing the account</li>
                </ul>

                <h4 className="text-lg font-bold text-white mt-6 mb-2">📞 Phone Number Search</h4>
                <p className="text-foreground/70">
                    Validates phone numbers and reveals carrier and location information:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>Validity Check:</strong> Is this a real, active phone number?</li>
                    <li><strong>Carrier Information:</strong> Cellular provider (Verizon, AT&T, T-Mobile, etc.)</li>
                    <li><strong>Line Type:</strong> Mobile, landline, VoIP, or virtual number</li>
                    <li><strong>Geographic Location:</strong> Country, state, and general location</li>
                    <li><strong>Risk Assessment:</strong> Flags potentially spoofed or fake numbers</li>
                </ul>
            </Section>

            <Section title="Data Sources & Intelligence Feeds" icon={Globe}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Threat Intelligence APIs</h3>
                <div className="space-y-3 my-4">
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">🛡️ Cisco Talos</h4>
                        <p className="text-sm text-foreground/70">One of the largest threat intelligence databases. Provides IP/domain reputation scores, malware detection, and blacklist status.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">🕷️ ThreatFox</h4>
                        <p className="text-sm text-foreground/70">Collaborative IOC (Indicator of Compromise) sharing platform from Abuse.ch. Contains known malware C2 servers, URLs, and hashes.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">📊 IPAPI/GeoIP</h4>
                        <p className="text-sm text-foreground/70">Geolocation and ASN data for IP addresses. Identifies hosting providers, ISPs, and geographic location.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">🌐 Tranco Ranking</h4>
                        <p className="text-sm text-foreground/70">Research-oriented ranking of top 1 million websites by popularity. Useful for assessing legitimacy of domains.</p>
                    </div>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Breach Databases & OSINT Sources</h3>
                <ul className="list-disc pl-5 space-y-1 text-foreground/70">
                    <li><strong>HaveIBeenPwned (HIBP):</strong> Largest email breach database with 10+ billion compromised records</li>
                    <li><strong>LinkedIn Breach Data:</strong> Contains exposed user profiles and contact information</li>
                    <li><strong>Facebook Breach Data:</strong> Phone numbers and user IDs from multiple Facebook breaches</li>
                    <li><strong>Public WHOIS Records:</strong> Domain registrant information (though often redacted)</li>
                    <li><strong>Public DNS Records:</strong> A, AAAA, MX, TXT, CNAME records</li>
                </ul>
            </Section>

            <Section title="Understanding Results" icon={Shield}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Risk Assessment Scoring</h3>
                <div className="space-y-3 my-4">
                    <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                        <h4 className="font-bold text-red-400 mb-1">🔴 HIGH RISK</h4>
                        <p className="text-sm text-red-200">IP is actively serving malware, phishing, or C2 commands. Email has been in multiple major breaches. Phone is likely compromised or spoofed.</p>
                    </div>
                    <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                        <h4 className="font-bold text-yellow-400 mb-1">🟡 MEDIUM RISK</h4>
                        <p className="text-sm text-yellow-200">IP has suspicious history but may not be actively malicious. Email was in 1-2 breaches. Phone is in breach databases.</p>
                    </div>
                    <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
                        <h4 className="font-bold text-green-400 mb-1">🟢 LOW RISK</h4>
                        <p className="text-sm text-green-200">IP appears clean in threat intel. Email not found in breaches. Phone is valid and non-suspicious.</p>
                    </div>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Common Findings & Interpretation</h3>
                <div className="space-y-3">
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">⚠️ Tor Exit Node Detected</h4>
                        <p className="text-sm text-foreground/70">The IP is a known Tor exit node. Legitimate for privacy but may indicate proxied traffic or attempts to mask origin.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">⚠️ Blacklisted IP</h4>
                        <p className="text-sm text-foreground/70">The IP is on Cisco Talos or other blacklists. Usually indicates spam hosting, botnet C2, or malware distribution.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">⚠️ Multiple Breaches</h4>
                        <p className="text-sm text-foreground/70">An email found in 3+ breaches indicates serious security risk. Passwords and sensitive data are likely compromised.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">⚠️ High Platform Presence</h4>
                        <p className="text-sm text-foreground/70">A username found on 10+ platforms may indicate oversharing or targeted account creation for sockpuppeting.</p>
                    </div>
                </div>
            </Section>

            <Section title="Legal & Ethical Guidelines" icon={AlertTriangle}>
                <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg mb-6">
                    <h4 className="font-bold text-yellow-500 mb-3">⚖️ Legal Disclaimer</h4>
                    <ul className="list-disc pl-5 space-y-2 text-sm text-yellow-200">
                        <li><strong>Authorization Required:</strong> Always obtain written permission before investigating any individual or organization</li>
                        <li><strong>Data Privacy Laws:</strong> Compliance with GDPR, CCPA, and local privacy regulations is your responsibility</li>
                        <li><strong>CFAA Compliance:</strong> In the US, unauthorized computer access violates the Computer Fraud and Abuse Act</li>
                        <li><strong>Not for Harassment:</strong> Do not use OSINT to stalk, harass, or dox individuals</li>
                        <li><strong>Professional Use:</strong> Use only for legitimate security research, incident response, and authorized pentesting</li>
                    </ul>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Responsible Disclosure</h3>
                <p className="text-foreground/70">
                    If you discover sensitive information or vulnerabilities during reconnaissance:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>Report findings to the affected organization directly</li>
                    <li>Follow responsible disclosure practices (90-day window)</li>
                    <li>Do not publish or sell the information</li>
                    <li>Respect privacy and do not contact affected individuals directly</li>
                </ul>
            </Section>
        </div>
    )
}
