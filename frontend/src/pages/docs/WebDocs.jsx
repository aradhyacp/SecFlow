import { Globe, Shield, Activity, Share2, Info, AlertCircle } from 'lucide-react'

const Section = ({ title, icon: Icon, children }) => (
    <div className="mb-12">
        <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-neon-green/10 text-neon-green">
                <Icon size={20} />
            </div>
            <h2 className="text-2xl font-bold text-white">{title}</h2>
        </div>
        <div className="prose prose-invert prose-p:text-foreground/70 prose-headings:text-white max-w-none">
            {children}
        </div>
    </div>
)

export default function WebDocs() {
    return (
        <div className="space-y-8">
            <div className="border-b border-white/10 pb-8">
                <h1 className="text-4xl font-bold text-white mb-4">Web Analysis Documentation</h1>
                <p className="text-xl text-foreground/60">
                    Comprehensive guide to analyzing websites, infrastructure, security posture, and digital footprints using SecFlow Web Analyzer.
                </p>
            </div>

            <Section title="What is Web Analysis?" icon={Globe}>
                <p>
                    Web Analysis is a reconnaissance and security assessment tool that gathers comprehensive intelligence about target websites and their infrastructure. It performs passive, non-intrusive analysis by querying publicly available data sources and APIs to construct a complete picture of a website's:
                </p>
                <ul className="list-disc pl-5 mt-3 space-y-2 text-foreground/70">
                    <li><strong>Infrastructure:</strong> Hosting providers, IP addresses, geographic locations</li>
                    <li><strong>Security Posture:</strong> SSL/TLS certificates, security headers, misconfigurations</li>
                    <li><strong>Technology Stack:</strong> Web servers, frameworks, content management systems</li>
                    <li><strong>Domain Information:</strong> DNS records, subdomains, domain history</li>
                    <li><strong>Public Reputation:</strong> Rankings, blacklist status, threat intelligence</li>
                </ul>
                <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg my-6">
                    <div className="flex items-start gap-3">
                        <Info className="text-blue-400 mt-1 shrink-0" size={18} />
                        <div className="text-sm text-blue-300">
                            <strong>Privacy Note:</strong> All analysis is passive and uses only publicly available information. The analyzer does not perform active scanning, port enumeration, or any intrusive techniques. It mimics the behavior of standard web browsers and search engine crawlers.
                        </div>
                    </div>
                </div>
            </Section>

            <Section title="Core Features" icon={Shield}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">SSL/TLS Certificate Analysis</h3>
                <p>
                    The analyzer inspects the SSL/TLS certificates deployed on the target website, including:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>Certificate Validity:</strong> Check if the certificate is valid and not expired</li>
                    <li><strong>Certificate Authority:</strong> Identify the issuing CA and their reputation</li>
                    <li><strong>Certificate Chain:</strong> Verify the complete chain of trust</li>
                    <li><strong>Common Name & SANs:</strong> Validate domain names covered by the certificate</li>
                    <li><strong>Key Size & Algorithm:</strong> Ensure strong cryptography (RSA-2048+, ECDSA-256+)</li>
                    <li><strong>TLS Version:</strong> Check for TLS 1.2+ support and disable of legacy SSLv3, TLS 1.0/1.1</li>
                    <li><strong>Cipher Suites:</strong> Analyze supported ciphers for weakness or vulnerabilities</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Security Headers Assessment</h3>
                <p>
                    HTTP security headers provide critical protection against common web vulnerabilities. SecFlow checks for:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">HSTS (Strict-Transport-Security)</h4>
                        <p className="text-sm text-foreground/70">Enforces HTTPS-only communication and prevents downgrade attacks. Expects values like <code className="bg-white/10 px-1 rounded text-neon-yellow text-xs">max-age=31536000</code></p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">CSP (Content-Security-Policy)</h4>
                        <p className="text-sm text-foreground/70">Controls which resources can be loaded, preventing XSS attacks and unauthorized code injection.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">X-Frame-Options</h4>
                        <p className="text-sm text-foreground/70">Prevents clickjacking attacks by restricting framing. Recommended value: <code className="bg-white/10 px-1 rounded text-neon-yellow text-xs">DENY</code></p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">X-Content-Type-Options</h4>
                        <p className="text-sm text-foreground/70">Prevents MIME-type sniffing. Should be set to <code className="bg-white/10 px-1 rounded text-neon-yellow text-xs">nosniff</code></p>
                    </div>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">DNS & Domain Intelligence</h3>
                <p>
                    The analyzer retrieves and analyzes DNS records for the target domain:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>A Records:</strong> IPv4 addresses pointing to the website</li>
                    <li><strong>AAAA Records:</strong> IPv6 addresses for modern protocol support</li>
                    <li><strong>MX Records:</strong> Mail server configuration and routing</li>
                    <li><strong>NS Records:</strong> Authoritative nameservers for the domain</li>
                    <li><strong>TXT Records:</strong> SPF, DKIM, DMARC settings for email security</li>
                    <li><strong>SOA Record:</strong> Start of Authority details and DNS configuration</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Technology Detection</h3>
                <p>
                    SecFlow identifies the technologies powering the website, including:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>Web servers (Apache, Nginx, IIS, etc.)</li>
                    <li>Content management systems (WordPress, Drupal, etc.)</li>
                    <li>Front-end frameworks (React, Vue, Angular)</li>
                    <li>Server-side languages (PHP, Python, Node.js, Java)</li>
                    <li>JavaScript libraries and CDNs</li>
                    <li>Hosting providers and cloud platforms</li>
                </ul>
            </Section>

            <Section title="Network & Infrastructure Analysis" icon={Share2}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">IP Geolocation & ASN Information</h3>
                <p>
                    The analyzer provides detailed information about the hosting infrastructure:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>IP Address:</strong> The public IP hosting the website</li>
                    <li><strong>Autonomous System Number (ASN):</strong> The network operator's unique identifier</li>
                    <li><strong>Country & City:</strong> Geographic location based on IP delegation data</li>
                    <li><strong>ISP/Organization:</strong> Internet Service Provider or hosting company name</li>
                    <li><strong>Latitude/Longitude:</strong> Precise geolocation coordinates</li>
                    <li><strong>Time Zone:</strong> Local time zone of the data center</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Reverse DNS & Email Configuration</h3>
                <p>
                    Understanding email infrastructure is critical for security:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>SPF (Sender Policy Framework):</strong> Prevents email spoofing by authorizing mail servers</li>
                    <li><strong>DKIM (DomainKeys Identified Mail):</strong> Digitally signs outgoing emails</li>
                    <li><strong>DMARC (Domain Message Authentication Reporting Conformance):</strong> Policy for handling unauthenticated emails</li>
                    <li><strong>Reverse DNS:</strong> Hostname associated with the IP address</li>
                </ul>
            </Section>

            <Section title="Domain Reputation & Ranking" icon={Activity}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Web Traffic Rankings</h3>
                <p>
                    The analyzer queries popular ranking services to assess a domain's popularity and legitimacy:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>Global Rank:</strong> Position in global top 1 million websites (based on Tranco/Alexa data)</li>
                    <li><strong>Category Rank:</strong> Ranking within specific verticals (news, business, shopping, etc.)</li>
                    <li><strong>Traffic Estimation:</strong> Estimated monthly visitors and page views</li>
                    <li><strong>Backlink Count:</strong> Number of external sites linking to the domain</li>
                    <li><strong>Domain Authority:</strong> Overall trust and authority score</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Blacklist & Threat Status</h3>
                <p>
                    Critical for identifying potentially malicious or compromised websites:
                </p>
                <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg my-4">
                    <h4 className="font-bold text-red-400 mb-2">🚨 Red Flags</h4>
                    <ul className="list-disc pl-5 space-y-1 text-sm text-red-200">
                        <li>Listed on Google Safe Browsing (phishing, malware, unwanted software)</li>
                        <li>Flagged by Norton Safe Web or AVG as unsafe</li>
                        <li>Spam hosting or malware distribution blacklists</li>
                        <li>High phishing similarity scores</li>
                    </ul>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Site Map & Crawlability</h3>
                <p>
                    SEO and search engine visibility indicators:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>Robots.txt:</strong> Search engine crawling instructions and disallowed paths</li>
                    <li><strong>Sitemap.xml:</strong> XML sitemap for search engine indexing</li>
                    <li><strong>Canonical URLs:</strong> Duplicate content resolution</li>
                    <li><strong>Crawlability Score:</strong> How easily search engines can index the site</li>
                </ul>
            </Section>

            <Section title="Understanding Results" icon={Shield}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Security Score Interpretation</h3>
                <p>
                    The overall security score is calculated based on multiple factors:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 my-4">
                    <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                        <h4 className="font-bold text-green-400 mb-2">EXCELLENT (90-100)</h4>
                        <p className="text-sm text-green-200">Strong SSL/TLS, comprehensive security headers, good reputation, no blacklist flags.</p>
                    </div>
                    <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                        <h4 className="font-bold text-yellow-400 mb-2">GOOD (70-89)</h4>
                        <p className="text-sm text-yellow-200">Valid HTTPS, some security headers missing, generally trusted by security vendors.</p>
                    </div>
                    <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                        <h4 className="font-bold text-red-400 mb-2">POOR (&lt;70)</h4>
                        <p className="text-sm text-red-200">Weak SSL, missing critical headers, reputation issues, or blacklist presence.</p>
                    </div>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Common Issues & Remediation</h3>
                <div className="space-y-3">
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">⚠️ Missing HSTS Header</h4>
                        <p className="text-sm text-foreground/70 mb-2">Vulnerability: Browsers can be tricked into using unencrypted HTTP</p>
                        <p className="text-sm text-foreground/60 italic">Fix: Add <code className="bg-white/10 px-1 rounded">Strict-Transport-Security: max-age=31536000; includeSubDomains</code> header</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">⚠️ Weak TLS Version</h4>
                        <p className="text-sm text-foreground/70 mb-2">Vulnerability: TLS 1.0/1.1 are vulnerable to known attacks (BEAST, Poodle)</p>
                        <p className="text-sm text-foreground/60 italic">Fix: Upgrade to TLS 1.2 or higher; disable older protocols in server configuration</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">⚠️ Self-Signed Certificate</h4>
                        <p className="text-sm text-foreground/70 mb-2">Vulnerability: Not trusted by browsers, users get warnings, enables MITM attacks</p>
                        <p className="text-sm text-foreground/60 italic">Fix: Obtain certificate from trusted CA (Let's Encrypt is free); use proper domain validation</p>
                    </div>
                </div>
            </Section>

            <Section title="API & Technical Details" icon={AlertCircle}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Data Sources & Integration</h3>
                <p>
                    The Web Analyzer integrates data from multiple trusted sources:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li><strong>SSL Labs:</strong> Certificate analysis and TLS configuration grading</li>
                    <li><strong>BuiltWith:</strong> Technology detection and web framework identification</li>
                    <li><strong>Google Safe Browsing:</strong> Malware and phishing detection</li>
                    <li><strong>WHOIS/IPWHOIS:</strong> Domain and IP registration information</li>
                    <li><strong>MaxMind GeoIP:</strong> IP geolocation and ASN data</li>
                    <li><strong>Tranco/Alexa:</strong> Website rankings and traffic statistics</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Rate Limiting & Performance</h3>
                <p>
                    The analyzer respects rate limits and caches results to ensure reliability:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>Typical analysis completes in 5-30 seconds depending on target complexity</li>
                    <li>Results are cached for 24 hours to reduce redundant API calls</li>
                    <li>Concurrent analyses are rate-limited to prevent service overload</li>
                    <li>Failed APIs gracefully degrade while still providing useful data</li>
                </ul>
            </Section>
        </div>
    )
}
