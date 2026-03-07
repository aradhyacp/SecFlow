import { Eye, FileCode, Lock, Layers, Zap, AlertCircle, Shield, Database } from 'lucide-react'

const Section = ({ title, icon: Icon, children }) => (
    <div className="mb-12">
        <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
                <Icon size={20} />
            </div>
            <h2 className="text-2xl font-bold text-white">{title}</h2>
        </div>
        <div className="prose prose-invert prose-p:text-foreground/70 prose-headings:text-white max-w-none">
            {children}
        </div>
    </div>
)

export default function StegDocs() {
    return (
        <div className="space-y-8">
            <div className="border-b border-white/10 pb-8">
                <h1 className="text-4xl font-bold text-white mb-4">Steganography Analysis Documentation</h1>
                <p className="text-xl text-foreground/60">
                    Complete guide to detecting and extracting hidden data from images, audio files, documents, and binaries using advanced forensic steganography techniques.
                </p>
            </div>

            <Section title="What is Steganography?" icon={Eye}>
                <p>
                    Steganography is the art and science of hiding secret messages or data inside other innocuous, non-secret content (called the "carrier").
                    Unlike encryption, which makes data unreadable, steganography hides the existence of data entirely.
                </p>
                <p className="mt-3">
                    A carrier can be an image file, audio file, video, or any binary format. The hidden data can be another file, text, or executable code.
                    The goal is to avoid detection by observers who don't know to look for hidden data.
                </p>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Common Applications</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">🔬 Digital Forensics</h4>
                        <p className="text-sm text-foreground/70">Recover evidence hidden by criminals or malware operators in seemingly innocent files.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">🎯 Malware Analysis</h4>
                        <p className="text-sm text-foreground/70">Identify and extract malware payloads hidden in images or documents (common in weaponized Office files).</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">🎓 CTF Challenges</h4>
                        <p className="text-sm text-foreground/70">Solve Capture The Flag forensic challenges requiring data extraction from media files.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-green mb-2">🔎 Incident Response</h4>
                        <p className="text-sm text-foreground/70">Discover covert communication channels or stolen data exfiltrated through steganography.</p>
                    </div>
                </div>
            </Section>

            <Section title="Steganography Techniques" icon={Zap}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">LSB (Least Significant Bit) Steganography</h3>
                <p>
                    The most common technique. Data is hidden in the least significant bits of pixel values in an image. Since these bits have minimal visual impact,
                    large amounts of data can be hidden without perceptible changes to the image.
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>Can hide up to 1 bit per color channel per pixel (3-4 bits per pixel for RGB/RGBA)</li>
                    <li>Commonly used in PNG, BMP, and JPEG images</li>
                    <li>Vulnerable to compression and image processing</li>
                    <li>Tools like Steghide and Zsteg can detect and extract LSB data</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">EXIF Metadata Hiding</h3>
                <p>
                    Digital images contain metadata (EXIF) including camera model, GPS location, creation date, and more. This metadata can be modified or padded with hidden data.
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>Less obvious than LSB but easier to detect</li>
                    <li>Can be stripped by many image processors</li>
                    <li>ExifTool is the standard tool for reading/writing EXIF metadata</li>
                    <li>Often used for embedding keywords, comments, or small files</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Audio Steganography</h3>
                <p>
                    Hidden data can be embedded in audio files using similar LSB techniques or phase coding.
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>WAV files are most suitable (uncompressed audio preserves hidden data)</li>
                    <li>MP3 compression may destroy hidden data</li>
                    <li>Steghide supports both image and audio carrier files</li>
                    <li>Often used for covert communication or embedding licenses/watermarks</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Firmware & Binary Steganography</h3>
                <p>
                    Data can be hidden within firmware images, executable files, or other binaries by exploiting:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>Unused code sections or padding between sections</li>
                    <li>Dead code or unreachable instructions</li>
                    <li>Slack space in filesystem structures</li>
                    <li>Tools like Binwalk and Foremost can locate and extract these hidden sections</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Document Steganography</h3>
                <p>
                    PDF, Office, and other documents can have hidden data in:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>Embedded streams and objects</li>
                    <li>Compressed content that goes unrendered</li>
                    <li>Macros and hidden scripts</li>
                    <li>Metadata and document properties</li>
                </ul>
            </Section>

            <Section title="Supported Analysis Tools" icon={Layers}>
                <p>
                    SecFlow Steg Analyzer automatically runs multiple forensic tools to maximize data recovery. Each tool specializes in different techniques and file types:
                </p>
                
                <div className="space-y-3 mt-6">
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">🔓 Steghide</h4>
                        <p className="text-sm text-foreground/70 mb-2">
                            Industry-standard steganography tool supporting embedding and extraction from multiple formats.
                        </p>
                        <p className="text-xs text-foreground/60"><strong>Best for:</strong> JPEG, BMP, WAV, AU files with LSB or random data hiding</p>
                        <p className="text-xs text-foreground/60 mt-1"><strong>Features:</strong> Password protection support, compression before embedding</p>
                    </div>

                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">📊 Zsteg</h4>
                        <p className="text-sm text-foreground/70 mb-2">
                            Specialized PNG/BMP LSB steganography detector and extractor written in Ruby.
                        </p>
                        <p className="text-xs text-foreground/60"><strong>Best for:</strong> PNG and BMP files with LSB hidden data</p>
                        <p className="text-xs text-foreground/60 mt-1"><strong>Features:</strong> Automatic LSB detection, channel analysis, palette-based detection</p>
                    </div>

                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">🏷️ ExifTool</h4>
                        <p className="text-sm text-foreground/70 mb-2">
                            Read and analyze metadata in images, PDFs, audio files, and other documents.
                        </p>
                        <p className="text-xs text-foreground/60"><strong>Best for:</strong> EXIF metadata extraction, hidden comments, creation/modification dates</p>
                        <p className="text-xs text-foreground/60 mt-1"><strong>Features:</strong> All metadata formats (EXIF, IPTC, XMP), thumbnail extraction</p>
                    </div>

                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">🔍 Binwalk</h4>
                        <p className="text-sm text-foreground/70 mb-2">
                            Fast binary analysis and firmware extraction tool for finding embedded files and structures.
                        </p>
                        <p className="text-xs text-foreground/60"><strong>Best for:</strong> Firmware images, compressed archives, executable payloads hidden in binaries</p>
                        <p className="text-xs text-foreground/60 mt-1"><strong>Features:</strong> Entropy analysis, file signature detection, automatic extraction</p>
                    </div>

                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">📝 Strings</h4>
                        <p className="text-sm text-foreground/70 mb-2">
                            Extract all printable ASCII/Unicode strings from binary files.
                        </p>
                        <p className="text-xs text-foreground/60"><strong>Best for:</strong> Finding embedded text, URLs, paths, comments in any binary file</p>
                        <p className="text-xs text-foreground/60 mt-1"><strong>Features:</strong> ASCII and Unicode extraction, configurable minimum string length</p>
                    </div>

                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">🎯 Foremost</h4>
                        <p className="text-sm text-foreground/70 mb-2">
                            Data carving tool that recovers files based on headers, footers, and internal data structures.
                        </p>
                        <p className="text-xs text-foreground/60"><strong>Best for:</strong> Recovering deleted files, finding embedded PDFs/images/archives in unallocated space</p>
                        <p className="text-xs text-foreground/60 mt-1"><strong>Features:</strong> 26+ file type signatures, custom configuration, block-level analysis</p>
                    </div>
                </div>
            </Section>

            <Section title="File Type Support" icon={FileCode}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Image Files</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
                    <div className="p-3 bg-[#0c1120] rounded-lg border border-white/10">
                        <p className="text-sm"><strong>JPEG (.jpg, .jpeg)</strong></p>
                        <p className="text-xs text-foreground/60 mt-1">Most suitable for LSB steganography. Steghide recommended.</p>
                    </div>
                    <div className="p-3 bg-[#0c1120] rounded-lg border border-white/10">
                        <p className="text-sm"><strong>PNG (.png)</strong></p>
                        <p className="text-xs text-foreground/60 mt-1">Uncompressed color channels. Zsteg and Steghide both effective.</p>
                    </div>
                    <div className="p-3 bg-[#0c1120] rounded-lg border border-white/10">
                        <p className="text-sm"><strong>BMP (.bmp)</strong></p>
                        <p className="text-xs text-foreground/60 mt-1">Uncompressed format. LSB hiding highly effective. Zsteg recommended.</p>
                    </div>
                    <div className="p-3 bg-[#0c1120] rounded-lg border border-white/10">
                        <p className="text-sm"><strong>GIF (.gif)</strong></p>
                        <p className="text-xs text-foreground/60 mt-1">Limited color palette. Can hide in palette and metadata.</p>
                    </div>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Audio Files</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
                    <div className="p-3 bg-[#0c1120] rounded-lg border border-white/10">
                        <p className="text-sm"><strong>WAV (.wav)</strong></p>
                        <p className="text-xs text-foreground/60 mt-1">Uncompressed audio. Steghide and LSB tools work best.</p>
                    </div>
                    <div className="p-3 bg-[#0c1120] rounded-lg border border-white/10">
                        <p className="text-sm"><strong>MP3 (.mp3)</strong></p>
                        <p className="text-xs text-foreground/60 mt-1">Compressed. LSB data may be destroyed during encoding.</p>
                    </div>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Documents & Other</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
                    <div className="p-3 bg-[#0c1120] rounded-lg border border-white/10">
                        <p className="text-sm"><strong>PDF (.pdf)</strong></p>
                        <p className="text-xs text-foreground/60 mt-1">Can hide data in streams and objects. ExifTool and Binwalk effective.</p>
                    </div>
                    <div className="p-3 bg-[#0c1120] rounded-lg border border-white/10">
                        <p className="text-sm"><strong>TXT (.txt)</strong></p>
                        <p className="text-xs text-foreground/60 mt-1">Can embed binary data. Foremost and Strings effective for extraction.</p>
                    </div>
                </div>
            </Section>

            <Section title="Password-Protected Extraction" icon={Lock}>
                <p>
                    Some steganography techniques, particularly Steghide, support password-based encryption of hidden data.
                    This adds a security layer preventing extraction without the correct passphrase.
                </p>

                <div className="p-4 bg-purple-500/10 border border-purple-500/20 rounded-lg my-4">
                    <h4 className="font-bold text-purple-400 mb-2">🔐 Using Passwords</h4>
                    <p className="text-sm text-purple-200 mb-3">
                        If you suspect a file contains password-protected hidden data, enter the passphrase in the <strong>"Decryption Password"</strong> field
                        before starting analysis.
                    </p>
                    <ul className="list-disc pl-5 space-y-1 text-sm text-purple-200">
                        <li>Steghide will attempt extraction using the provided password</li>
                        <li>If the password is incorrect, extraction will fail silently</li>
                        <li>Without a password, some hidden data may remain inaccessible</li>
                        <li>Common passwords or empty passwords are often worth trying</li>
                    </ul>
                </div>

                <p className="mt-4 text-foreground/70">
                    If you don't have the password and the file is critical, consider:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>Analyzing with all password-free tools (Zsteg, ExifTool, Binwalk, Strings, Foremost)</li>
                    <li>Brute-forcing common passwords or wordlists (if resources permit)</li>
                    <li>Dictionary attacks if the password hint is known</li>
                </ul>
            </Section>

            <Section title="Interpreting Results" icon={Database}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Output Format</h3>
                <p>
                    Each tool produces different output formats. The analyzer aggregates results showing:
                </p>
                <ul className="list-disc pl-5 mt-3 space-y-2 text-foreground/70">
                    <li><strong>Tool Name:</strong> Which forensic tool found the data</li>
                    <li><strong>Data Found:</strong> Type of hidden content (text strings, files, metadata)</li>
                    <li><strong>Extraction Status:</strong> Whether data was successfully extracted or requires further action</li>
                    <li><strong>Confidence:</strong> How likely the detected data is actually hidden (vs random noise)</li>
                    <li><strong>Details:</strong> Specific information about the hidden content</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Common Findings</h3>
                <div className="space-y-3">
                    <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
                        <h4 className="font-bold text-green-400 mb-1">✅ Data Successfully Extracted</h4>
                        <p className="text-sm text-green-200">Hidden file or content was recovered. Check the extracted files section for results.</p>
                    </div>
                    <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                        <h4 className="font-bold text-yellow-400 mb-1">⚠️ Suspicious Strings Detected</h4>
                        <p className="text-sm text-yellow-200">Unusual text or potentially hidden data found. May be legitimate metadata or actual hidden content.</p>
                    </div>
                    <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                        <h4 className="font-bold text-blue-400 mb-1">ℹ️ Metadata Found</h4>
                        <p className="text-sm text-blue-200">EXIF or other metadata present. Review for creation dates, camera info, GPS coordinates, or embedded comments.</p>
                    </div>
                    <div className="p-4 bg-gray-500/10 border border-gray-500/20 rounded-lg">
                        <h4 className="font-bold text-gray-400 mb-1">✓ No Hidden Data Detected</h4>
                        <p className="text-sm text-gray-200">File appears clean. Either no steganography is present or tools couldn't detect the specific technique used.</p>
                    </div>
                </div>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Security Implications</h3>
                <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                    <h4 className="font-bold text-red-400 mb-2">🚨 If Hidden Malware is Found</h4>
                    <ul className="list-disc pl-5 space-y-1 text-sm text-red-200">
                        <li>Do NOT execute or open extracted files</li>
                        <li>Upload to <strong>Malware Analysis</strong> tool for sandboxed analysis</li>
                        <li>If part of incident response, preserve original file and extracted data for forensics</li>
                        <li>Report to security team or incident response immediately</li>
                    </ul>
                </div>
            </Section>

            <Section title="Advanced Techniques" icon={Shield}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Detecting Steganography</h3>
                <p>
                    Steganalysis (the opposite of steganography) attempts to detect whether a file contains hidden data:
                </p>
                <ul className="list-disc pl-5 mt-3 space-y-2 text-foreground/70">
                    <li><strong>Entropy Analysis:</strong> LSB steganography increases file entropy. High entropy in image LSBs is suspicious.</li>
                    <li><strong>Statistical Analysis:</strong> Hidden data disturbs color distribution patterns in images.</li>
                    <li><strong>Signature Scanning:</strong> Known file headers/signatures in unexpected locations indicate embedded content.</li>
                    <li><strong>Binwalk's Entropy Scan:</strong> Visualizes entropy across file to identify high-entropy regions (likely compressed or encrypted data)</li>
                </ul>

                <h3 className="text-xl font-bold text-white mt-6 mb-3">Combining Multiple Tools</h3>
                <p className="mt-3 text-foreground/70">
                    Steganography is an arms race. Different techniques evade different tools. SecFlow runs all major tools to maximize detection:
                </p>
                <ul className="list-disc pl-5 mt-2 space-y-1 text-foreground/70">
                    <li>If Steghide fails, Zsteg may succeed (different LSB algorithms)</li>
                    <li>If LSB detection fails, ExifTool may find metadata hiding</li>
                    <li>If metadata fails, Binwalk may locate embedded archives or executables</li>
                    <li>Strings and Foremost provide final fallback coverage for carving</li>
                </ul>
            </Section>

            <Section title="Practical Forensic Workflow" icon={AlertCircle}>
                <h3 className="text-xl font-bold text-white mt-4 mb-3">Step-by-Step Analysis</h3>
                <ol className="list-decimal pl-5 space-y-3 mt-4">
                    <li className="text-foreground/70">
                        <strong>Upload the suspect file</strong> - Ensure it's in a supported format
                    </li>
                    <li className="text-foreground/70">
                        <strong>Enter password if known</strong> - Some tools require the passphrase to decrypt
                    </li>
                    <li className="text-foreground/70">
                        <strong>Start analysis</strong> - Let all tools run automatically
                    </li>
                    <li className="text-foreground/70">
                        <strong>Review tool results</strong> - Check each tool's findings carefully
                    </li>
                    <li className="text-foreground/70">
                        <strong>Prioritize extracted files</strong> - Focus on actual file signatures (ExifTool, Binwalk, Foremost) before raw strings
                    </li>
                    <li className="text-foreground/70">
                        <strong>Analyze extracted content</strong> - Use Malware Analysis for executables, examine documents for IOCs
                    </li>
                    <li className="text-foreground/70">
                        <strong>Document findings</strong> - Create forensic report with hash, tools used, extracted content, timestamps
                    </li>
                </ol>

                <h3 className="text-xl font-bold text-white mt-8 mb-3">Common CTF/Forensics Scenarios</h3>
                <div className="space-y-3 mt-4">
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">🎯 Scenario: Flag Hidden in PNG</h4>
                        <p className="text-sm text-foreground/70">Use Zsteg for LSB detection, Steghide if password-protected, ExifTool for metadata. Check tool output for base64-encoded or hex-encoded strings.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">🎯 Scenario: Executable Hidden in Image</h4>
                        <p className="text-sm text-foreground/70">Binwalk will detect the ELF/PE header. Foremost will carve the file. Extract with Binwalk's extraction mode, then analyze with Malware Analysis.</p>
                    </div>
                    <div className="p-4 bg-[#0c1120] rounded-lg border border-white/10">
                        <h4 className="font-bold text-neon-yellow mb-2">🎯 Scenario: Archive Hidden in PDF</h4>
                        <p className="text-sm text-foreground/70">Binwalk detects the ZIP header. Foremost extracts the archive. Strings may reveal paths or file names inside the PDF stream.</p>
                    </div>
                </div>
            </Section>
        </div>
    )
}
