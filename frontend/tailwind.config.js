/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,jsx}",
    ],
    theme: {
        extend: {
            colors: {
                // Kept for compatibility, now mapped to neon-blue theme values.
                'neon-green': '#29c5ff',
                'neon-yellow': '#73e6ff',
                'neon-blue': '#29c5ff',
                'neon-cyan': '#73e6ff',
                'background': '#070d1f',
                'foreground': '#d9e7ff',
                'card': '#101b36',
                'border': '#1b2b4f',
            },
            fontFamily: {
                sans: ['Space Grotesk', 'Sora', 'sans-serif'],
                mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
            },
            animation: {
                'scan': 'scan 3s linear infinite',
                'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
            },
            keyframes: {
                scan: {
                    '0%': { transform: 'translateY(0%)' },
                    '100%': { transform: 'translateY(100%)' },
                },
                'pulse-glow': {
                    '0%, 100%': { opacity: '0.5' },
                    '50%': { opacity: '0.8' },
                },
            },
        },
    },
    plugins: [],
}
