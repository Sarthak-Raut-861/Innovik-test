/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        trust: {
          trusted: '#22c55e',
          degraded: '#eab308',
          suspicious: '#f97316',
          critical: '#ef4444',
          blocked: '#b91c1c',
          contained: '#a855f7',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      keyframes: {
        'pulse-ring': {
          '0%': { opacity: '0.7' },
          '100%': { opacity: '0.15' },
        },
      },
      animation: {
        'pulse-ring': 'pulse-ring 1.6s ease-in-out infinite alternate',
      },
    },
  },
  plugins: [],
};
