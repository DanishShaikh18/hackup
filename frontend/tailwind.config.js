/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'bg-base': '#0a0d12',
        'bg-surface': '#111827',
        'bg-elevated': '#1a2234',
        'border': '#1e2d40',
        'accent-gold': '#C9A020',
        'accent-danger': '#ff4757',
        'accent-warning': '#ffa502',
        'accent-success': '#2ed573',
        'accent-ai': '#7c3aed',
        'text-primary': '#e2e8f0',
        'text-secondary': '#94a3b8',
        'text-muted': '#4a5568',
      },
      fontFamily: {
        'sans': ['Inter', 'sans-serif'],
        'mono': ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
};
