/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        gobs: {
          50: '#f0f7ff',
          100: '#dbeafe',
          500: '#2563eb',
          600: '#1d4ed8',
          700: '#1e3a5f',
          800: '#172554',
          900: '#0f172a',
        },
      },
    },
  },
  plugins: [],
}
