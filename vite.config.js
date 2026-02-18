const { defineConfig } = require('vite')
const react = require('@vitejs/plugin-react')
const path = require('path')

module.exports = defineConfig({
  root: 'frontend',
  plugins: [react()],
  build: {
    outDir: path.resolve(__dirname, 'public'),
    emptyOutDir: false,
    rollupOptions: {
      input: path.resolve(__dirname, 'frontend', 'index.html')
    }
  },
})
