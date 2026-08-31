import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  {
    ignores: ['node_modules', 'out', 'coverage']
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/main/**/*.ts', 'electron.vite.config.ts'],
    languageOptions: {
      globals: globals.node
    }
  },
  {
    files: ['src/renderer/**/*.{ts,tsx}'],
    languageOptions: {
      globals: globals.browser
    }
  }
)

