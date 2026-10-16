import tsPlugin from '@typescript-eslint/eslint-plugin'
import tsParser from '@typescript-eslint/parser'
import pluginVue from 'eslint-plugin-vue'

const typescript = {
  plugins: { '@typescript-eslint': tsPlugin },
  rules: {
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
  },
}

export default [
  ...pluginVue.configs['flat/recommended'],
  {
    files: ['**/*.ts'],
    languageOptions: { parser: tsParser, parserOptions: { sourceType: 'module', ecmaVersion: 'latest' } },
    ...typescript,
  },
  {
    files: ['**/*.vue'],
    languageOptions: { parserOptions: { parser: tsParser, sourceType: 'module', ecmaVersion: 'latest' } },
    ...typescript,
    rules: {
      ...typescript.rules,
      'vue/multi-word-component-names': 'off',
    },
  },
  { ignores: ['dist/', 'node_modules/', 'src-tauri/'] },
]
