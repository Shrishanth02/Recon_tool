import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{js,jsx}'],
    extends: [
      js.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    rules: {
      // Advisory React-plugin rules kept as WARNINGS (still reported), not errors:
      // these flag legitimate, idiomatic patterns in the shipping app rather than
      // bugs, so they must not hard-fail the release lint gate. Genuine errors
      // (unused vars, empty blocks, ref-access-during-render, useless assignment,
      // etc.) remain errors and DO fail the gate.
      //   - set-state-in-effect: the reset-then-load-on-workspace-change effects
      //     (e.g. clear stale findings/triage when the selected workspace changes)
      //     are standard React and would need risky per-site refactors to remove.
      //   - only-export-components: the Provider + useAuth() hook colocated in
      //     AuthContext.jsx is the canonical context pattern.
      //   - preserve-manual-memoization / exhaustive-deps: React-Compiler / deps
      //     advisories on working memoized callbacks.
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/exhaustive-deps': 'warn',
      'react-hooks/preserve-manual-memoization': 'warn',
      'react-refresh/only-export-components': 'warn',
    },
  },
])
