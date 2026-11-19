import js from '@eslint/js';
import globals from 'globals';

export default [
	{ ignores: ['node_modules/', 'docs/'] },
	js.configs.recommended,
	{
		languageOptions: {
			ecmaVersion: 2023,
			sourceType: 'module',
			globals: { ...globals.node },
		},
		rules: {
			'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
		},
	},
];
