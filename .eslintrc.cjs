module.exports = {
  env: {
    browser: true,
  },
  extends: ['airbnb-base', 'plugin:prettier/recommended'],
  rules: {
    'import/prefer-default-export': 0,
    'import/extensions': ['error', 'ignorePackages'],
    'no-console': 2,
    // 'import/no-default-export': 2,
    'max-lines': ['error', 300],
    quotes: ['error', 'single'],
    camelcase: ['error', { ignoreDestructuring: true }],
  },
}
