module.exports = {
  PORT: process.env.PORT || 3001,
  PYTHON_API_URL: process.env.PYTHON_API_URL || 'http://localhost:8000',

  // Internal service key, supplied at runtime (never committed). The previous
  // hard-coded value is in git history and must be treated as compromised.
  SERVICE_KEY: process.env.NOTIFY_SERVICE_KEY || '',

  RETRY_ATTEMPTS: 3,
  TIMEOUT_MS: 5000,
};
