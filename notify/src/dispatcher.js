const axios = require('axios');
const config = require('./config');

async function dispatch(webhook, payload) {
  for (let attempt = 1; attempt <= config.RETRY_ATTEMPTS; attempt++) {
    try {
      await axios.post(webhook.url, payload, {
        timeout: config.TIMEOUT_MS,
        headers: {
          'Content-Type': 'application/json',
          ...(config.SERVICE_KEY && { 'X-Service-Key': config.SERVICE_KEY }),
        },
      });
      return { webhookId: webhook.id, success: true, attempt };
    } catch (err) {
      if (attempt === config.RETRY_ATTEMPTS) {
        return { webhookId: webhook.id, success: false, error: err.message, attempt };
      }
    }
  }
}

module.exports = { dispatch };
