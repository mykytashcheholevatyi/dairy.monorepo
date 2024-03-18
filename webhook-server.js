const http = require('http');
const { exec } = require('child_process');
const os = require('os');
const winston = require('winston');

const PORT = 3000;
const projectDir = '/var/www/dairy-monorepo';
const gitBranch = 'main';
const logCommitMessage = '[Log Update] Automated log commit';

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(info => `[${info.timestamp}] ${info.level}: ${info.message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: `${projectDir}/logs/webhook-server.log` }),
  ],
});

// HTTP server for handling webhooks
const server = http.createServer((req, res) => {
  if (req.method === 'POST') {
    handlePostRequest(req, res);
  } else {
    res.statusCode = 404;
    res.end();
  }
});

function handlePostRequest(req, res) {
  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
  });
  req.on('end', () => processRequestBody(body, res));
}

function processRequestBody(body, res) {
  let payload;
  try {
    payload = JSON.parse(body);
  } catch (e) {
    handleError(res, 400, 'Error parsing JSON payload from GitHub webhook');
    return;
  }
  const lastCommitMessage = (payload.head_commit && payload.head_commit.message) || '';
  if (lastCommitMessage.includes(logCommitMessage)) {
    logger.info('Commit for log update detected, skipping code update to avoid loop.');
    res.end('Log update commit detected, skipping.');
    return;
  }
  checkForCleanDirectoryAndPullChanges(res);
}

function checkForCleanDirectoryAndPullChanges(res) {
  exec(`cd ${projectDir} && git status --porcelain`, (err, stdout, stderr) => {
    if (err) {
      handleError(res, 500, `Error checking for clean directory: ${err}`);
      return;
    }
    if (stdout) {
      handleError(res, 500, 'The working directory is not clean. Aborting auto-update.');
      return;
    }
    pullChanges(res);
  });
}

function pullChanges(res) {
  exec(`cd ${projectDir} && git pull --rebase origin ${gitBranch}`, (err, stdout, stderr) => {
    if (err) {
      handleError(res, 500, `Error updating code: ${err}`);
      return;
    }
    logger.info(`Code updated: ${stdout}`);
    stderr && logger.error(`Update stderr: ${stderr}`);
    res.end('Code updated.');
  });
}

function handleError(res, statusCode, errorMessage) {
  logger.error(errorMessage);
  res.statusCode = statusCode;
  res.end(errorMessage);
}

server.listen(PORT, () => {
  const timestamp = new Date().toISOString();
  const host = os.hostname();
  logger.info(`Server started at ${timestamp} on ${host}`);
});
