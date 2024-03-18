const http = require('http');
const simpleGit = require('simple-git');
const pino = require('pino');
const cron = require('node-cron');
const os = require('os');

const PORT = 3000;
const projectDir = '/var/www/dairy-monorepo';
const gitBranch = 'main';
const logCommitMessage = '[Log Update] Automated log commit';

const git = simpleGit(projectDir);
const logger = pino({ level: 'info' }, pino.destination(`${projectDir}/logs/webhook-server.log`));

// Schedule a task to check for updates periodically
cron.schedule('*/30 * * * *', () => {
  checkForUpdates();
});

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
  req.on('end', () => {
    processRequestBody(body, res);
  });
}

function processRequestBody(body, res) {
  let payload;
  try {
    payload = JSON.parse(body);
  } catch (e) {
    logger.error('Error parsing JSON payload from GitHub webhook');
    res.statusCode = 400;
    res.end('Error parsing JSON payload');
    return;
  }
  const lastCommitMessage = payload.head_commit && payload.head_commit.message;
  if (lastCommitMessage && lastCommitMessage.includes(logCommitMessage)) {
    logger.info('Commit for log update detected, skipping code update to avoid loop.');
    res.end('Log update commit detected, skipping.');
    return;
  }
  checkForUpdates();
  res.end('Webhook received and processed.');
}

function checkForUpdates() {
  git.status().then(status => {
    if (!status.isClean()) {
      logger.warn('The working directory is not clean. Attempting to stash changes.');
      git.stash().then(() => updateCode()).catch(err => logger.error(`Stashing error: ${err}`));
    } else {
      updateCode();
    }
  }).catch(err => logger.error(`Git status error: ${err}`));
}

function updateCode() {
  git.pull('origin', gitBranch, {'--rebase': 'true'}).then(() => {
    logger.info('Repository successfully updated.');
  }).catch(err => {
    logger.error(`Git pull error: ${err}`);
  });
}

server.listen(PORT, () => {
  logger.info(`Server started at ${new Date().toISOString()} on ${os.hostname()}`);
});
