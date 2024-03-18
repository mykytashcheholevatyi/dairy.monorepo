const http = require('http');
const simpleGit = require('simple-git/promise'); // Используем промисы для упрощения асинхронного кода
const pino = require('pino');
const os = require('os');

const PORT = 3000;
const projectDir = '/var/www/dairy-monorepo';
const gitBranch = 'main';
const logCommitMessage = '[Log Update] Automated log commit';

const git = simpleGit(projectDir);
const logger = pino({ level: 'info' }, pino.destination(`${projectDir}/logs/webhook-server.log`));

const server = http.createServer((req, res) => {
  if (req.method === 'POST') {
    handlePostRequest(req, res);
  } else {
    res.statusCode = 404;
    res.end();
  }
});

async function handlePostRequest(req, res) {
  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
  });
  req.on('end', () => {
    processRequestBody(body, res);
  });
}

async function processRequestBody(body, res) {
  let payload;
  try {
    payload = JSON.parse(body);
  } catch (e) {
    logger.error('Error parsing JSON payload from GitHub webhook', e);
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
  await smartStashAndPull();
  res.end('Webhook received and processed.');
}

async function smartStashAndPull() {
  try {
    const status = await git.status();
    if (!status.isClean()) {
      logger.info('Working directory not clean. Checking for critical changes...');
      if (status.files.some(file => file.index !== '?' && file.working_dir !== '?')) {
        logger.info('Critical changes detected, stashing...');
        await git.stash();
      } else {
        logger.info('No critical changes, proceeding without stashing...');
      }
    }
    const pullResult = await git.pull('origin', gitBranch, { '--rebase': 'true' });
    logger.info('Repository successfully updated.', pullResult);
  } catch (error) {
    logger.error('Error during smart stash and pull operation', error);
  }
}

server.listen(PORT, () => {
  logger.info(`Server started at ${new Date().toISOString()} on ${os.hostname()}`);
});
