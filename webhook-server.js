const http = require('http');
const { exec } = require('child_process');
const os = require('os');
const winston = require('winston');

const PORT = 3000;
const projectDir = '/var/www/dairy-monorepo';
const goAppPath = `${projectDir}/dairy-monolit/main.go`;
const goLogPath = `${projectDir}/dairy-monolit/logs/backend.log`;
const gitBranch = 'main';
const logCommitMessage = '[Log Update] Automated log commit';

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

const server = http.createServer((req, res) => {
  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', () => {
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

      updateCodeAndLogs(res);
    });
  } else {
    res.statusCode = 404;
    res.end();
  }
});

function handleError(res, statusCode, errorMessage) {
  logger.error(errorMessage);
  res.statusCode = statusCode;
  res.end(errorMessage);
}

function updateCodeAndLogs(res) {
  exec(`cd ${projectDir} && git pull --rebase=true origin ${gitBranch}`, (updateError, updateStdout, updateStderr) => {
    if (updateError) {
      handleError(res, 500, `Error updating code: ${updateError}`);
      return;
    }

    logger.info(`Code updated: ${updateStdout}`);
    updateStderr && logger.error(`Update stderr: ${updateStderr}`);

    startGoApp();
    commitLogs(res);
  });
}

function startGoApp() {
  exec(`go run ${goAppPath} > ${goLogPath} 2>&1 &`, (goError, goStdout, goStderr) => {
    if (goError) {
      logger.error(`Go app exec error: ${goError}`);
      return;
    }
    goStdout && logger.info(`Go app stdout: ${goStdout}`);
    goStderr && logger.info(`Go app stderr: ${goStderr}`);
  });
}

function commitLogs(res) {
  exec(`cd ${projectDir} && git add . && git commit -m "${logCommitMessage}" && git push origin ${gitBranch}`, (logError, logStdout, logStderr) => {
    if (logError) {
      handleError(res, 500, `Error committing logs: ${logError}`);
      return;
    }

    logger.info(`Logs committed: ${logStdout}`);
    logStderr && logger.error(`Log commit stderr: ${logStderr}`);
    res.end('Code updated, Go app started, and logs committed.');
  });
}

server.listen(PORT, () => {
  const timestamp = new Date().toISOString();
  const host = os.hostname();
  const address = server.address().address;
  logger.info(`Server started at ${timestamp} on ${host} (${address})`);
});
