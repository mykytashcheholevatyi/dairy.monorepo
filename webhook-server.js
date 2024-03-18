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
        logger.error('Error parsing JSON payload from GitHub webhook');
        res.statusCode = 400;
        res.end('Error parsing payload');
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

function updateCodeAndLogs(res) {
  exec(`cd ${projectDir} && git pull --rebase origin ${gitBranch}`, (updateError, updateStdout, updateStderr) => {
    if (updateError) {
      if (updateStderr.includes('hint: You have divergent branches')) {
        const errorMessage = 'Error updating code: Divergent branches detected. Choosing resolution strategy...';
        logger.error(errorMessage);
        resolveDivergentBranches(res);
        return;
      } else {
        logger.error(`Error updating code: ${updateError}`);
        res.statusCode = 500;
        res.end(`Error updating code: ${updateError}`);
        return;
      }
    }

    logger.info(`Code updated: ${updateStdout}`);
    updateStderr && logger.error(`Update stderr: ${updateStderr}`);

    startGoApp();
    commitLogs(res);
  });
}

function resolveDivergentBranches(res) {
  exec(`cd ${projectDir} && git pull origin ${gitBranch} --rebase`, (resolveError, resolveStdout, resolveStderr) => {
    if (resolveError) {
      logger.error(`Error resolving divergent branches: ${resolveError}`);
      res.statusCode = 500;
      res.end(`Error resolving divergent branches: ${resolveError}`);
      return;
    }

    logger.info(`Divergent branches resolved: ${resolveStdout}`);
    resolveStderr && logger.error(`Resolve stderr: ${resolveStderr}`);

    updateCodeAndLogs(res);
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
      logger.error(`Error committing logs: ${logError}`);
      res.statusCode = 500;
      res.end(`Error committing logs: ${logError}`);
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
