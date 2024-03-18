const http = require('http');
const exec = require('child_process').exec;
const fs = require('fs');
const winston = require('winston');
const PORT = 3000;

const projectDir = '/var/www/dairy-monorepo';
const goAppPath = `${projectDir}/dairy-monolit/main.go`;
const goLogPath = `${projectDir}/dairy-monolit/logs/backend.log`;
const gitRepoUrl = 'https://github.com/mykytashch/dairy.monorepo.git';
const gitBranch = 'main';
const logCommitMessage = '[Log Update] Automated log commit';

// Настройка Winston для логирования
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.File({ filename: `${projectDir}/logs/webhook-server.log` }),
  ],
});

// Убедитесь, что директория с логами существует
fs.mkdirSync(`${projectDir}/dairy-monolit/logs`, { recursive: true });

http.createServer((req, res) => {
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
        res.end('Error parsing payload');
        return;
      }

      const lastCommitMessage = (payload.head_commit && payload.head_commit.message) || '';
      if (lastCommitMessage.includes(logCommitMessage)) {
        logger.info('Commit for log update detected, skipping code update to avoid loop.');
        res.end('Log update commit detected, skipping.');
        return;
      }

      const updateCmd = `cd ${projectDir} && git pull origin ${gitBranch}`;
      exec(updateCmd, (updateError, updateStdout, updateStderr) => {
        if (updateError) {
          logger.error(`exec error: ${updateError}`);
          res.end(`Error updating code: ${updateError}`);
          return;
        }

        logger.info(`Update stdout: ${updateStdout}`);
        updateStderr && logger.error(`Update stderr: ${updateStderr}`);

        // Запуск Go-приложения
        exec(`go run ${goAppPath} > ${goLogPath} 2>&1 &`, (goError, goStdout, goStderr) => {
          if (goError) {
            logger.error(`Go app exec error: ${goError}`);
            return;
          }
          goStdout && logger.info(`Go app stdout: ${goStdout}`);
          goStderr && logger.info(`Go app stderr: ${goStderr}`);
        });

        // Добавление и коммит изменений, включаааая логи
        exec(`cd ${projectDir} && git add . && git commit -m "${logCommitMessage}" && git push origin ${gitBranch}`, (logError, logStdout, logStderr) => {
          if (logError) {
            logger.error(`exec error: ${logError}`);
            res.end(`Error committing logs: ${logError}`);
            return;
          }

          logger.info(`Log commit stdout: ${logStdout}`);
          logStderr && logger.info(`Log commit stderr: ${logStderr}`);
          res.end('Code updated, Go app started, and logs committed.');
        });
      });
    });
  } else {
    res.statusCode = 404;
    res.end();
  }
}).listen(PORT, () => {
  logger.info(`Server listening on port ${PORT}`);
});
