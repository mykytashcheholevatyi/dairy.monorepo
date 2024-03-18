const http = require('http');
const exec = require('child_process').exec;
const fs = require('fs');
const winston = require('winston');
const PORT = 3000;

const projectDir = '/var/www/dairy-monorepo';
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

http.createServer((req, res) => {
  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      // Десериализация тела запроса
      let payload;
      try {
        payload = JSON.parse(body);
      } catch (e) {
        logger.error('Error parsing JSON payload from GitHub webhook');
        res.end('Error parsing payload');
        return;
      }

      // Проверка комментария последнего коммита на наличие специфической строки
      const lastCommitMessage = payload.head_commit.message;
      if (lastCommitMessage.includes(logCommitMessage)) {
        logger.info('Commit for log update detected, skipping code update to avoid loop.');
        res.end('Log update commit detected, skipping.');
        return;
      }

      // Обновление кода
      const updateCmd = `cd ${projectDir} && git pull origin ${gitBranch}`;
      exec(updateCmd, (error, stdout, stderr) => {
        if (error) {
          logger.error(`exec error: ${error}`);
          res.end(`Error updating code: ${error}`);
          return;
        }
        logger.info(`stdout: ${stdout}`);
        if (stderr) logger.info(`stderr: ${stderr}`);

        // После обновления кода, добавляем и коммитим логи, если есть изменения
        const logCmd = `cd ${projectDir} && git add logs/*.log && git commit -m "${logCommitMessage}" && git push origin ${gitBranch}`;
        exec(logCmd, (logError, logStdout, logStderr) => {
          if (logError) {
            logger.error(`exec error: ${logError}`);
            res.end(`Error committing logs: ${logError}`);
            return;
          }
          logger.info(`Log stdout: ${logStdout}`);
          if (logStderr) logger.info(`Log stderr: ${logStderr}`);
        });

        res.end('Code updated and logs committed.');
      });
    });
  } else {
    res.statusCode = 404;
    res.end();
  }
}).listen(PORT, () => {
  logger.info(`Server listening on port ${PORT}`);
});
