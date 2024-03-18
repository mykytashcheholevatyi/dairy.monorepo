const http = require('http');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const winston = require('winston');

const PORT = 3000;

// Константы и конфигурация
const projectDir = '/var/www/dairy-monorepo';
const goAppPath = `${projectDir}/dairy-monolit/main.go`;
const goLogPath = `${projectDir}/dairy-monolit/logs/backend.log`;
const gitRepoUrl = 'https://github.com/mykytashch/dairy.monorepo.git';
const gitBranch = 'main';
const logCommitMessage = '[Log Update] Automated log commit';

// Настройка логгера Winston
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

// Создание HTTP сервера
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
        res.statusCode = 400; // Bad request
        res.end('Error parsing payload');
        return;
      }

      const lastCommitMessage = (payload.head_commit && payload.head_commit.message) || '';

      if (lastCommitMessage.includes(logCommitMessage)) {
        logger.info('Commit for log update detected, skipping code update to avoid loop.');
        res.end('Log update commit detected, skipping.');
        return;
      }

// Обновление кода из репозитория Git
exec(`cd ${projectDir} && git pull origin ${gitBranch}`, (updateError, updateStdout, updateStderr) => {
  if (updateError) {
    if (updateStderr.includes('Your local changes to the following files would be overwritten by merge')) {
      // В случае конфликта при обновлении, предложить пользователю выбрать стратегию разрешения конфликта
      const errorMessage = 'Error updating code: Merge conflict detected. Choose conflict resolution strategy.';
      const options = ['Merge', 'Rebase', 'Fast-Forward Only'];
      logger.error(errorMessage);
      res.statusCode = 409; // Conflict
      res.end(`${errorMessage}\nOptions: ${options.join(', ')}`);
      return;
    } else {
      // Если другая ошибка, вывести сообщение об ошибке
      logger.error(`Error updating code: ${updateError}`);
      res.statusCode = 500; // Internal server error
      res.end(`Error updating code: ${updateError}`);
      return;
    }
  }

  logger.info(`Code updated: ${updateStdout}`);
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

  // Коммит логов в репозиторий Git
  exec(`cd ${projectDir} && git add . && git commit -m "${logCommitMessage}" && git push origin ${gitBranch}`, (logError, logStdout, logStderr) => {
    if (logError) {
      logger.error(`Error committing logs: ${logError}`);
      res.statusCode = 500; // Internal server error
      res.end(`Error committing logs: ${logError}`);
      return;
    }

    logger.info(`Logs committed: ${logStdout}`);
    logStderr && logger.error(`Log commit stderr: ${logStderr}`);
    res.end('Code updated, Go app started, and logs committed.');
  });
});


// Запуск сервера
server.listen(PORT, () => {
  const timestamp = new Date().toISOString();
  const host = os.hostname();
  const address = server.address().address;
  logger.info(`Server started at ${timestamp} on ${host} (${address})`);
});
