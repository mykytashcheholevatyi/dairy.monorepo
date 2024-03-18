const http = require('http');
const exec = require('child_process').exec;
const fs = require('fs');
const PORT = 3000; // Можете изменить порт по вашему усмотрению

const projectDir = '/var/www/dairy-monorepo';
const gitRepoUrl = 'https://github.com/mykytashch/dairy.monorepo.git';
const gitBranch = 'main';

http.createServer((req, res) => {
  if (req.method === 'POST') {
    // Обработка POST запроса от webhook
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString(); // Преобразование данных запроса в строку
    });
    req.on('end', () => {
      // При получении данных от GitHub
      console.log('Received webhook:', body);

      // Проверка существования директории проекта и ее создание при необходимости
      if (!fs.existsSync(projectDir)){
        fs.mkdirSync(projectDir, { recursive: true });
      }

      // Команда для клонирования репозитория или обновления, если он уже существует
      const gitCmd = `cd ${projectDir} && (git clone -b ${gitBranch} ${gitRepoUrl} . || git pull origin ${gitBranch})`;

      // Выполнение команды Git
      exec(gitCmd, (error, stdout, stderr) => {
        if (error) {
          console.error(`exec error: ${error}`);
          return;
        }
        console.log(`stdout: ${stdout}`);
        console.error(`stderr: ${stderr}`);
      });

      res.end('Webhook received and processed');
    });
  } else {
    res.statusCode = 404;
    res.end();
  }
}).listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
