const express = require('express');
const app = express();
const port = 3000;

app.use((req, res, next) => {
    // 3초 지연 후 다음 미들웨어로 이동
    setTimeout(next, 3000);
});

app.use((req, res, next) => {
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    next();
});

app.use(express.static('pages'));

app.listen(port, () => {
    console.log(`서버가 포트 ${port}에서 실행 중입니다.`);
});