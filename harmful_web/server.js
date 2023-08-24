// server.js

const express = require('express');
const cors = require('cors');
const app = express();
const port = 3000; // 사용할 포트 번호를 지정합니다

app.use((req, res, next) => {
  // 3초 지연 후 다음 미들웨어로 이동
  setTimeout(next, 3000);
});

app.use(cors()); // CORS 설정

app.post('/api/add-domain', (req, res) => {
  // 추가 로직을 구현하세요
});

app.get('/api/get-harmful-domains', (req, res) => {
  // 데이터를 가져오는 로직을 구현하세요
});

app.post('/api/delete-domains', (req, res) => {
  // 삭제 로직을 구현하세요
});

app.listen(port, () => {
  console.log(`Express server is running on port ${port}`);
});
