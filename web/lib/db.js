const mariadb = require('mariadb');

// 데이터베이스 연결 풀 생성
const pool = mariadb.createPool({
    host:             process.env.DB_HOST,
    user:             process.env.DB_USER,
    password:         process.env.DB_PASSWORD,    
    database:         process.env.DB_DATABASE,
    connectionLimit:  5, 
});

// 데이터베이스 쿼리 실행 함수
async function queryDatabase(query, values = []) {
    let conn;
    try {
        console.log(process.env.DB_HOST);
        conn = await pool.getConnection();
        const result = await conn.query(query, values);
        return result;
    } catch (error) {
        throw error;
    } finally {
        if (conn) conn.release(); // 연결 반환
    }
}

module.exports = {
    queryDatabase,
};
