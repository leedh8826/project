const mariadb = require('mariadb');

// 데이터베이스 연결 풀 생성
const pool = mariadb.createPool({
    host:             process.env.DB_HOST,          //export DB_HOST=localhost
    user:             process.env.DB_USER,          //export DB_USER=
    password:         process.env.DB_PASSWORD,      //export DB_PASSWORD=
    database:         process.env.DB_DATABASE,      //export DB_DATABASE=
    connectionLimit:  5, 
});

// const pool = mariadb.createPool({
//     host:             'localhost',          //export DB_HOST=localhost
//     user:             'ubuntu',          //export DB_USER=
//     password:         '1234',      //export DB_PASSWORD=
//     database:         'project',      //export DB_DATABASE=
//     connectionLimit:  5, 
// });

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
