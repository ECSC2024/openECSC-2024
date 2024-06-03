import mariadb from 'mariadb';
const pool = mariadb.createPool({
	socketPath: '/run/mysqld/mysqld.sock',
	user: 'cyberpost',
	database: 'cyberpost',
	password: 'password',
	connectionLimit: 5
});

BigInt.prototype.toJSON = function () {
	return this.toString();
};
Buffer.prototype.toJSON = function () {
	return this.toString();
};

export async function sql(query) {
	let conn;
	let res;
	try {
		conn = await pool.getConnection();
		res = await conn.query(query);
	} catch (error) {
		res = {};
	} finally {
		if (conn) conn.release();
	}
	return res;
}
