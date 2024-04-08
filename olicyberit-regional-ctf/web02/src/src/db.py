import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import hashlib

queries = [
    """
    CREATE TABLE users (
        id VARCHAR(36) PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL
    );
    """,
    """
    CREATE TABLE tasks (
        id VARCHAR(36) PRIMARY KEY,
        description TEXT,
        added_at DATE,
        completed BOOLEAN DEFAULT FALSE,

        user_id VARCHAR(36) NOT NULL
    );
    """,
    """
    CREATE TABLE sessions(
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL
    );
    """
]

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

class DBException(Exception):
    pass


class DB:
    def _get_database(ip):
        database_prefix = hashlib.md5(ip.encode()).hexdigest()
        return f'./{database_prefix}-database.db'


    def _setup(self, ip):
        cursor = self.get_cursor()

        for q in queries:
            try:
                cursor.execute(q)
            except sqlite3.OperationalError as e:
                raise DBException("Error creating table: %s" % e)

        antonio_id = str(uuid.uuid4())
        flag_task_id = str(uuid.uuid4())
        FLAG = os.getenv('FLAG', 'flag{placeholder}')

        cursor.execute("INSERT INTO users (id, username, password_hash) VALUES ('%s', 'antonio', '')" % antonio_id)

        cursor.execute("INSERT INTO tasks (id, description, added_at, completed, user_id) VALUES ('%s', 'Submit the flag: %s', '2021-01-01', 0, '%s')" % (flag_task_id, FLAG, antonio_id))

        self.commit()
        cursor.close()


    def __init__(self, remote_address) -> None:
        self.connection = sqlite3.connect(DB._get_database(remote_address))
        self.connection.row_factory = dict_factory

        try:
            cur = self.connection.cursor()
            cur.execute("SELECT * FROM users")
            cur.fetchall()                 
        except sqlite3.OperationalError:
            self._setup(remote_address)


    def get_cursor(self) -> sqlite3.Cursor:
        return self.connection.cursor()
    

    def commit(self):
        self.connection.commit()


    def register(self, username, password):
        cursor = self.get_cursor()
        username = username.replace("'", "''")

        cursor.execute(
            "SELECT id FROM users WHERE username = '%s'" % (username, ))

        users = cursor.fetchall()
        if len(users) == 1:
            cursor.close()
            return None

        password_hash = generate_password_hash(password)
        user_id = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO users(id, username, password_hash)
            VALUES ('%s', '%s', '%s'); 
            """ % (user_id, username, password_hash))

        self.commit()
        cursor.close()

        return user_id


    def create_session(self, user_id):
        cursor = self.get_cursor()

        session_id = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO sessions(id, user_id)
            VALUES ('%s', '%s');
            """ % (session_id, user_id))

        self.commit()
        cursor.close()

        return session_id
    

    def get_user_from_session(self, session_id):
        cursor = self.get_cursor()

        cursor.execute(
            """SELECT users.id, users.username
            FROM users
            JOIN sessions ON users.id = sessions.user_id
            WHERE sessions.id = '%s';""" % (session_id,))

        users = cursor.fetchall()
        cursor.close()

        if len(users) == 1:
            return users[0]

        return None


    def get_tasks(self, user_id):
        cursor = self.get_cursor()
        user_id = user_id.replace("'", "''")

        cursor.execute(
            """SELECT *
            FROM tasks
            WHERE user_id = '%s';""" % (user_id,))

        tasks = cursor.fetchall()
        cursor.close()

        return tasks


    def toggle_task(self, task_id, user_id):
        cursor = self.get_cursor()
        task_id = task_id.replace("'", "''")
        user_id = user_id.replace("'", "''")

        cursor.execute(
            """UPDATE tasks
            SET completed = NOT completed
            WHERE id = '%s' AND user_id = '%s';""" % (task_id, user_id))
        
        self.commit()
        cursor.close()


    def add_task(self, description, user_id):
        cursor = self.get_cursor()
        description = description.replace("'", "''")
        user_id = user_id.replace("'", "''")

        cursor.execute(
            """INSERT INTO tasks(id, description, added_at, user_id)
            VALUES ('%s', '%s', date('now'), '%s');""" % (str(uuid.uuid4()), description, user_id))

        self.commit()
        cursor.close()
