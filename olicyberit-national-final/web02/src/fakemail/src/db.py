import sqlite3

DATABASE = './database.db'

TABLES = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        email TEXT,
        password TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,

        email_from TEXT,
        subject TEXT,
        body TEXT,
        seen BOOLEAN DEFAULT 0,

        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """
]

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


class DB():
    DONE = False

    def __init__(self) -> None:
        self.conn = sqlite3.connect(DATABASE)
        self.conn.row_factory = dict_factory

        self.commit()


    def get_cursor(self) -> sqlite3.Cursor:
        return self.conn.cursor()
    

    def commit(self):
        self.conn.commit()


    def get_user(self, email):
        cursor = self.get_cursor()

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        self.commit()

        return user


    def add_user(self, email, password):
        cursor = self.get_cursor()

        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))

        self.commit()


    def add_email(self, user_id, email_from, subject, body):
        cursor = self.get_cursor()

        cursor.execute("INSERT INTO emails (user_id, email_from, subject, body) VALUES (?, ?, ?, ?)", (user_id, email_from, subject, body))

        cursor.execute("SELECT last_insert_rowid() as id")
        email_id = cursor.fetchone()['id']

        self.commit()

        return email_id


    def get_emails(self, user_id):
        cursor = self.get_cursor()

        cursor.execute("SELECT * FROM emails WHERE user_id = ?", (user_id,))
        emails = cursor.fetchall()

        self.commit()

        return emails


    def get_email(self, user_id, email_id):
        cursor = self.get_cursor()

        cursor.execute("SELECT * FROM emails WHERE user_id = ? AND id = ?", (user_id, email_id))
        email = cursor.fetchone()

        self.commit()

        return email
    

    def set_seen(self, email_id):
        cursor = self.get_cursor()

        cursor.execute("UPDATE emails SET seen = 1 WHERE id = ?", (email_id,))

        self.commit()


    def delete_mail(self, email_id):
        cursor = self.get_cursor()

        cursor.execute("DELETE FROM emails WHERE id = ?", (email_id,))

        self.commit()