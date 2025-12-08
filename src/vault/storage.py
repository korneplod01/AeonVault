import sqlite3
import os
import datetime

class LogStorage:
    def __init__(self, path = 'logs_vault.db'):
        self.path = path
        self.connection = sqlite3.connect(self.path)
        self.cursor = self.connection.cursor()
        self._create_table()

    def _create_table(self):
        
        self.cursor.execute(
            """CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            comment TEXT NOT NULL,
            tag TEXT NOT NULL
        );"""
        )
        self.connection.commit()

    def write_log(self, comment: str, tag: str):
        
        self.cursor.execute(
            "INSERT INTO logs (timestamp, comment, tag) VALUES (?, ?, ?)",
            (datetime.datetime.now(), comment, tag)
        )
        self.connection.commit()


class PasswordStorage:
    def __init__(self, logs=LogStorage(), path='vault.db' ):
        self.path = path
        self.connection = sqlite3.connect(self.path)
        self.cursor = self.connection.cursor()
        self._create_table()
        self.logs = logs
        logs.write_log('Successfully initiated the Password Vault', 'system_PasswordStorage')


    def _create_table(self):
        self.logs.write_log('Attempting to create the "passwords" table...', 'system_PasswordStorage')
        try:
            self.cursor.execute(
                """ 
            CREATE TABLE passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                login TEXT NOT NULL,
                password TEXT NOT NULL,
                UNIQUE(website, login)
            );"""
            )
            self.logs.write_log(f'Successfully created table "passwords"', 'system_PasswordStorage')
            self.connection.commit()
        except sqlite3.OperationalError:
            self.logs.write_log(f'Table "passwords" alreday exists, skipping...', 'system_PasswordStorage')


    def add_password(self, website: str, login: str, password: str):
        self.logs.write_log(f'Attemtpting to add the {website}/{login} pair...', 'info')
        try:
            self.cursor.execute(
            "INSERT INTO passwords (website, login, password) VALUES (?, ?, ?)",
            (website, login, password)
        )
            self.connection.commit()
            self.logs.write_log(f'Successfully added {website}/{login} pair', 'info')
            return True
        except sqlite3.IntegrityError:
            self.logs.write_log(f'Failed to add {website}/{login} pair', 'info')
            return False


    def get_password(self, website: str, login: str):
        self.logs.write_log(f'Attemtpting to retrieve the {website}/{login} pair...', 'info')
        self.cursor.execute(
        "SELECT password FROM passwords WHERE website = ? AND login = ?",
        (website, login)
        )
        row = self.cursor.fetchone()
        if row:
            self.logs.write_log(f'Returned the password for the {website}/{login} combination')
            return row[0]
        else:
            self.logs.write_log(f'No passwords were found for the {website}/{login} combination')
            return None


    def update_password(self, website: str, login: str, new_password: str):
        self.logs.write_log(f'Attemtpting to update the {website}/{login} pair...', 'info')
        self.cursor.execute(
            "UPDATE passwords SET password = ? WHERE website = ? AND login = ?",
            (new_password, website, login)
        )
        self.connection.commit()
        if self.cursor.rowcount == 0:
            self.logs.write_log('No passwords were updated', 'info')
            return False
        else:
            self.logs.write_log(f'Password pair {website}/{login} has been updated', 'info')
            return True
        

    def list_passwords(self):
        self.cursor.execute(
            "SELECT website, login FROM passwords"
        )
        self.logs.write_log('Listed all the website/login pairs', 'info')
        return self.cursor.fetchall()


    def delete_password(self, website: str, login: str):
        self.cursor.execute(
            "DELETE from passwords WHERE website = ? and login = ?",
            (website, login)
        )
        self.connection.commit()
        if self.cursor.rowcount == 0:
            self.logs.write_log(f'Failed to delete the {website}/{login} pair', 'info')
            return False
        else:
            self.logs.write_log(f'Successfully deleted the {website}/{login} pair', 'info')
            return True


    def close_connection(self):
        self.connection.close()
        self.logs.write_log('Closed connection with the Password Vault', 'system_PasswordStorage')



