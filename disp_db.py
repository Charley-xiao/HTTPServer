import sqlite3
from server import DATABASE_FILE

with sqlite3.connect(DATABASE_FILE) as connection:
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

print(users)