import MySQLdb
import os

DB_HOST = '127.0.0.1'  
DB_USER = 'your_username'
DB_PASSWORD = 'your_password'
DB_NAME = 'your_database'

def initialize_database():
    """Creates the database and tables if they do not exist."""
    try:
        conn = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASSWORD)
        cursor = conn.cursor()

        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        cursor.execute(f"USE {DB_NAME}")

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        )
        """)

        conn.commit()
        print("✅ Database initialized successfully! 🎉")

    except MySQLdb.Error as e:
        print(f"❌ Database Error: {e}")

    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    initialize_database()
