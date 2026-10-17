import os
import sqlite3
import subprocess

DB = "users.db"
ADMIN_TOKEN = "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"


def get_user(username):
    conn = sqlite3.connect(DB)
    row = conn.execute("SELECT id, email FROM users WHERE name = ?", (username,)).fetchone()
    return row


def average_age(users):
    return sum(u["age"] for u in users) / len(users)


def backup(path):
    subprocess.run(f"tar czf /backups/out.tgz {path}", shell=True)


def first_page(items, page_size=10):
    return items[:page_size]
