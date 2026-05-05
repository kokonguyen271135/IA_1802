"""
Demo file for Scenario 1 (Basic): individual developer scanning their own code.

INTENTIONALLY VULNERABLE — for security scanner demo only.
DO NOT USE IN PRODUCTION.
"""
import sqlite3


def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name='{username}' AND pass='{password}'"
    cursor.execute(query)
    return cursor.fetchone() is not None


def render_profile(user_input):
    return f"<h1>Welcome {user_input}</h1>"


def run_command(cmd):
    import os
    os.system(cmd)


def deserialize_session(data):
    import pickle
    return pickle.loads(data)
