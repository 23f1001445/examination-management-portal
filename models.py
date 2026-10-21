import sqlite3
import os
import secrets
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'exam_portal.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','examiner','student')),
        name TEXT NOT NULL,
        department TEXT DEFAULT '',
        contact TEXT DEFAULT '',
        status TEXT DEFAULT 'active' CHECK(status IN ('active','pending','deactivated')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_code TEXT UNIQUE NOT NULL,
        course_name TEXT NOT NULL,
        description TEXT DEFAULT '',
        status TEXT DEFAULT 'active' CHECK(status IN ('active','inactive')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS examinations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER NOT NULL,
        exam_name TEXT NOT NULL,
        exam_type TEXT NOT NULL CHECK(exam_type IN ('Viva','Practical','Project Demo','Assessment')),
        duration INTEGER NOT NULL,
        max_marks REAL NOT NULL,
        slot_creation_start TEXT,
        slot_creation_end TEXT,
        slot_booking_start TEXT,
        slot_booking_end TEXT,
        status TEXT DEFAULT 'Draft' CHECK(status IN ('Draft','Slot Creation','Booking Open','Closed','Completed')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (course_id) REFERENCES courses(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS rubrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        exam_id INTEGER NOT NULL,
        criterion_name TEXT NOT NULL,
        max_marks REAL NOT NULL,
        weightage REAL NOT NULL,
        description TEXT DEFAULT '',
        FOREIGN KEY (exam_id) REFERENCES examinations(id) ON DELETE CASCADE
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS examination_slots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        exam_id INTEGER NOT NULL,
        examiner_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        max_capacity INTEGER NOT NULL DEFAULT 1,
        available_seats INTEGER NOT NULL DEFAULT 1,
        status TEXT DEFAULT 'Available' CHECK(status IN ('Available','Full','Cancelled','Completed')),
        FOREIGN KEY (exam_id) REFERENCES examinations(id),
        FOREIGN KEY (examiner_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        slot_id INTEGER NOT NULL,
        booking_date TEXT DEFAULT (datetime('now')),
        status TEXT DEFAULT 'Booked' CHECK(status IN ('Booked','Cancelled','Completed')),
        FOREIGN KEY (student_id) REFERENCES users(id),
        FOREIGN KEY (slot_id) REFERENCES examination_slots(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS evaluations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_id INTEGER NOT NULL,
        rubric_id INTEGER NOT NULL,
        marks REAL DEFAULT 0,
        remarks TEXT DEFAULT '',
        FOREIGN KEY (booking_id) REFERENCES bookings(id),
        FOREIGN KEY (rubric_id) REFERENCES rubrics(id)
    )''')

    # Seed admin user
    admin = c.execute("SELECT id FROM users WHERE role='admin'").fetchone()
    if not admin:
        # Initial admin password comes from the environment; if not set, a random
        # one-time password is generated and printed to the app logs once.
        admin_pwd = os.environ.get('ADMIN_INITIAL_PASSWORD')
        if not admin_pwd:
            admin_pwd = secrets.token_urlsafe(12)
            print(f'[exam-portal] Initial admin password generated: {admin_pwd}', flush=True)
        c.execute('''INSERT INTO users (username, email, password_hash, role, name, department, status)
            VALUES (?,?,?,'admin','System Administrator','Administration','active')''',
            ('admin', 'admin@exam.portal', generate_password_hash(admin_pwd)))

    conn.commit()
    conn.close()
