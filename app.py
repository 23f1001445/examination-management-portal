import os
import secrets
import sqlite3
from datetime import datetime, date
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash)
from werkzeug.security import generate_password_hash, check_password_hash

from models import get_db, init_db

app = Flask(__name__)

# a guessable hardcoded value.
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

init_db()

# ── helpers ──────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if 'user_id' not in session:
                flash('Please log in first.', 'warning')
                return redirect(url_for('login'))
            if session.get('role') != role:
                flash('Access denied.', 'danger')
                return redirect(url_for('login'))
            return f(*a, **kw)
        return wrapper
    return decorator

def today_str():
    return date.today().isoformat()

def now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# ── auth ─────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        r = session['role']
        if r == 'admin':    return redirect(url_for('admin_dashboard'))
        if r == 'examiner': return redirect(url_for('examiner_dashboard'))
        if r == 'student':  return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd   = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username=?', (uname,)).fetchone()
        db.close()
        if user and check_password_hash(user['password_hash'], pwd):
            if user['status'] == 'pending':
                flash('Account pending admin approval.', 'warning')
                return redirect(url_for('login'))
            if user['status'] == 'deactivated':
                flash('Account deactivated.', 'danger')
                return redirect(url_for('login'))
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            session['name']     = user['name']
            flash(f'Welcome, {user["name"]}!', 'success')
            if user['role'] == 'admin':    return redirect(url_for('admin_dashboard'))
            if user['role'] == 'examiner': return redirect(url_for('examiner_dashboard'))
            return redirect(url_for('student_dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        uname  = request.form['username']
        email  = request.form['email']
        pwd    = request.form['password']
        name   = request.form['name']
        role   = request.form['role']
        dept   = request.form.get('department', '')
        contact= request.form.get('contact', '')
        if role not in ('examiner','student'):
            flash('Invalid role.', 'danger')
            return redirect(url_for('register'))
        status = 'pending' if role == 'examiner' else 'active'
        db = get_db()
        try:
            db.execute('INSERT INTO users (username,email,password_hash,role,name,department,contact,status) VALUES (?,?,?,?,?,?,?,?)',
                       (uname, email, generate_password_hash(pwd), role, name, dept, contact, status))
            db.commit()
            msg = 'Registration successful! Awaiting admin approval.' if role=='examiner' else 'Registration successful! Please log in.'
            flash(msg, 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
        finally:
            db.close()
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

# ══════════════════════════════════════════════════════════════════════
#  ADMIN ROUTES
# ══════════════════════════════════════════════════════════════════════
@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    db = get_db()
    stats = {
        'courses':      db.execute('SELECT COUNT(*) c FROM courses').fetchone()['c'],
        'examinations': db.execute('SELECT COUNT(*) c FROM examinations').fetchone()['c'],
        'examiners':    db.execute("SELECT COUNT(*) c FROM users WHERE role='examiner'").fetchone()['c'],
        'students':     db.execute("SELECT COUNT(*) c FROM users WHERE role='student'").fetchone()['c'],
        'slots':        db.execute('SELECT COUNT(*) c FROM examination_slots').fetchone()['c'],
        'bookings':     db.execute('SELECT COUNT(*) c FROM bookings').fetchone()['c'],
        'pending':      db.execute("SELECT COUNT(*) c FROM users WHERE role='examiner' AND status='pending'").fetchone()['c'],
    }
    db.close()
    return render_template('admin/dashboard.html', stats=stats)

# ── courses ──────────────────────────────────────────────────────────
@app.route('/admin/courses')
@role_required('admin')
def admin_courses():
    db = get_db()
    courses = db.execute('SELECT * FROM courses ORDER BY id DESC').fetchall()
    db.close()
    return render_template('admin/courses.html', courses=courses)

@app.route('/admin/courses/create', methods=['GET','POST'])
@role_required('admin')
def admin_course_create():
    if request.method == 'POST':
        db = get_db()
        try:
            db.execute('INSERT INTO courses (course_code,course_name,description,status) VALUES (?,?,?,?)',
                       (request.form['course_code'], request.form['course_name'],
                        request.form.get('description',''), request.form.get('status','active')))
            db.commit()
            flash('Course created.', 'success')
        except sqlite3.IntegrityError:
            flash('Course code already exists.', 'danger')
        finally:
            db.close()
        return redirect(url_for('admin_courses'))
    return render_template('admin/courses.html', form_mode='create', courses=[])

@app.route('/admin/courses/<int:cid>/edit', methods=['GET','POST'])
@role_required('admin')
def admin_course_edit(cid):
    db = get_db()
    if request.method == 'POST':
        db.execute('UPDATE courses SET course_code=?, course_name=?, description=?, status=? WHERE id=?',
                   (request.form['course_code'], request.form['course_name'],
                    request.form.get('description',''), request.form.get('status','active'), cid))
        db.commit()
        db.close()
        flash('Course updated.', 'success')
        return redirect(url_for('admin_courses'))
    course = db.execute('SELECT * FROM courses WHERE id=?', (cid,)).fetchone()
    courses = db.execute('SELECT * FROM courses ORDER BY id DESC').fetchall()
    db.close()
    return render_template('admin/courses.html', form_mode='edit', edit_course=course, courses=courses)

@app.route('/admin/courses/<int:cid>/delete', methods=['POST'])
@role_required('admin')
def admin_course_delete(cid):
    db = get_db()
    db.execute('DELETE FROM courses WHERE id=?', (cid,))
    db.commit()
    db.close()
    flash('Course removed.', 'success')
    return redirect(url_for('admin_courses'))

# ── examinations ─────────────────────────────────────────────────────
@app.route('/admin/examinations')
@role_required('admin')
def admin_examinations():
    db = get_db()
    exams = db.execute('''SELECT e.*, c.course_name FROM examinations e
                          JOIN courses c ON e.course_id=c.id ORDER BY e.id DESC''').fetchall()
    db.close()
    return render_template('admin/examinations.html', exams=exams)

@app.route('/admin/examinations/create', methods=['GET','POST'])
@role_required('admin')
def admin_exam_create():
    db = get_db()
    if request.method == 'POST':
        db.execute('''INSERT INTO examinations
            (course_id,exam_name,exam_type,duration,max_marks,
             slot_creation_start,slot_creation_end,slot_booking_start,slot_booking_end,status)
            VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (request.form['course_id'], request.form['exam_name'], request.form['exam_type'],
             int(request.form['duration']), float(request.form['max_marks']),
             request.form.get('slot_creation_start',''), request.form.get('slot_creation_end',''),
             request.form.get('slot_booking_start',''), request.form.get('slot_booking_end',''),
             request.form.get('status','Draft')))
        db.commit()
        db.close()
        flash('Examination created.', 'success')
        return redirect(url_for('admin_examinations'))
    courses = db.execute("SELECT * FROM courses WHERE status='active'").fetchall()
    db.close()
    return render_template('admin/examinations.html', form_mode='create', courses=courses, exams=[])

@app.route('/admin/examinations/<int:eid>/edit', methods=['GET','POST'])
@role_required('admin')
def admin_exam_edit(eid):
    db = get_db()
    if request.method == 'POST':
        db.execute('''UPDATE examinations SET course_id=?,exam_name=?,exam_type=?,duration=?,max_marks=?,
            slot_creation_start=?,slot_creation_end=?,slot_booking_start=?,slot_booking_end=?,status=? WHERE id=?''',
            (request.form['course_id'], request.form['exam_name'], request.form['exam_type'],
             int(request.form['duration']), float(request.form['max_marks']),
             request.form.get('slot_creation_start',''), request.form.get('slot_creation_end',''),
             request.form.get('slot_booking_start',''), request.form.get('slot_booking_end',''),
             request.form.get('status','Draft'), eid))
        db.commit()
        db.close()
        flash('Examination updated.', 'success')
        return redirect(url_for('admin_examinations'))
    exam = db.execute('SELECT * FROM examinations WHERE id=?', (eid,)).fetchone()
    courses = db.execute("SELECT * FROM courses WHERE status='active'").fetchall()
    exams = db.execute('''SELECT e.*, c.course_name FROM examinations e
                          JOIN courses c ON e.course_id=c.id ORDER BY e.id DESC''').fetchall()
    db.close()
    return render_template('admin/examinations.html', form_mode='edit', edit_exam=exam, courses=courses, exams=exams)

@app.route('/admin/examinations/<int:eid>/delete', methods=['POST'])
@role_required('admin')
def admin_exam_delete(eid):
    db = get_db()
    db.execute('DELETE FROM examinations WHERE id=?', (eid,))
    db.commit()
    db.close()
    flash('Examination removed.', 'success')
    return redirect(url_for('admin_examinations'))

# ── rubrics ──────────────────────────────────────────────────────────
@app.route('/admin/rubrics/<int:eid>')
@role_required('admin')
def admin_rubrics(eid):
    db = get_db()
    exam = db.execute('SELECT * FROM examinations WHERE id=?', (eid,)).fetchone()
    rubrics = db.execute('SELECT * FROM rubrics WHERE exam_id=? ORDER BY id', (eid,)).fetchall()
    db.close()
    return render_template('admin/rubrics.html', exam=exam, rubrics=rubrics)

@app.route('/admin/rubrics/<int:eid>/create', methods=['POST'])
@role_required('admin')
def admin_rubric_create(eid):
    db = get_db()
    db.execute('INSERT INTO rubrics (exam_id,criterion_name,max_marks,weightage,description) VALUES (?,?,?,?,?)',
               (eid, request.form['criterion_name'], float(request.form['max_marks']),
                float(request.form['weightage']), request.form.get('description','')))
    db.commit()
    db.close()
    flash('Rubric added.', 'success')
    return redirect(url_for('admin_rubrics', eid=eid))

@app.route('/admin/rubrics/<int:rid>/delete', methods=['POST'])
@role_required('admin')
def admin_rubric_delete(rid):
    db = get_db()
    rubric = db.execute('SELECT exam_id FROM rubrics WHERE id=?', (rid,)).fetchone()
    eid = rubric['exam_id'] if rubric else 0
    db.execute('DELETE FROM rubrics WHERE id=?', (rid,))
    db.commit()
    db.close()
    flash('Rubric removed.', 'success')
    return redirect(url_for('admin_rubrics', eid=eid))

# ── examiners ────────────────────────────────────────────────────────
@app.route('/admin/examiners')
@role_required('admin')
def admin_examiners():
    db = get_db()
    examiners = db.execute("SELECT * FROM users WHERE role='examiner' ORDER BY id DESC").fetchall()
    db.close()
    return render_template('admin/examiners.html', examiners=examiners)

@app.route('/admin/examiners/<int:uid>/approve', methods=['POST'])
@role_required('admin')
def admin_examiner_approve(uid):
    db = get_db()
    db.execute("UPDATE users SET status='active' WHERE id=? AND role='examiner'", (uid,))
    db.commit()
    db.close()
    flash('Examiner approved.', 'success')
    return redirect(url_for('admin_examiners'))

@app.route('/admin/examiners/<int:uid>/deactivate', methods=['POST'])
@role_required('admin')
def admin_examiner_deactivate(uid):
    db = get_db()
    db.execute("UPDATE users SET status='deactivated' WHERE id=? AND role='examiner'", (uid,))
    db.commit()
    db.close()
    flash('Examiner deactivated.', 'success')
    return redirect(url_for('admin_examiners'))

@app.route('/admin/examiners/<int:uid>/activate', methods=['POST'])
@role_required('admin')
def admin_examiner_activate(uid):
    db = get_db()
    db.execute("UPDATE users SET status='active' WHERE id=? AND role='examiner'", (uid,))
    db.commit()
    db.close()
    flash('Examiner activated.', 'success')
    return redirect(url_for('admin_examiners'))

# ── students ─────────────────────────────────────────────────────────
@app.route('/admin/students')
@role_required('admin')
def admin_students():
    db = get_db()
    students = db.execute("SELECT * FROM users WHERE role='student' ORDER BY id DESC").fetchall()
    db.close()
    return render_template('admin/students.html', students=students)

# ── slots (admin view) ───────────────────────────────────────────────
@app.route('/admin/slots')
@role_required('admin')
def admin_slots():
    db = get_db()
    slots = db.execute('''SELECT s.*, e.exam_name, u.name as examiner_name
                          FROM examination_slots s
                          JOIN examinations e ON s.exam_id=e.id
                          JOIN users u ON s.examiner_id=u.id
                          ORDER BY s.date DESC, s.start_time''').fetchall()
    examiners = db.execute("SELECT id, name FROM users WHERE role='examiner' AND status='active'").fetchall()
    db.close()
    return render_template('admin/slots.html', slots=slots, examiners=examiners)

@app.route('/admin/slots/<int:sid>/change-examiner', methods=['POST'])
@role_required('admin')
def admin_change_examiner(sid):
    new_examiner_id = int(request.form['examiner_id'])
    db = get_db()
    db.execute('UPDATE examination_slots SET examiner_id=? WHERE id=?', (new_examiner_id, sid))
    db.commit()
    db.close()
    flash('Examiner changed.', 'success')
    return redirect(url_for('admin_slots'))

# ── bookings (admin) ─────────────────────────────────────────────────
@app.route('/admin/bookings')
@role_required('admin')
def admin_bookings():
    db = get_db()
    bookings = db.execute('''SELECT b.*, u.name as student_name, u.username,
                             s.date, s.start_time, s.end_time,
                             e.exam_name, ex.name as examiner_name
                             FROM bookings b
                             JOIN users u ON b.student_id=u.id
                             JOIN examination_slots s ON b.slot_id=s.id
                             JOIN examinations e ON s.exam_id=e.id
                             JOIN users ex ON s.examiner_id=ex.id
                             ORDER BY b.id DESC''').fetchall()
    slots = db.execute('''SELECT s.id, s.date, s.start_time, s.end_time, e.exam_name,
                          s.available_seats, u.name as examiner_name
                          FROM examination_slots s
                          JOIN examinations e ON s.exam_id=e.id
                          JOIN users u ON s.examiner_id=u.id
                          WHERE s.status='Available' AND s.available_seats>0
                          ORDER BY s.date''').fetchall()
    db.close()
    return render_template('admin/bookings.html', bookings=bookings, slots=slots)

@app.route('/admin/bookings/<int:bid>/reschedule', methods=['POST'])
@role_required('admin')
def admin_reschedule(bid):
    new_slot_id = int(request.form['new_slot_id'])
    db = get_db()
    old = db.execute('SELECT slot_id FROM bookings WHERE id=?', (bid,)).fetchone()
    if old:
        db.execute('UPDATE examination_slots SET available_seats=available_seats+1 WHERE id=?', (old['slot_id'],))
        db.execute("UPDATE examination_slots SET status='Available' WHERE id=? AND status='Full'", (old['slot_id'],))
    db.execute('UPDATE bookings SET slot_id=? WHERE id=?', (new_slot_id, bid))
    db.execute('UPDATE examination_slots SET available_seats=available_seats-1 WHERE id=?', (new_slot_id,))
    db.execute("UPDATE examination_slots SET status='Full' WHERE id=? AND available_seats<=0", (new_slot_id,))
    db.commit()
    db.close()
    flash('Booking rescheduled.', 'success')
    return redirect(url_for('admin_bookings'))

# ── search ───────────────────────────────────────────────────────────
@app.route('/admin/search')
@role_required('admin')
def admin_search():
    q = request.args.get('q', '').strip()
    results = {'students': [], 'examiners': [], 'exams': [], 'bookings': []}
    if q:
        db = get_db()
        like = f'%{q}%'
        results['students'] = db.execute(
            "SELECT * FROM users WHERE role='student' AND (name LIKE ? OR username LIKE ? OR CAST(id AS TEXT)=?)",
            (like, like, q)).fetchall()
        results['examiners'] = db.execute(
            "SELECT * FROM users WHERE role='examiner' AND (name LIKE ? OR username LIKE ? OR CAST(id AS TEXT)=?)",
            (like, like, q)).fetchall()
        results['exams'] = db.execute(
            "SELECT e.*, c.course_name FROM examinations e JOIN courses c ON e.course_id=c.id WHERE e.exam_name LIKE ? OR CAST(e.id AS TEXT)=?",
            (like, q)).fetchall()
        results['bookings'] = db.execute('''SELECT b.*, u.name as student_name, e.exam_name
            FROM bookings b JOIN users u ON b.student_id=u.id
            JOIN examination_slots s ON b.slot_id=s.id
            JOIN examinations e ON s.exam_id=e.id
            WHERE u.name LIKE ? OR CAST(b.id AS TEXT)=?''', (like, q)).fetchall()
        db.close()
    return render_template('admin/dashboard.html', stats=None, search_mode=True, query=q, results=results)

# ══════════════════════════════════════════════════════════════════════
#  EXAMINER ROUTES
# ══════════════════════════════════════════════════════════════════════
@app.route('/examiner/dashboard')
@role_required('examiner')
def examiner_dashboard():
    uid = session['user_id']
    db = get_db()
    exams = db.execute('''SELECT DISTINCT e.* FROM examinations e
                          JOIN examination_slots s ON e.id=s.exam_id
                          WHERE s.examiner_id=?''', (uid,)).fetchall()
    slot_count = db.execute('SELECT COUNT(*) c FROM examination_slots WHERE examiner_id=?', (uid,)).fetchone()['c']
    booked = db.execute('''SELECT COUNT(*) c FROM bookings b
                           JOIN examination_slots s ON b.slot_id=s.id
                           WHERE s.examiner_id=? AND b.status='Booked' ''', (uid,)).fetchone()['c']
    pending_eval = db.execute('''SELECT COUNT(*) c FROM bookings b
                                 JOIN examination_slots s ON b.slot_id=s.id
                                 WHERE s.examiner_id=? AND b.status='Booked'
                                 AND b.id NOT IN (SELECT DISTINCT booking_id FROM evaluations)''', (uid,)).fetchone()['c']
    # Also show exams in slot-creation period that examiner can create slots for
    available_exams = db.execute('''SELECT e.*, c.course_name FROM examinations e
                                    JOIN courses c ON e.course_id=c.id
                                    WHERE e.status IN ('Slot Creation','Booking Open')
                                    ORDER BY e.id DESC''').fetchall()
    db.close()
    return render_template('examiner/dashboard.html', exams=exams, slot_count=slot_count,
                           booked=booked, pending_eval=pending_eval, available_exams=available_exams)

@app.route('/examiner/slots')
@role_required('examiner')
def examiner_slots():
    uid = session['user_id']
    db = get_db()
    slots = db.execute('''SELECT s.*, e.exam_name, e.status as exam_status,
                          e.slot_creation_start, e.slot_creation_end,
                          e.slot_booking_start
                          FROM examination_slots s
                          JOIN examinations e ON s.exam_id=e.id
                          WHERE s.examiner_id=? ORDER BY s.date DESC''', (uid,)).fetchall()
    db.close()
    return render_template('examiner/slots.html', slots=slots)

@app.route('/examiner/slots/create', methods=['GET','POST'])
@role_required('examiner')
def examiner_slot_create():
    uid = session['user_id']
    db = get_db()
    if request.method == 'POST':
        eid = int(request.form['exam_id'])
        exam = db.execute('SELECT * FROM examinations WHERE id=?', (eid,)).fetchone()
        td = today_str()
        if exam and exam['slot_creation_start'] <= td <= exam['slot_creation_end']:
            cap = int(request.form['max_capacity'])
            db.execute('''INSERT INTO examination_slots
                (exam_id,examiner_id,date,start_time,end_time,max_capacity,available_seats,status)
                VALUES (?,?,?,?,?,?,?,'Available')''',
                (eid, uid, request.form['date'], request.form['start_time'],
                 request.form['end_time'], cap, cap))
            db.commit()
            flash('Slot created.', 'success')
        else:
            flash('Slot creation not allowed for this examination right now.', 'danger')
        db.close()
        return redirect(url_for('examiner_slots'))
    exams = db.execute("SELECT * FROM examinations WHERE status='Slot Creation'").fetchall()
    db.close()
    return render_template('examiner/slot_form.html', exams=exams, mode='create')

@app.route('/examiner/slots/<int:sid>/edit', methods=['GET','POST'])
@role_required('examiner')
def examiner_slot_edit(sid):
    uid = session['user_id']
    db = get_db()
    slot = db.execute('SELECT s.*, e.slot_booking_start FROM examination_slots s JOIN examinations e ON s.exam_id=e.id WHERE s.id=? AND s.examiner_id=?', (sid, uid)).fetchone()
    if not slot:
        db.close()
        flash('Slot not found.', 'danger')
        return redirect(url_for('examiner_slots'))
    if slot['slot_booking_start'] and today_str() >= slot['slot_booking_start']:
        db.close()
        flash('Cannot edit slot after booking has started.', 'danger')
        return redirect(url_for('examiner_slots'))
    if request.method == 'POST':
        cap = int(request.form['max_capacity'])
        booked = cap - slot['available_seats'] + (slot['max_capacity'] - slot['available_seats'])
        new_avail = cap - (slot['max_capacity'] - slot['available_seats'])
        db.execute('UPDATE examination_slots SET date=?,start_time=?,end_time=?,max_capacity=?,available_seats=? WHERE id=?',
                   (request.form['date'], request.form['start_time'], request.form['end_time'], cap, max(new_avail, 0), sid))
        db.commit()
        db.close()
        flash('Slot updated.', 'success')
        return redirect(url_for('examiner_slots'))
    exams = db.execute("SELECT * FROM examinations WHERE status='Slot Creation'").fetchall()
    db.close()
    return render_template('examiner/slot_form.html', exams=exams, mode='edit', slot=slot)

@app.route('/examiner/slots/<int:sid>/delete', methods=['POST'])
@role_required('examiner')
def examiner_slot_delete(sid):
    uid = session['user_id']
    db = get_db()
    slot = db.execute('SELECT s.*, e.slot_booking_start FROM examination_slots s JOIN examinations e ON s.exam_id=e.id WHERE s.id=? AND s.examiner_id=?', (sid, uid)).fetchone()
    if slot and (not slot['slot_booking_start'] or today_str() < slot['slot_booking_start']):
        db.execute('DELETE FROM examination_slots WHERE id=?', (sid,))
        db.commit()
        flash('Slot removed.', 'success')
    else:
        flash('Cannot delete slot after booking has started.', 'danger')
    db.close()
    return redirect(url_for('examiner_slots'))

@app.route('/examiner/slots/<int:sid>/students')
@role_required('examiner')
def examiner_booked_students(sid):
    uid = session['user_id']
    db = get_db()
    slot = db.execute('''SELECT s.*, e.exam_name FROM examination_slots s
                         JOIN examinations e ON s.exam_id=e.id
                         WHERE s.id=? AND s.examiner_id=?''', (sid, uid)).fetchone()
    bookings = db.execute('''SELECT b.*, u.name as student_name, u.username, u.email
                             FROM bookings b JOIN users u ON b.student_id=u.id
                             WHERE b.slot_id=? AND b.status='Booked' ORDER BY u.name''', (sid,)).fetchall()
    db.close()
    return render_template('examiner/booked_students.html', slot=slot, bookings=bookings)

@app.route('/examiner/evaluate/<int:bid>', methods=['GET','POST'])
@role_required('examiner')
def examiner_evaluate(bid):
    uid = session['user_id']
    db = get_db()
    booking = db.execute('''SELECT b.*, u.name as student_name, s.exam_id,
                            e.exam_name, s.examiner_id
                            FROM bookings b
                            JOIN users u ON b.student_id=u.id
                            JOIN examination_slots s ON b.slot_id=s.id
                            JOIN examinations e ON s.exam_id=e.id
                            WHERE b.id=? AND s.examiner_id=?''', (bid, uid)).fetchone()
    if not booking:
        db.close()
        flash('Booking not found or access denied.', 'danger')
        return redirect(url_for('examiner_dashboard'))
    rubrics = db.execute('SELECT * FROM rubrics WHERE exam_id=?', (booking['exam_id'],)).fetchall()
    existing = {ev['rubric_id']: ev for ev in
                db.execute('SELECT * FROM evaluations WHERE booking_id=?', (bid,)).fetchall()}
    if request.method == 'POST':
        for r in rubrics:
            marks = float(request.form.get(f'marks_{r["id"]}', 0))
            remarks = request.form.get(f'remarks_{r["id"]}', '')
            if r['id'] in existing:
                db.execute('UPDATE evaluations SET marks=?, remarks=? WHERE id=?',
                           (marks, remarks, existing[r['id']]['id']))
            else:
                db.execute('INSERT INTO evaluations (booking_id,rubric_id,marks,remarks) VALUES (?,?,?,?)',
                           (bid, r['id'], marks, remarks))
        db.execute("UPDATE bookings SET status='Completed' WHERE id=?", (bid,))
        db.commit()
        db.close()
        flash('Evaluation submitted.', 'success')
        return redirect(url_for('examiner_booked_students', sid=booking['slot_id']))
    db.close()
    return render_template('examiner/evaluate.html', booking=booking, rubrics=rubrics, existing=existing)

# ══════════════════════════════════════════════════════════════════════
#  STUDENT ROUTES
# ══════════════════════════════════════════════════════════════════════
@app.route('/student/dashboard')
@role_required('student')
def student_dashboard():
    uid = session['user_id']
    db = get_db()
    available_exams = db.execute('''SELECT e.*, c.course_name FROM examinations e
                                    JOIN courses c ON e.course_id=c.id
                                    WHERE e.status='Booking Open' ORDER BY e.id DESC''').fetchall()
    upcoming = db.execute('''SELECT b.id as booking_id, b.status as bstatus, s.date, s.start_time, s.end_time,
                             e.exam_name, u.name as examiner_name
                             FROM bookings b
                             JOIN examination_slots s ON b.slot_id=s.id
                             JOIN examinations e ON s.exam_id=e.id
                             JOIN users u ON s.examiner_id=u.id
                             WHERE b.student_id=? AND b.status='Booked' AND s.date>=?
                             ORDER BY s.date, s.start_time''', (uid, today_str())).fetchall()
    results_count = db.execute("SELECT COUNT(*) c FROM bookings WHERE student_id=? AND status='Completed'", (uid,)).fetchone()['c']
    total_bookings = db.execute('SELECT COUNT(*) c FROM bookings WHERE student_id=?', (uid,)).fetchone()['c']
    db.close()
    return render_template('student/dashboard.html', available_exams=available_exams,
                           upcoming=upcoming, results_count=results_count, total_bookings=total_bookings)

@app.route('/student/examinations')
@role_required('student')
def student_examinations():
    uid = session['user_id']
    db = get_db()
    q = request.args.get('q', '').strip()
    etype = request.args.get('type', '').strip()
    query = '''SELECT e.*, c.course_name FROM examinations e
               JOIN courses c ON e.course_id=c.id
               WHERE e.status='Booking Open' '''
    params = []
    if q:
        query += ' AND (e.exam_name LIKE ? OR c.course_name LIKE ?)'
        params += [f'%{q}%', f'%{q}%']
    if etype:
        query += ' AND e.exam_type=?'
        params.append(etype)
    query += ' ORDER BY e.id DESC'
    exams = db.execute(query, params).fetchall()
    # For each exam, get available slots
    exam_slots = {}
    for ex in exams:
        slots = db.execute('''SELECT s.*, u.name as examiner_name FROM examination_slots s
                              JOIN users u ON s.examiner_id=u.id
                              WHERE s.exam_id=? AND s.status='Available' AND s.available_seats>0
                              ORDER BY s.date, s.start_time''', (ex['id'],)).fetchall()
        exam_slots[ex['id']] = slots
    # Get student's existing bookings to prevent duplicates
    booked_exams = set()
    rows = db.execute('''SELECT DISTINCT s.exam_id FROM bookings b
                         JOIN examination_slots s ON b.slot_id=s.id
                         WHERE b.student_id=? AND b.status='Booked' ''', (uid,)).fetchall()
    for r in rows:
        booked_exams.add(r['exam_id'])
    db.close()
    return render_template('student/examinations.html', exams=exams, exam_slots=exam_slots,
                           booked_exams=booked_exams, query=q, etype=etype)

@app.route('/student/book/<int:slot_id>', methods=['POST'])
@role_required('student')
def student_book(slot_id):
    uid = session['user_id']
    db = get_db()
    slot = db.execute('SELECT * FROM examination_slots WHERE id=?', (slot_id,)).fetchone()
    if not slot or slot['status'] != 'Available' or slot['available_seats'] <= 0:
        flash('Slot not available.', 'danger')
        db.close()
        return redirect(url_for('student_examinations'))
    exam = db.execute('SELECT * FROM examinations WHERE id=?', (slot['exam_id'],)).fetchone()
    if not exam or exam['status'] != 'Booking Open':
        flash('Booking not open for this examination.', 'danger')
        db.close()
        return redirect(url_for('student_examinations'))
    if exam['slot_booking_end'] and today_str() > exam['slot_booking_end']:
        flash('Booking deadline passed.', 'danger')
        db.close()
        return redirect(url_for('student_examinations'))
    dup = db.execute('''SELECT b.id FROM bookings b
                        JOIN examination_slots s ON b.slot_id=s.id
                        WHERE b.student_id=? AND s.exam_id=? AND b.status='Booked' ''',
                     (uid, slot['exam_id'])).fetchone()
    if dup:
        flash('You already have a booking for this examination.', 'warning')
        db.close()
        return redirect(url_for('student_examinations'))
    db.execute('INSERT INTO bookings (student_id, slot_id, status) VALUES (?,?,"Booked")', (uid, slot_id))
    db.execute('UPDATE examination_slots SET available_seats=available_seats-1 WHERE id=?', (slot_id,))
    db.execute("UPDATE examination_slots SET status='Full' WHERE id=? AND available_seats<=0", (slot_id,))
    db.commit()
    db.close()
    flash('Slot booked successfully!', 'success')
    return redirect(url_for('student_bookings'))

@app.route('/student/bookings')
@role_required('student')
def student_bookings():
    uid = session['user_id']
    db = get_db()
    bookings = db.execute('''SELECT b.*, s.date, s.start_time, s.end_time,
                             e.exam_name, e.exam_type, e.slot_booking_end,
                             u.name as examiner_name
                             FROM bookings b
                             JOIN examination_slots s ON b.slot_id=s.id
                             JOIN examinations e ON s.exam_id=e.id
                             JOIN users u ON s.examiner_id=u.id
                             WHERE b.student_id=? ORDER BY b.id DESC''', (uid,)).fetchall()
    db.close()
    return render_template('student/bookings.html', bookings=bookings, today=today_str())

@app.route('/student/cancel/<int:bid>', methods=['POST'])
@role_required('student')
def student_cancel(bid):
    uid = session['user_id']
    db = get_db()
    booking = db.execute('''SELECT b.*, e.slot_booking_end, b.slot_id FROM bookings b
                            JOIN examination_slots s ON b.slot_id=s.id
                            JOIN examinations e ON s.exam_id=e.id
                            WHERE b.id=? AND b.student_id=? AND b.status='Booked' ''', (bid, uid)).fetchone()
    if not booking:
        flash('Booking not found.', 'danger')
        db.close()
        return redirect(url_for('student_bookings'))
    if booking['slot_booking_end'] and today_str() > booking['slot_booking_end']:
        flash('Cancellation deadline passed.', 'danger')
        db.close()
        return redirect(url_for('student_bookings'))
    db.execute("UPDATE bookings SET status='Cancelled' WHERE id=?", (bid,))
    db.execute('UPDATE examination_slots SET available_seats=available_seats+1 WHERE id=?', (booking['slot_id'],))
    db.execute("UPDATE examination_slots SET status='Available' WHERE id=? AND status='Full'", (booking['slot_id'],))
    db.commit()
    db.close()
    flash('Booking cancelled.', 'success')
    return redirect(url_for('student_bookings'))

@app.route('/student/results')
@role_required('student')
def student_results():
    uid = session['user_id']
    db = get_db()
    completed = db.execute('''SELECT b.id as booking_id, e.exam_name, e.max_marks,
                              s.date, u.name as examiner_name
                              FROM bookings b
                              JOIN examination_slots s ON b.slot_id=s.id
                              JOIN examinations e ON s.exam_id=e.id
                              JOIN users u ON s.examiner_id=u.id
                              WHERE b.student_id=? AND b.status='Completed'
                              ORDER BY s.date DESC''', (uid,)).fetchall()
    results = []
    for c in completed:
        evals = db.execute('''SELECT ev.marks, ev.remarks, r.criterion_name, r.max_marks, r.weightage
                              FROM evaluations ev JOIN rubrics r ON ev.rubric_id=r.id
                              WHERE ev.booking_id=?''', (c['booking_id'],)).fetchall()
        total = sum(e['marks'] for e in evals)
        results.append({'booking': c, 'evals': evals, 'total': total})
    db.close()
    return render_template('student/results.html', results=results)

@app.route('/student/profile', methods=['GET','POST'])
@role_required('student')
def student_profile():
    uid = session['user_id']
    db = get_db()
    if request.method == 'POST':
        db.execute('UPDATE users SET name=?, email=?, department=?, contact=? WHERE id=?',
                   (request.form['name'], request.form['email'],
                    request.form.get('department',''), request.form.get('contact',''), uid))
        db.commit()
        session['name'] = request.form['name']
        flash('Profile updated.', 'success')
    user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    db.close()
    return render_template('student/profile.html', user=user)

# ── run ──────────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('APP_PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
