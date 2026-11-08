# TrustVault - Fixed Login + Admin / Owner / Viewer Roles
import os, sqlite3, secrets
from datetime import datetime, timedelta
from flask import Flask, request, redirect, session, send_file, flash, g, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
app = Flask(__name__)
app.secret_key = 'trust-vault-secret-2026'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
KEY_FILE='secret.key'
if os.path.exists(KEY_FILE):
    with open(KEY_FILE,'rb') as f: KEY=f.read()
else:
    KEY=Fernet.generate_key(); open(KEY_FILE,'wb').write(KEY)
cipher=Fernet(KEY)

def get_db():
    if 'db' not in g:
        g.db=sqlite3.connect('trustvault.db'); g.db.row_factory=sqlite3.Row
    return g.db
@app.teardown_appcontext
def close_db(e):
    db=g.pop('db',None)
    if db: db.close()

def init_db():
    db=sqlite3.connect('trustvault.db')
    db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, fullname TEXT, password TEXT, role TEXT DEFAULT "owner")')
    db.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, owner_id INTEGER, owner_name TEXT, title TEXT, category TEXT, stored_name TEXT, size INTEGER, upload_date TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS shares (id INTEGER PRIMARY KEY, file_id INTEGER, token TEXT UNIQUE, expiry TEXT, created_by INTEGER)')
    # --- FIX: Auto Create Demo Accounts (So login never fails) ---
    demo = [
        ('admin','Admin User','admin123','admin'),
        ('alice','Alice Rao','alice123','owner'),
        ('viewer','Viewer User','viewer123','viewer'),
        ('owner','Owner User','owner123','owner'),
    ]
    for u, fn, pw, role in demo:
        cur=db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not cur:
            db.execute("INSERT INTO users (username,fullname,password,role) VALUES (?,?,?,?)",(u,fn,generate_password_hash(pw),role))
        else:
            # If user exists but password changed, reset it
            db.execute("UPDATE users SET password=?, role=?, fullname=? WHERE username=?",(generate_password_hash(pw),role,fn,u))
    db.commit(); db.close()
init_db()

BASE = """<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>TrustVault</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:#eef2f7;font-family:Arial} .header{background:#0a2a5e;color:white;padding:14px 20px} .header a{color:white;text-decoration:none} .nav-tab{padding:8px 18px;border-radius:8px;color:white} .nav-tab.active{background:#1e4a8a} .card-doc{background:white;border-radius:12px;padding:18px;box-shadow:0 1px 4px rgba(0,0,0,.08);position:relative} .badge-owner{background:#0a2a5e;color:white;font-size:11px;padding:4px 10px;border-radius:5px;position:absolute;top:14px;right:14px} .btn-navy{background:#0a2a5e;color:white;border:none;padding:10px 22px;border-radius:8px} .filter-box{background:white;padding:16px;border-radius:12px} input,select{border:1px solid #d0d7e3!important;border-radius:8px!important}</style></head><body>
<div class="header d-flex justify-content-between align-items-center flex-wrap gap-2"><div class="d-flex align-items-center gap-3"><span style="font-size:24px;font-weight:700">🛡️ TrustVault</span><a href="/overview" class="nav-tab">Overview</a><a href="/documents" class="nav-tab">Documents</a></div><div class="d-flex align-items-center gap-2"><span>👤 {{session.fullname or session.username}} ({{session.role}})</span><span style="background:#1e4a8a;font-size:12px;padding:4px 12px;border-radius:20px">{{session.role}}</span><a href="/logout" style="border:1px solid white;padding:6px 14px;border-radius:8px">Log out</a></div></div>
<div class="container-fluid px-3 py-3">{% with m=get_flashed_messages(with_categories=true) %}{% for c,msg in m %}<div class="alert alert-{{c}}">{{msg}}</div>{% endfor %}{% endwith %}CONTENT</div></body></html>"""
def render_page(content, **kw): return render_template_string(BASE.replace("CONTENT", content), **kw)
LOGIN = """<div class="row justify-content-center mt-5"><div class="col-md-5"><div class="card p-4"><h3 class="text-center">TrustVault Login</h3><form method="POST"><input name="username" class="form-control mb-2" placeholder="Username" required><input name="password" type="password" class="form-control mb-3" placeholder="Password" required><button class="btn-navy w-100">Login</button></form><hr><p class="small"><b>Demo Logins (Use These):</b><br>👑 Admin - <b>admin / admin123</b> - Sees ALL files<br>📄 Owner - <b>alice / alice123</b> - Own files only<br>👀 Viewer - <b>viewer / viewer123</b> - View only, No Upload/Delete</p><p class="text-center mt-2"><a href="/register">Create Account</a></p></div></div></div>"""
REGISTER = """<div class="row justify-content-center mt-5"><div class="col-md-4"><div class="card p-4"><h3 class="text-center">Create Account</h3><form method="POST"><input name="fullname" class="form-control mb-2" placeholder="Full Name" required><input name="username" class="form-control mb-2" placeholder="Username" required><input name="password" type="password" class="form-control mb-2" placeholder="Password" required><select name="role" class="form-control mb-3"><option value="owner">Owner</option><option value="viewer">Viewer</option><option value="admin">Admin</option></select><button class="btn-navy w-100">Register</button></form><p class="text-center mt-3"><a href="/login">Login</a></p></div></div></div>"""
OVERVIEW = """<h1 class="text-center mt-3" style="color:#0a2a5e;font-weight:700">Welcome, {{fullname}} ({{role}})</h1><p class="text-center fs-4" style="color:#5a6b8a">What would you like to do?</p><div class="row justify-content-center mt-4"><div class="col-md-6"><div class="card-doc"><div style="background:#e8efff;width:60px;height:60px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:28px">📄</div><h3 class="mt-3">Open my documents</h3><p style="color:#5a6b8a">Search, open and download the documents you own or that were shared with you.</p><a href="/documents" class="btn-navy" style="text-decoration:none;display:inline-block">Documents</a></div></div><div class="col-md-6 mt-3 mt-md-0"><div class="card-doc"><div style="background:#e8efff;width:60px;height:60px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:28px">⬆️</div><h3 class="mt-3">Upload a document</h3><p style="color:#5a6b8a">Upload securely. Encrypted before storage. Viewer cannot upload.</p><a href="/documents" class="btn-navy" style="text-decoration:none;display:inline-block">Upload</a></div></div></div>"""
DOCUMENTS = """<div class="d-flex justify-content-between align-items-center flex-wrap gap-2"><div><h3>Documents</h3><p style="color:#5a6b8a">Role: {{role}} | {% if role=='admin' %}Admin sees ALL documents{% elif role=='viewer' %}Viewer - View Only{% else %}Only your documents{% endif %}</p></div>{% if role!='viewer' %}<button class="btn-navy" onclick="document.getElementById('uploadForm').style.display='block'">Upload a document</button>{% endif %}</div><div id="uploadForm" class="filter-box mb-3" style="display:none"><form action="/upload" method="POST" enctype="multipart/form-data"><div class="row g-2"><div class="col-md-4"><label>Title</label><input name="title" class="form-control" required></div><div class="col-md-3"><label>Category</label><select name="category" class="form-control"><option>Contract</option><option>Drawing</option><option>Salary letter</option><option>Other</option></select></div><div class="col-md-3"><label>File</label><input type="file" name="file" class="form-control" required></div><div class="col-md-2 d-flex align-items-end"><button class="btn-navy w-100">Upload</button></div></div></form></div><div class="filter-box mb-3"><form method="GET" class="row g-2 align-items-end"><div class="col-md-2"><label>Title contains</label><input name="q" value="{{q}}" class="form-control"></div><div class="col-md-2"><label>Category</label><select name="cat" class="form-control"><option value="">All</option><option>Contract</option><option>Drawing</option><option>Salary letter</option><option>Other</option></select></div><div class="col-md-2"><label>Owner</label><input name="owner" value="{{owner}}" class="form-control"></div><div class="col-md-2"><label>Uploaded from</label><input name="from" type="date" class="form-control"></div><div class="col-md-2"><label>Uploaded to</label><input name="to" type="date" class="form-control"></div><div class="col-md-2"><button class="btn-navy">Search</button></div></form></div><div class="row">{% for f in files %}<div class="col-md-6 col-lg-4 mb-3"><div class="card-doc"><span class="badge-owner">{{f.owner_name}}</span><div style="font-size:22px">📄</div><h5 class="mt-2">{{f.title}}</h5><p style="color:#5a6b8a">{{f.category}} · {{f.owner_name}}</p><hr><p class="small" style="color:#5a6b8a">Uploaded {{f.upload_date}} · {{f.size_str}}</p><div class="d-flex gap-2"><a href="/download/{{f.id}}" class="btn btn-sm btn-outline-primary">Download</a>{% if role!='viewer' %}<a href="/share/{{f.id}}" class="btn btn-sm btn-outline-secondary">Share</a><a href="/delete/{{f.id}}" class="btn btn-sm btn-outline-danger">Delete</a>{% endif %}</div></div></div>{% else %}<p class="text-center">No documents yet.</p>{% endfor %}</div>"""
SHARE_PAGE = """<div class="card-doc mx-auto" style="max-width:500px"><h4>Share: {{file.title}}</h4>{% if created %}<div class="alert alert-success">Link:<br><b>{{link}}</b></div><a href="/documents" class="btn-navy" style="text-decoration:none">Back</a>{% else %}<form method="POST"><label>Expiry Hours</label><input name="expiry_hours" type="number" value="24" class="form-control mb-3"><button class="btn-navy w-100">Generate Secure Link</button></form>{% endif %}</div>"""

@app.route('/')
def index(): return redirect('/overview' if 'user_id' in session else '/login')
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        db=get_db()
        try: db.execute("INSERT INTO users (username,fullname,password,role) VALUES (?,?,?,?)",(request.form['username'],request.form['fullname'],generate_password_hash(request.form['password']),request.form.get('role','owner'))); db.commit(); flash('Account created! Login now.','success'); return redirect('/login')
        except: flash('Username exists','danger')
    return render_page(REGISTER)
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        db=get_db(); u=db.execute("SELECT * FROM users WHERE username=?", (request.form['username'].strip(),)).fetchone()
        if u and check_password_hash(u['password'], request.form['password'].strip()):
            session['user_id']=u['id']; session['username']=u['username']; session['fullname']=u['fullname']; session['role']=u['role'] or 'owner'; return redirect('/overview')
        flash('Invalid login - Try admin/admin123 or alice/alice123 or viewer/viewer123','danger')
    return render_page(LOGIN)
@app.route('/logout')
def logout(): session.clear(); return redirect('/login')
@app.route('/overview')
def overview():
    if 'user_id' not in session: return redirect('/login')
    return render_page(OVERVIEW, fullname=session.get('fullname'), role=session.get('role'))
@app.route('/documents')
def documents():
    if 'user_id' not in session: return redirect('/login')
    db=get_db(); q=request.args.get('q',''); owner=request.args.get('owner',''); cat=request.args.get('cat',''); role=session.get('role','owner')
    if role=='admin': sql="SELECT * FROM files WHERE 1=1"; params=[]
    elif role=='viewer': sql="SELECT * FROM files WHERE 1=1"; params=[]
    else: sql="SELECT * FROM files WHERE owner_id=?"; params=[session['user_id']]
    if q: sql+=" AND title LIKE ?"; params.append(f"%{q}%")
    if cat: sql+=" AND category=?"; params.append(cat)
    if owner: sql+=" AND owner_name LIKE ?"; params.append(f"%{owner}%")
    sql+=" ORDER BY id DESC"; rows=db.execute(sql, params).fetchall(); files=[]
    for r in rows:
        d=dict(r); sz=r['size']; d['size_str']=f"{sz/1024:.1f} kB" if sz>1024 else f"{sz} Bytes"; files.append(d)
    return render_page(DOCUMENTS, files=files, q=q, owner=owner, role=role)
@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session: return redirect('/login')
    if session.get('role')=='viewer': flash('Viewer cannot upload!','danger'); return redirect('/documents')
    f=request.files.get('file')
    if not f: return redirect('/documents')
    title=request.form.get('title') or secure_filename(f.filename); cat=request.form.get('category') or 'Other'; stored=f"{secrets.token_hex(8)}.enc"; data=f.read(); enc=cipher.encrypt(data); open(os.path.join(app.config['UPLOAD_FOLDER'],stored),'wb').write(enc)
    db=get_db(); db.execute("INSERT INTO files (owner_id,owner_name,title,category,stored_name,size,upload_date) VALUES (?,?,?,?,?,?,?)",(session['user_id'],session.get('fullname'),title,cat,stored,len(data),datetime.now().strftime("%Y-%m-%d %H:%M UTC"))); db.commit(); flash(f'{title} uploaded & encrypted!','success'); return redirect('/documents')
@app.route('/download/<int:fid>')
def download(fid):
    if 'user_id' not in session: return redirect('/login')
    db=get_db()
    if session.get('role')=='admin': f=db.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    else: f=db.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    if not f: return redirect('/documents')
    dec=cipher.decrypt(open(os.path.join(app.config['UPLOAD_FOLDER'],f['stored_name']),'rb').read()); tmp=f"/tmp/{f['title']}"; open(tmp,'wb').write(dec); return send_file(tmp, as_attachment=True, download_name=f['title'])
@app.route('/delete/<int:fid>')
def delete_file(fid):
    if 'user_id' not in session: return redirect('/login')
    if session.get('role')=='viewer': flash('Viewer cannot delete!','danger'); return redirect('/documents')
    db=get_db()
    if session.get('role')=='admin': f=db.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    else: f=db.execute("SELECT * FROM files WHERE id=? AND owner_id=?", (fid,session['user_id'])).fetchone()
    if f:
        try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'],f['stored_name']))
        except: pass
        db.execute("DELETE FROM files WHERE id=?", (fid,)); db.commit()
    return redirect('/documents')
@app.route('/share/<int:fid>', methods=['GET','POST'])
def share(fid):
    if 'user_id' not in session: return redirect('/login')
    if session.get('role')=='viewer': flash('Viewer cannot share!','danger'); return redirect('/documents')
    db=get_db(); f=db.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    if not f: return redirect('/documents')
    if request.method=='POST':
        token=secrets.token_urlsafe(10); hours=int(request.form.get('expiry_hours') or 24); expiry=(datetime.now()+timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M"); db.execute("INSERT INTO shares (file_id,token,expiry,created_by) VALUES (?,?,?,?)",(fid,token,expiry,session['user_id'])); db.commit(); return render_page(SHARE_PAGE, file=f, link=request.host_url+f"s/{token}", created=True)
    return render_page(SHARE_PAGE, file=f, created=False)
@app.route('/s/<token>')
def view_shared(token):
    db=get_db(); s=db.execute("SELECT s.*, f.title, f.stored_name FROM shares s JOIN files f ON s.file_id=f.id WHERE token=?", (token,)).fetchone()
    if not s: return "<h2>Link Invalid</h2>"
    dec=cipher.decrypt(open(os.path.join(app.config['UPLOAD_FOLDER'],s['stored_name']),'rb').read()); tmp=f"/tmp/{s['title']}"; open(tmp,'wb').write(dec); return send_file(tmp, as_attachment=True, download_name=s['title'])
if __name__=='__main__': app.run(debug=True, host='0.0.0.0', port=5000)
