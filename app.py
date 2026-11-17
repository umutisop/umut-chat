import os
import sqlite3
import secrets
from functools import wraps
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
PRODUCTION = os.environ.get("PRODUCTION") == "1"
SECRET_KEY = os.environ.get("SECRET_KEY")
if PRODUCTION and not SECRET_KEY:
    raise RuntimeError("Production ortamında SECRET_KEY ayarlanmalı.")
app.secret_key = SECRET_KEY or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=PRODUCTION,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,
)
ADMIN_SETUP_CODE = os.environ.get("ADMIN_SETUP_CODE", "")
DB = os.environ.get("DATABASE_PATH", "umut_chat.db")


def connect_db():
    db = sqlite3.connect(DB, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with connect_db() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )""")
        cols = [r["name"] for r in db.execute("PRAGMA table_info(users)")]
        if "role" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if "created_at" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
        db.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            time TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            used_by TEXT
        )""")


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        expected = session.get("csrf")
        if not supplied or not expected or not secrets.compare_digest(supplied, expected):
            return "İstek doğrulanamadı. Sayfayı yenileyip tekrar deneyin.", 400


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    if PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            if request.path == "/messages":
                return jsonify({"error": "Giriş gerekli."}), 401
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        with connect_db() as db:
            user = db.execute("SELECT role FROM users WHERE username=?", (session["user"],)).fetchone()
        if not user or user["role"] != "admin":
            return "Bu sayfaya yalnızca yönetici erişebilir.", 403
        return func(*args, **kwargs)
    return wrapper


STYLE = """
<style>
*{box-sizing:border-box}body{margin:0;background:#101322;color:#f5f6ff;font-family:Arial,sans-serif;padding:18px}
.box{background:#202944;padding:22px;border-radius:16px;width:100%;max-width:460px;margin:35px auto}
h1,h2{text-align:center}input,button{width:100%;padding:13px;margin:7px 0;border:0;border-radius:9px;font-size:15px}
input{background:#f5f6ff;color:#15182a}button{background:#7164ff;color:white;font-weight:bold;cursor:pointer}
a{color:#c5bcff;overflow-wrap:anywhere}.error{color:#ffaaaa}.note{color:#c5cbe0;font-size:13px;line-height:1.5}
.item{background:#171d31;padding:12px;border-radius:9px;margin:10px 0;overflow-wrap:anywhere}
</style>"""
AUTH = """<!doctype html><html lang=tr><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>UMUT CHAT</title>""" + STYLE + """</head><body><main class=box><h1>💬 UMUT CHAT</h1><h2>{{title}}</h2>{% if error %}<p class=error>{{error}}</p>{% endif %}
<form method=post><input type=hidden name=csrf_token value='{{csrf_token()}}'>
{% if show_invite %}<input name=invite placeholder='Davet kodu' value='{{invite or ""}}' required>{% endif %}
<input name=username placeholder='Kullanıcı adı' minlength=3 maxlength=20 autocomplete=username required>
<input name=password type=password placeholder='Şifre (en az 8 karakter)' minlength=8 autocomplete=current-password required>
{% if setup %}<input name=setup_code placeholder='İlk kurulum kodu' required>{% endif %}
<button type=submit>{{button}}</button></form><p>{{other_text}} <a href='{{other_url}}'>{{other_link}}</a></p></main></body></html>"""
CHAT = """<!doctype html><html lang=tr><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>UMUT CHAT</title>""" + STYLE + """<style>
body{padding:0}.top{background:#202944;padding:16px;text-align:center;font-size:22px;font-weight:bold}.info{background:#171d31;padding:12px;display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
#chat{height:calc(100vh - 190px);overflow-y:auto;padding:12px 12px 95px}.message{background:#252f4c;padding:11px;border-radius:10px;margin:9px 0;overflow-wrap:anywhere}.message p{white-space:pre-wrap;margin:8px 0}small{color:#aab5d2}
footer{position:fixed;bottom:0;left:0;width:100%;background:#171d31;padding:10px;display:flex;gap:8px}footer input{flex:1;width:auto;margin:0}footer button{width:105px;margin:0}
</style></head><body><div class=top>💬 UMUT CHAT</div><div class=info><span>Merhaba, <b>{{username}}</b>! · <a href=/admin>Yönetici paneli</a></span>
<form method=post action=/logout style='margin:0'><input type=hidden name=csrf_token value='{{csrf_token()}}'><button style='width:auto;padding:8px 14px;margin:0'>Çıkış</button></form></div>
<div id=chat aria-live=polite></div><footer><input id=msg maxlength=500 placeholder='Mesajını yaz...' autocomplete=off><button id=send>GÖNDER</button></footer>
<script>
const csrf={{csrf_token()|tojson}};let lastSignature='';
async function loadMessages(){try{const r=await fetch('/messages',{credentials:'same-origin'});if(r.status===401){location.href='/login';return;}if(!r.ok)return;const data=await r.json();const sig=data.length?data[data.length-1].id+':'+data.length:'0';if(sig===lastSignature)return;lastSignature=sig;const chat=document.getElementById('chat');chat.replaceChildren();for(const m of data){const d=document.createElement('div');d.className='message';const b=document.createElement('b');b.textContent=m.username;const p=document.createElement('p');p.textContent=m.text;const s=document.createElement('small');s.textContent=m.time;d.append(b,p,s);chat.appendChild(d);}chat.scrollTop=chat.scrollHeight;}catch(e){console.log('Mesajlar yüklenemedi.');}}
async function sendMessage(){const input=document.getElementById('msg');const value=input.value.trim();if(!value)return;const btn=document.getElementById('send');btn.disabled=true;try{const r=await fetch('/send',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({text:value})});if(r.ok){input.value='';await loadMessages();}else{alert('Mesaj gönderilemedi. Sayfayı yenileyip tekrar deneyin.');}}finally{btn.disabled=false;input.focus();}}
document.getElementById('send').addEventListener('click',sendMessage);document.getElementById('msg').addEventListener('keydown',e=>{if(e.key==='Enter')sendMessage();});loadMessages();setInterval(loadMessages,2000);
</script></body></html>"""
ADMIN = """<!doctype html><html lang=tr><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>UMUT CHAT Yönetim</title>""" + STYLE + """</head><body><main class=box><h1>⚙️ Yönetici Paneli</h1><p><a href=/chat>← Sohbete dön</a></p>
<h2>Davet bağlantısı oluştur</h2><form method=post action=/admin/invite><input type=hidden name=csrf_token value='{{csrf_token()}}'><button>YENİ DAVET OLUŞTUR</button></form>
{% if new_link %}<div class=item><b>Yeni davet bağlantısı:</b><br><a href='{{new_link}}'>{{new_link}}</a><p class=note>Bu bağlantı bir kişi tarafından kullanılabilir. Yalnızca güvendiğiniz kişiye gönderin.</p></div>{% endif %}
<h2>Bekleyen davetler</h2>{% for invite in invites %}<div class=item><a href='{{invite.link}}'>{{invite.link}}</a></div>{% else %}<p>Bekleyen davet yok.</p>{% endfor %}
<h2>Üyeler</h2>{% for member in members %}<div class=item>{{member.username}} — {{'Yönetici' if member.role=='admin' else 'Üye'}}</div>{% else %}<p>Henüz üye yok.</p>{% endfor %}</main></body></html>"""


def valid_username(username):
    return 3 <= len(username) <= 20 and username.replace("_", "").isalnum()


@app.route("/")
def home():
    return redirect("/chat" if "user" in session else "/login")


@app.route("/setup", methods=["GET", "POST"])
def setup():
    with connect_db() as db:
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count:
        return "İlk yönetici hesabı zaten oluşturulmuş.", 403
    if not ADMIN_SETUP_CODE:
        return "Kurulum kapalı: Hosting ortamında ADMIN_SETUP_CODE ayarlanmalı.", 503
    error = ""
    if request.method == "POST":
        username=request.form.get("username", "").strip(); password=request.form.get("password", ""); code=request.form.get("setup_code", "")
        if not secrets.compare_digest(code, ADMIN_SETUP_CODE): error="İlk kurulum kodu hatalı."
        elif not valid_username(username): error="Kullanıcı adı 3-20 karakter olmalı; harf, rakam ve _ kullanın."
        elif len(password)<8: error="Şifre en az 8 karakter olmalı."
        else:
            try:
                with connect_db() as db: db.execute("INSERT INTO users(username,password,role,created_at) VALUES(?,?,?,?)",(username,generate_password_hash(password),"admin",datetime.utcnow().isoformat()))
                session.clear(); session.permanent=True; session["user"]=username; return redirect("/admin")
            except sqlite3.IntegrityError: error="Bu kullanıcı adı zaten kullanılıyor."
    return render_template_string(AUTH,title="İlk yönetici hesabını oluştur",button="YÖNETİCİ HESABI OLUŞTUR",error=error,show_invite=False,invite="",setup=True,other_text="Hesabın var mı?",other_link="Giriş yap",other_url="/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    error=""; invite=request.args.get("invite", "") or request.form.get("invite", "")
    if request.method=="POST":
        username=request.form.get("username", "").strip(); password=request.form.get("password", "")
        if not valid_username(username): error="Kullanıcı adı 3-20 karakter olmalı; harf, rakam ve _ kullanın."
        elif len(password)<8: error="Şifre en az 8 karakter olmalı."
        elif not invite: error="Kayıt olmak için davet bağlantısı gerekli."
        else:
            try:
                with connect_db() as db:
                    db.execute("BEGIN IMMEDIATE"); row=db.execute("SELECT id,used FROM invites WHERE code=?",(invite,)).fetchone()
                    if not row or row["used"]: raise ValueError("Davet bağlantısı geçersiz veya daha önce kullanılmış.")
                    db.execute("INSERT INTO users(username,password,role,created_at) VALUES(?,?,?,?)",(username,generate_password_hash(password),"user",datetime.utcnow().isoformat()))
                    changed=db.execute("UPDATE invites SET used=1,used_by=? WHERE id=? AND used=0",(username,row["id"])).rowcount
                    if changed!=1: raise ValueError("Bu davet bağlantısı başka biri tarafından kullanılmış.")
                session.clear(); session.permanent=True; session["user"]=username; return redirect("/chat")
            except ValueError as exc: error=str(exc)
            except sqlite3.IntegrityError: error="Bu kullanıcı adı zaten kullanılıyor."
    return render_template_string(AUTH,title="Davetle hesap oluştur",button="KAYIT OL",error=error,show_invite=True,invite=invite,setup=False,other_text="Zaten hesabın var mı?",other_link="Giriş yap",other_url="/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    error=""
    if request.method=="POST":
        username=request.form.get("username", "").strip(); password=request.form.get("password", "")
        with connect_db() as db: user=db.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        if user and check_password_hash(user["password"],password):
            session.clear(); session.permanent=True; session["user"]=username; return redirect("/chat")
        error="Kullanıcı adı veya şifre hatalı."
    return render_template_string(AUTH,title="Giriş yap",button="GİRİŞ YAP",error=error,show_invite=False,invite="",setup=False,other_text="İlk yönetici misin?",other_link="Kurulumu yap",other_url="/setup")


@app.route("/logout",methods=["POST"])
@login_required
def logout(): session.clear(); return redirect("/login")


@app.route("/admin")
@admin_required
def admin():
    with connect_db() as db:
        pending=db.execute("SELECT code FROM invites WHERE used=0 ORDER BY id DESC").fetchall(); members=db.execute("SELECT username,role FROM users ORDER BY id").fetchall()
    invites=[{"link":url_for("register",invite=r["code"],_external=True)} for r in pending]
    return render_template_string(ADMIN,invites=invites,members=members,new_link=session.pop("new_invite_link",None))


@app.route("/admin/invite",methods=["POST"])
@admin_required
def create_invite():
    code=secrets.token_urlsafe(24)
    with connect_db() as db: db.execute("INSERT INTO invites(code,created_at) VALUES(?,?)",(code,datetime.utcnow().isoformat()))
    session["new_invite_link"]=url_for("register",invite=code,_external=True); return redirect("/admin")


@app.route("/chat")
@login_required
def chat(): return render_template_string(CHAT,username=session["user"])


@app.route("/messages")
@login_required
def get_messages():
    with connect_db() as db: rows=db.execute("SELECT id,username,text,time FROM messages ORDER BY id DESC LIMIT 200").fetchall()
    return jsonify([dict(r) for r in reversed(rows)])


@app.route("/send",methods=["POST"])
@login_required
def send():
    data=request.get_json(silent=True) or {}; message=str(data.get("text", "")).strip()[:500]
    if not message: return jsonify({"error":"Boş mesaj gönderilemez."}),400
    with connect_db() as db: db.execute("INSERT INTO messages(username,text,time) VALUES(?,?,?)",(session["user"],message,datetime.now().strftime("%H:%M")))
    return jsonify({"success":True})


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)
