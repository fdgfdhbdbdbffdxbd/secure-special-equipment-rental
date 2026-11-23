import base64
import io
import os
import secrets
import uuid
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation

import click
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, send_file, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import select

load_dotenv()
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET"],
    SQLALCHEMY_DATABASE_URI=os.environ["DATABASE_URL"],
    SESSION_COOKIE_SECURE=os.getenv("DEV_HTTP") != "1",
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
)
db = SQLAlchemy(app)
CSRFProtect(app)
hasher = PasswordHasher()
dummy_hash = hasher.hash(secrets.token_hex(32))
key = base64.b64decode(os.environ["DATA_KEY"], validate=True)
if len(key) != 32:
    raise ValueError("DATA_KEY must decode to 32 bytes")
aes = AESGCM(key)


class User(db.Model):
    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    login = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    phone = db.Column(db.LargeBinary)
    role = db.Column(db.String(12), nullable=False, default="client")


class LoginSession(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Uuid, db.ForeignKey("user.id"), nullable=False)
    expires = db.Column(db.DateTime(timezone=True), nullable=False)


class Machine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    kind = db.Column(db.String(20), nullable=False)
    hourly = db.Column(db.Integer, nullable=False)
    dispatch = db.Column(db.Integer, nullable=False)
    per_km = db.Column(db.Integer, nullable=False)


class Rental(db.Model):
    id = db.Column(db.Uuid, primary_key=True, default=uuid.uuid4)
    user_id = db.Column(db.Uuid, db.ForeignKey("user.id"), nullable=False, index=True)
    machine_id = db.Column(db.Integer, db.ForeignKey("machine.id"), nullable=False)
    day = db.Column(db.Date, nullable=False)
    hours = db.Column(db.Integer, nullable=False)
    km = db.Column(db.Numeric(8, 2), nullable=False)
    delivery = db.Column(db.Numeric(12, 2), nullable=False)
    total = db.Column(db.Numeric(12, 2), nullable=False)
    status = db.Column(db.String(12), nullable=False, default="new")
    note = db.Column(db.String(300), nullable=False, default="")


class Contract(db.Model):
    id = db.Column(db.Uuid, primary_key=True)
    rental_id = db.Column(db.Uuid, db.ForeignKey("rental.id"), unique=True, nullable=False)
    blob = db.Column(db.LargeBinary, nullable=False)
    key_version = db.Column(db.Integer, nullable=False, default=1)


class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    actor = db.Column(db.Uuid, db.ForeignKey("user.id"))
    action = db.Column(db.String(32), nullable=False)
    target = db.Column(db.Uuid)


def seal(raw, context):
    nonce = secrets.token_bytes(12)
    return nonce + aes.encrypt(nonce, raw, context)


def unseal(blob, context):
    return aes.decrypt(blob[:12], blob[12:], context)


def actor():
    record = db.session.get(LoginSession, session.get("sid", ""))
    if record and record.expires > db.session.scalar(select(db.func.now())):
        return db.session.get(User, record.user_id)
    return None


def log(action, user=None, target=None):
    db.session.add(Audit(action=action, actor=user.id if user else None, target=target))


def require(*roles):
    user = actor()
    if not user:
        abort(401)
    if user.role not in roles:
        log("forbidden", user)
        db.session.commit()
        abort(403)
    return user


def rental_access(rental_id):
    user = require("client", "staff")
    rental = db.session.get(Rental, rental_id)
    if not rental or (user.role == "client" and rental.user_id != user.id):
        log("rental_denied", user, rental_id)
        db.session.commit()
        abort(404)
    return user, rental


@app.after_request
def headers(response):
    response.headers.update({
        "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    })
    return response


@app.route("/")
def index():
    return render_template("page.html", user=actor(), machines=db.session.scalars(select(Machine).order_by(Machine.id)).all())


@app.post("/register")
def register():
    name = request.form.get("login", "").strip().lower()
    password = request.form.get("password", "")
    phone = request.form.get("phone", "").strip()
    if not (3 <= len(name) <= 64 and name.isascii() and name.isalnum()
            and 12 <= len(password) <= 128 and len(phone) <= 25):
        abort(400)
    uid = uuid.uuid4()
    user = User(id=uid, login=name, password_hash=hasher.hash(password),
                phone=seal(phone.encode(), b"phone:v1:" + uid.bytes) if phone else None)
    db.session.add(user)
    try:
        db.session.commit()
    except db.exc.IntegrityError:
        db.session.rollback()
        abort(409)
    return redirect(url_for("index"))


@app.post("/login")
def login():
    name = request.form.get("login", "").strip().lower()
    password = request.form.get("password", "")
    if len(name) > 64 or len(password) > 128:
        abort(400)
    user = db.session.scalar(select(User).where(User.login == name))
    try:
        hasher.verify(user.password_hash if user else dummy_hash, password)
    except VerifyMismatchError:
        log("login_failed")
        db.session.commit()
        abort(401)
    if user is None:
        abort(401)
    previous = db.session.get(LoginSession, session.get("sid", ""))
    if previous:
        db.session.delete(previous)
    sid = secrets.token_hex(32)
    db.session.add(LoginSession(id=sid, user_id=user.id,
                                expires=db.session.scalar(select(db.func.now())) + timedelta(hours=2)))
    log("login", user)
    db.session.commit()
    session.clear()
    session["sid"] = sid
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    record = db.session.get(LoginSession, session.get("sid", ""))
    if record:
        db.session.delete(record)
        db.session.commit()
    session.clear()
    return redirect(url_for("index"))


def quote(machine, hours, km):
    delivery = machine.dispatch + 2 * km * machine.per_km
    return delivery, delivery + hours * machine.hourly


@app.route("/rentals", methods=["GET", "POST"])
def rentals():
    user = require("client", "staff")
    if request.method == "POST":
        if user.role != "client":
            abort(403)
        try:
            machine_id = int(request.form["machine"])
            day = date.fromisoformat(request.form["day"])
            hours = int(request.form["hours"])
            km = Decimal(request.form["km"])
            if not km.is_finite() or not 0 <= km <= 500 or km.as_tuple().exponent < -2:
                abort(400)
        except (ValueError, InvalidOperation):
            abort(400)
        machine = db.session.get(Machine, machine_id)
        note = request.form.get("note", "")
        if not machine or not 1 <= hours <= 72 or day < date.today() or len(note) > 300:
            abort(400)
        delivery, total = quote(machine, hours, km)
        db.session.add(Rental(user_id=user.id, machine_id=machine.id, day=day,
                              hours=hours, km=km, delivery=delivery, total=total, note=note))
        db.session.commit()
        return redirect(url_for("rentals"))
    query = select(Rental)
    if user.role == "client":
        query = query.where(Rental.user_id == user.id)
    offset = max(0, min(request.args.get("offset", 0, type=int), 100000))
    rows = db.session.scalars(query.order_by(Rental.day.desc(), Rental.id).offset(offset).limit(51)).all()
    return render_template("page.html", user=user, rentals=rows[:50], offset=offset, more=len(rows) > 50)


@app.route("/rentals/<uuid:rental_id>", methods=["GET", "POST"])
def detail(rental_id):
    user, rental = rental_access(rental_id)
    if request.method == "POST":
        rental = db.session.scalar(select(Rental).where(Rental.id == rental_id).with_for_update().execution_options(populate_existing=True))
        transitions = {"staff": {"new": {"accepted", "cancelled"}, "accepted": {"closed"}},
                       "client": {"new": {"cancelled"}}}
        next_status = request.form.get("status")
        if next_status not in transitions[user.role].get(rental.status, set()):
            abort(409)
        rental.status = next_status
        log("status_changed", user, rental_id)
        db.session.commit()
        return redirect(url_for("detail", rental_id=rental_id))
    contract = db.session.scalar(select(Contract.id).where(Contract.rental_id == rental_id))
    return render_template("page.html", user=user, rental=rental, contract=contract)


@app.route("/rentals/<uuid:rental_id>/contract", methods=["POST", "GET"])
def document(rental_id):
    user, rental = rental_access(rental_id)
    if request.method == "POST":
        if user.role != "staff":
            abort(403)
        rental = db.session.scalar(select(Rental).where(Rental.id == rental_id).with_for_update().execution_options(populate_existing=True))
        if rental.status != "accepted" or db.session.scalar(select(Contract.id).where(Contract.rental_id == rental_id)):
            abort(409)
        upload = request.files.get("pdf")
        if not upload:
            abort(400)
        raw = upload.stream.read(5 * 1024 * 1024 + 1)
        if len(raw) > 5 * 1024 * 1024:
            abort(413)
        if not raw.startswith(b"%PDF-"):
            abort(400)
        cid = uuid.uuid4()
        aad = b"contract:v1:" + rental_id.bytes + cid.bytes
        db.session.add(Contract(id=cid, rental_id=rental_id, blob=seal(raw, aad)))
        log("contract_uploaded", user, rental_id)
        db.session.commit()
        return redirect(url_for("detail", rental_id=rental_id))
    contract = db.session.scalar(select(Contract).where(Contract.rental_id == rental_id))
    if not contract:
        abort(404)
    if contract.key_version != 1:
        abort(503)
    try:
        raw = unseal(contract.blob, b"contract:v1:" + rental_id.bytes + contract.id.bytes)
    except InvalidTag:
        log("contract_invalid", user, rental_id)
        db.session.commit()
        abort(503)
    log("contract_download", user, rental_id)
    db.session.commit()
    return send_file(io.BytesIO(raw), mimetype="application/pdf", as_attachment=True,
                     download_name="contract.pdf")


@app.get("/audit")
def audit():
    user = require("admin")
    rows = db.session.scalars(select(Audit).order_by(Audit.id.desc()).limit(100)).all()
    return render_template("page.html", user=user, audit=rows)


@app.cli.command("init-db")
def init_db():
    db.create_all()
    if not db.session.get(Machine, 1):
        db.session.add_all([
            Machine(id=1, name="Экскаватор 20 т", kind="excavator", hourly=2500, dispatch=3500, per_km=90),
            Machine(id=2, name="Автокран 25 т", kind="crane", hourly=3200, dispatch=4500, per_km=110),
        ])
        db.session.commit()


@app.cli.command("create-user")
@click.argument("login_name")
@click.argument("role", type=click.Choice(["client", "staff", "admin"]))
@click.password_option()
def create_user(login_name, role, password):
    if len(password) < 12:
        raise click.ClickException("Minimum password length: 12")
    db.session.add(User(login=login_name.lower(), role=role, password_hash=hasher.hash(password)))
    db.session.commit()


@app.cli.command("seed")
def seed():
    import random

    rng = random.Random(42)
    uid = uuid.UUID("10000000-0000-4000-8000-000000000001")
    if db.session.get(User, uid):
        click.echo("Seed already loaded")
        return
    db.session.add(User(id=uid, login="syntheticseed", role="client",
                        password_hash=hasher.hash(secrets.token_hex(32))))
    db.session.flush()
    machines = [db.session.get(Machine, i) for i in (1, 2)]
    rows = []
    for index in range(5000):
        machine = rng.choice(machines)
        hours = rng.randint(2, 12)
        km = Decimal(rng.randint(1, 90))
        delivery, total = quote(machine, hours, km)
        rows.append(dict(id=uuid.uuid5(uid, str(index)), user_id=uid, machine_id=machine.id,
                         day=date(2026, 10, 1) + timedelta(days=rng.randrange(61)),
                         hours=hours, km=km, delivery=delivery, total=total,
                         status=rng.choices(["new", "accepted", "closed", "cancelled"], [2, 3, 4, 1])[0], note=""))
    db.session.execute(db.insert(Rental), rows)
    db.session.commit()
    click.echo("5000 synthetic rentals inserted")
