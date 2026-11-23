"""Run against a disposable database after init-db and seed."""
import io
import re
import uuid
from datetime import date, timedelta

from sqlalchemy import select, text

from app import app, db, Contract, Rental, Audit, LoginSession, User, hasher


def check(label, condition):
    if not condition:
        raise AssertionError(label)
    print("PASS", label)


def token(browser):
    page = browser.get("/", base_url="https://localhost")
    return re.search(rb'name="csrf_token" value="([^"]+)', page.data)[1].decode()


def post(browser, path, **data):
    return browser.post(path, base_url="https://localhost",
                        headers={"Referer": "https://localhost/"}, data={"csrf_token": token(browser), **data})


def get(browser, path):
    return browser.get(path, base_url="https://localhost")


suffix = uuid.uuid4().hex[:8]
password = "Demo-password-735!"
clients = [app.test_client() for _ in range(4)]
owner, stranger, staff, admin = clients
with app.app_context():
    for role in ("staff", "admin"):
        db.session.add(User(login=role + suffix, password_hash=hasher.hash(password), role=role))
    db.session.commit()
    count = db.session.scalar(select(db.func.count()).select_from(Rental).where(
        Rental.user_id == uuid.UUID("10000000-0000-4000-8000-000000000001")))
    check("S01 PostgreSQL contains 5000 seeded rentals", count == 5000)

check("S02 guest gets 401", get(owner, "/rentals").status_code == 401)
for i, browser in enumerate(clients[:2]):
    check("S03 register client", post(browser, "/register", login=f"client{i}{suffix}",
          password=password, phone="+70000000001").status_code == 302)
check("S04 injection payload rejected", post(owner, "/login", login="' OR 1=1 --", password=password).status_code == 401)
for browser, name in zip(clients, (f"client0{suffix}", f"client1{suffix}", "staff"+suffix, "admin"+suffix)):
    result = post(browser, "/login", login=name, password=password)
    cookie = result.headers.get("Set-Cookie", "")
    check("S05 login and cookie attributes", result.status_code == 302 and all(
        item in cookie for item in ("Secure", "HttpOnly", "SameSite=Lax")))

check("S06 CSRF absent returns 400", owner.post("/rentals", base_url="https://localhost").status_code == 400)
payload = "<script>alert(1)</script>"
check("S07 valid rental created", post(owner, "/rentals", machine=1,
      day=(date.today()+timedelta(days=1)).isoformat(), hours=8, km=25, note=payload).status_code == 302)
with app.app_context():
    user = db.session.scalar(select(User).where(User.login == "client0"+suffix))
    rental = db.session.scalar(select(Rental).where(Rental.user_id == user.id))
    rid = rental.id
    check("S08 delivery 8000 and quote 28000", rental.delivery == 8000 and rental.total == 28000)
    check("S09 Argon2id and encrypted phone", user.password_hash.startswith("$argon2id$") and b"+70000000001" not in user.phone)

path = f"/rentals/{rid}"
check("S10 XSS payload escaped", b"&lt;script&gt;" in get(owner, path).data and payload.encode() not in get(owner, path).data)
check("S11 URL substitution returns 404", get(stranger, path).status_code == 404)
check("S12 client cannot read audit", get(owner, "/audit").status_code == 403)
check("S13 staff accepts order", post(staff, path, status="accepted").status_code == 302)
pdf = b"%PDF-1.4\n% test fixture\n%%EOF\n"
check("S14 upload accepted", post(staff, path+"/contract", pdf=(io.BytesIO(pdf), "demo.pdf")).status_code == 302)
check("S15 cross-account download blocked", get(stranger, path+"/contract").status_code == 404)
download = get(owner, path+"/contract")
check("S16 owner download matches bytes", download.data == pdf and "attachment" in download.headers["Content-Disposition"])
with app.app_context():
    document = db.session.scalar(select(Contract).where(Contract.rental_id == rid))
    column_type = db.session.execute(text("SELECT pg_typeof(blob)::text FROM contract LIMIT 1")).scalar_one()
    check("S17 ciphertext stored as bytea", column_type == "bytea" and pdf not in document.blob)
    document.blob = document.blob[:-1] + bytes([document.blob[-1] ^ 1])
    db.session.commit()
check("S18 modified tag returns 503", get(owner, path+"/contract").status_code == 503)
check("S19 denial and tampering audited", b"contract_invalid" in get(admin, "/audit").data
      and b"rental_denied" in get(admin, "/audit").data)
check("S20 logout invalidates access", post(owner, "/logout").status_code == 302 and get(owner, path).status_code == 401)


