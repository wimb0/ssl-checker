#!/usr/bin/env python3
"""SSL Monitor - stores state in data.json and history in history.jsonl.

Requires Python 3.8+ and the `cryptography` package.
SMTP is configured exclusively through environment variables (see SMTP_* below).
"""
import base64, json, math, os, re, secrets, signal, smtplib, socket, ssl, sys
import threading, time, traceback
from collections import deque
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATA_FILE = DATA_DIR / "data.json"
HISTORY_FILE = DATA_DIR / "history.jsonl"
PUBLIC = BASE / "public"
AUTH_USER = os.environ.get("AUTH_USER")
AUTH_PASS = os.environ.get("AUTH_PASS")
MAX_BODY = 1_000_000            # max request body in bytes


def _env_int(name, default):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        sys.exit(f"Invalid value for {name}: {raw!r} (expected a number)")


PORT = _env_int("PORT", 3082)

# ---------- SMTP (environment only, never stored in data.json) ----------
SMTP_PORT = _env_int("SMTP_PORT", 587)
SMTP = {
    "host": os.environ.get("SMTP_HOST", "").strip(),
    "port": SMTP_PORT,
    # starttls = upgrade a plain connection (usually port 587); ssl = implicit TLS (port 465);
    # none = no encryption (only for a trusted local relay)
    "security": (os.environ.get("SMTP_SECURITY", "").strip().lower()
                 or ("ssl" if SMTP_PORT == 465 else "starttls")),
    "user": os.environ.get("SMTP_USER", "").strip(),
    "pass": os.environ.get("SMTP_PASS", ""),
    "from": os.environ.get("SMTP_FROM", "").strip(),
}
if SMTP["security"] not in ("starttls", "ssl", "none"):
    sys.exit("SMTP_SECURITY must be one of: starttls, ssl, none")

LOCK = threading.RLock()        # guards db (data.json)
HLOCK = threading.Lock()        # guards history.jsonl
EVAL_LOCK = threading.Lock()    # prevents duplicate alarm emails
IN_PROGRESS = set()             # ids of domains being checked right now (guarded by LOCK)

db = {
    "domains": [],
    "alarms": [],
    "settings": {
        "intervalHours": 24,
        "historyDays": 365,
    },
}
last_mail_error = None
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_iso(s):
    """Any ISO date -> '2025-01-31T12:00:00Z' (so dates can be compared as strings)."""
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        raise ApiError("Invalid date")
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- Storage: data.json ----------
def load():
    if not DATA_FILE.exists():
        return
    try:
        loaded = json.loads(DATA_FILE.read_text("utf-8"))
        db["domains"] = loaded.get("domains", [])
        db["alarms"] = loaded.get("alarms", [])
        s = loaded.get("settings", {})
        db["settings"]["intervalHours"] = s.get("intervalHours", 24)
        db["settings"]["historyDays"] = s.get("historyDays", 365)
        # Note: an old "smtp" block in settings is intentionally ignored (SMTP is env-only)
    except Exception as e:
        print("Could not read data.json:", e, flush=True)


def save():
    """Atomic write: write to a temp file, then rename. File mode 600."""
    with LOCK:
        tmp = DATA_FILE.with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        os.replace(tmp, DATA_FILE)


def new_id():
    return secrets.token_hex(6)


# ---------- Domain helpers ----------
def is_upload(d):
    return d.get("source") == "upload"


def label_of(d):
    return f"{d['host']} (uploaded certificate)" if is_upload(d) else f"{d['host']}:{d['port']}"


def public_domain(d):
    """Domain without the stored PEM (keeps API responses small)."""
    return {k: v for k, v in d.items() if k != "cert"}


def find_domain(domain_id):
    return next((d for d in db["domains"] if d["id"] == domain_id), None)


def reset_alarm_state(domain_id):
    """Forget which alarms were already sent for this domain (e.g. after its target changed)."""
    with LOCK:
        for a in db["alarms"]:
            a.get("sent", {}).pop(domain_id, None)


# ---------- Storage: history.jsonl ----------
SEARCH_FIELDS = ("host", "status", "error", "authError", "issuer", "subject",
                 "ip", "serial", "sha256", "email", "mailSubject")


def append_history(entry):
    entry = {k: v for k, v in entry.items() if v is not None}
    line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
    with HLOCK:
        with open(HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def repair_history():
    """Make sure the file ends with a newline (after a crash in the middle of a write)."""
    with HLOCK:
        if not HISTORY_FILE.exists() or HISTORY_FILE.stat().st_size == 0:
            return
        with open(HISTORY_FILE, "rb+") as f:
            f.seek(-1, os.SEEK_END)
            if f.read(1) != b"\n":
                f.write(b"\n")


def prune_history():
    days = int(db["settings"].get("historyDays") or 0)
    if days <= 0:
        return
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    removed = 0
    with HLOCK:
        if not HISTORY_FILE.exists():
            return
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:     # quick check: first line
            first = f.readline()
        try:
            if not first or json.loads(first)["t"] >= cutoff:
                return
        except Exception:
            pass
        tmp = HISTORY_FILE.with_suffix(".jsonl.tmp")
        with open(HISTORY_FILE, "r", encoding="utf-8") as src, open(tmp, "w", encoding="utf-8") as out:
            for line in src:
                try:
                    t = json.loads(line)["t"]
                except Exception:
                    continue                      # drop corrupt lines
                if t >= cutoff:
                    out.write(line)
                else:
                    removed += 1
        os.replace(tmp, HISTORY_FILE)
    if removed:
        print(f"History pruned: removed {removed} lines older than {days} days", flush=True)


def search_history(q=None, domain_id=None, status=None, type_=None,
                   date_from=None, date_to=None, limit=100, offset=0):
    """Newest first. Memory use is bounded to offset+limit results."""
    q = q.strip().lower() if q else None
    buf = deque(maxlen=max(1, offset + limit))
    total = 0
    if not HISTORY_FILE.exists():
        return {"total": 0, "items": []}
    with HLOCK:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if q and q not in line.lower():            # cheap pre-filter
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if domain_id and e.get("domainId") != domain_id:
                    continue
                if status and e.get("status") != status:
                    continue
                if type_ and e.get("type") != type_:
                    continue
                t = e.get("t", "")
                if date_from and t < date_from:
                    continue
                if date_to and t > date_to:
                    continue
                if q:
                    hay = " ".join(str(e[k]) for k in SEARCH_FIELDS if e.get(k) is not None).lower()
                    if q not in hay:
                        continue
                total += 1
                buf.append(e)
    items = list(buf)[::-1][offset:offset + limit]
    return {"total": total, "items": items}


# ---------- Certificate parsing ----------
def _err_name(e):
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "Connection timed out"
    if isinstance(e, socket.gaierror):
        return "DNS lookup failed"
    if isinstance(e, ConnectionRefusedError):
        return "Connection refused"
    return str(e) or type(e).__name__


def _attr(name, oid):
    """First value of an attribute (CN, O, ...) from an x509.Name."""
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else ""


def _utc(cert, attr):
    """Validity date as timezone-aware UTC (works with old and new cryptography)."""
    v = getattr(cert, attr + "_utc", None)          # cryptography >= 42
    if v is None:
        v = getattr(cert, attr).replace(tzinfo=timezone.utc)
    return v


def _oid_name(oid):
    return getattr(oid, "_name", None) or oid.dotted_string


def _hex_colon(data):
    return ":".join(f"{b:02X}" for b in data)


def _serial(n):
    h = f"{n:X}"
    if len(h) % 2:
        h = "0" + h
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def _key_info(cert):
    try:
        pub = cert.public_key()
    except Exception:
        return "Unknown", None
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC ({pub.curve.name})", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    return type(pub).__name__, None


def describe_cert(cert):
    """Turn an x509.Certificate into the dict stored as a check result."""
    valid_from = _utc(cert, "not_valid_before")
    valid_to = _utc(cert, "not_valid_after")
    issuer = (_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
              or _attr(cert.issuer, NameOID.COMMON_NAME))

    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [f"DNS:{n}" for n in ext.get_values_for_type(x509.DNSName)]
        sans += [f"IP:{addr}" for addr in ext.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []

    try:
        eku = [_oid_name(o) for o in
               cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except x509.ExtensionNotFound:
        eku = []

    try:
        is_ca = bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        is_ca = False

    key_type, key_size = _key_info(cert)
    days_left = math.floor((valid_to - datetime.now(timezone.utc)).total_seconds() / 86400)
    return {
        "validFrom": valid_from.isoformat().replace("+00:00", "Z"),
        "validTo": valid_to.isoformat().replace("+00:00", "Z"),
        "daysLeft": days_left,
        "subject": _attr(cert.subject, NameOID.COMMON_NAME),
        "issuer": issuer,
        "san": ", ".join(sans),
        "subjectDn": cert.subject.rfc4514_string(),
        "issuerDn": cert.issuer.rfc4514_string(),
        "serial": _serial(cert.serial_number),
        "sha256": _hex_colon(cert.fingerprint(hashes.SHA256())),
        "sha1": _hex_colon(cert.fingerprint(hashes.SHA1())),
        "sigAlg": _oid_name(cert.signature_algorithm_oid),
        "keyType": key_type,
        "keySize": key_size,
        "version": cert.version.name,
        "isCA": is_ca,
        "eku": eku,
        "sans": sans,
    }


# ---------- Uploaded certificates ----------
PEM_RE = re.compile(r"-----BEGIN (?:X509 )?CERTIFICATE-----.+?-----END (?:X509 )?CERTIFICATE-----", re.S)


def parse_certificate_input(text):
    """Accepts PEM text (first certificate is used) or base64-encoded DER. Returns x509.Certificate."""
    text = (text or "").strip()
    if not text:
        raise ApiError("No certificate provided")
    if "PRIVATE KEY" in text:
        raise ApiError("This looks like a private key. Never upload private keys, only the certificate")
    try:
        m = PEM_RE.search(text)
        if m:
            return x509.load_pem_x509_certificate(m.group(0).encode())
        if "-----BEGIN" in text:
            raise ApiError("No certificate found in the PEM text")
        der = base64.b64decode(re.sub(r"\s+", "", text), validate=True)
        return x509.load_der_x509_certificate(der)
    except ApiError:
        raise
    except Exception:
        raise ApiError("Could not read the certificate. Provide PEM text or a .cer/.crt/.pem/.der file")


def read_uploaded(text):
    """Returns (normalized PEM, default display name)."""
    cert = parse_certificate_input(text)
    try:
        info = describe_cert(cert)
    except Exception as e:
        raise ApiError(f"Could not read the certificate: {e}")
    first_san = info["sans"][0].split(":", 1)[1] if info["sans"] else ""
    name = info["subject"] or first_san or "certificate"
    return cert.public_bytes(Encoding.PEM).decode(), name


def inspect_uploaded(pem):
    """Re-evaluate a stored certificate (no network). Trust cannot be verified, so authorized is None."""
    try:
        info = describe_cert(x509.load_pem_x509_certificate(pem.encode()))
    except Exception as e:
        return {"error": f"Could not parse certificate: {e}"}
    return {"error": None, **info, "authorized": None, "authError": None}


# ---------- Network check ----------
def check_cert(host, port=443, timeout=10):
    # 1) Connect without verification, so expired/invalid certificates can still be read
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                response_ms = round((time.perf_counter() - t0) * 1000)
                der = t.getpeercert(binary_form=True)
                protocol = t.version()
                cipher = t.cipher()
                ip = t.getpeername()[0]
    except Exception as e:
        return {"error": _err_name(e)}

    if not der:
        return {"error": "No certificate received"}

    # 2) Parse the certificate
    try:
        info = describe_cert(x509.load_der_x509_certificate(der))
    except Exception as e:
        return {"error": f"Could not parse certificate: {e}"}

    # 3) Second connection WITH verification, to determine whether the certificate is trusted
    authorized, auth_error = True, None
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with vctx.wrap_socket(s, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as e:
        authorized, auth_error = False, e.verify_message
    except Exception:
        pass

    return {
        "error": None,
        **info,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
        "cipherBits": cipher[2] if cipher else None,
        "ip": ip,
        "responseMs": response_ms,
        "authorized": authorized,
        "authError": auth_error,
    }


def compute_status(r):
    if r.get("error"):
        return "error"
    if r["daysLeft"] < 0:
        return "expired"
    if r.get("authorized") is False:         # None = unknown (uploaded certificate)
        return "invalid"
    if r["daysLeft"] <= 7:
        return "critical"
    if r["daysLeft"] <= 30:
        return "warning"
    return "ok"


# ---------- Email ----------
def smtp_public():
    """Read-only view of the SMTP configuration (never includes the password)."""
    return {
        "configured": bool(SMTP["host"]),
        "host": SMTP["host"],
        "port": SMTP["port"],
        "security": SMTP["security"],
        "user": SMTP["user"],
        "from": SMTP["from"] or SMTP["user"],
    }


def send_mail(to, subject, text):
    s = SMTP
    if not s["host"]:
        raise ApiError("SMTP is not configured. Set SMTP_HOST (and related variables) in .env")
    sender = s["from"] or s["user"]
    if not sender:
        raise ApiError("No sender address. Set SMTP_FROM in .env")
    if not to:
        raise ApiError("No recipient provided")
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text)
    try:
        if s["security"] == "ssl":
            server = smtplib.SMTP_SSL(s["host"], s["port"], timeout=20,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(s["host"], s["port"], timeout=20)
        with server:
            if s["security"] == "starttls":
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
            if s["user"]:
                server.login(s["user"], s["pass"])
            server.send_message(msg)
    except (smtplib.SMTPException, OSError) as e:
        raise ApiError(f"Sending failed: {_err_name(e)}")


def fmt_local(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M")


def evaluate_alarms(domain):
    """Decide which alarms must fire. Emails are sent outside the db lock."""
    global last_mail_error
    with EVAL_LOCK:
        todo = []
        with LOCK:
            r = domain.get("last")
            if not r:
                return
            label = label_of(domain)
            for a in db["alarms"]:
                if a["domainId"] != "all" and a["domainId"] != domain["id"]:
                    continue
                sent = a.setdefault("sent", {})
                key = subject = text = None

                if r.get("error"):
                    key = "error"
                    subject = f"[SSL] {label} could not be checked"
                    text = f"The certificate of {label} could not be checked.\nError: {r['error']}"
                elif r["daysLeft"] <= a["days"]:
                    key = "exp:" + r["validTo"]
                    n = r["daysLeft"]
                    subject = (f"[SSL] Certificate of {label} has EXPIRED" if n < 0
                               else f"[SSL] Certificate of {label} expires in {n} day{'' if n == 1 else 's'}")
                    text = (f"Domain: {label}\nExpires on: {fmt_local(r['validTo'])}\n"
                            f"Days left: {n}\nIssuer: {r['issuer']}\n"
                            f"Alarm threshold: {a['days']} days")
                elif r.get("authorized") is False:
                    key = "invalid:" + str(r["authError"])
                    subject = f"[SSL] Certificate of {label} is invalid"
                    text = f"Domain: {label}\nProblem: {r['authError']}"

                if key is None:
                    sent.pop(domain["id"], None)   # all OK -> reset the alarm
                    continue
                if sent.get(domain["id"]) == key:  # already reported
                    continue
                todo.append((a, a["email"], key, subject, text))

        for a, email, key, subject, text in todo:
            entry = {"type": "alarm", "t": now_iso(), "domainId": domain["id"],
                     "host": domain["host"], "port": domain.get("port"),
                     "source": "upload" if is_upload(domain) else None,
                     "email": email, "mailSubject": subject}
            try:
                send_mail(email, subject, text)
                with LOCK:
                    a.setdefault("sent", {})[domain["id"]] = key
                    last_mail_error = None
                entry["status"] = "sent"
                print(f"Alarm email sent to {email}: {subject}", flush=True)
            except Exception as e:
                with LOCK:
                    last_mail_error = f"{datetime.now().strftime('%Y-%m-%d %H:%M')}: {e}"
                entry["status"] = "failed"
                entry["error"] = str(e)
                print("Sending email failed:", e, flush=True)
            append_history(entry)


# ---------- Checking ----------
def run_check(domain):
    with LOCK:
        IN_PROGRESS.add(domain["id"])
        upload = is_upload(domain)
        host, port, pem = domain["host"], domain.get("port"), domain.get("cert")
    try:
        result = inspect_uploaded(pem) if upload else check_cert(host, port)   # network I/O outside the lock
        result["status"] = compute_status(result)
        result["checkedAt"] = now_iso()
        with LOCK:
            domain["last"] = result
        append_history({
            "type": "check", "t": result["checkedAt"],
            "domainId": domain["id"], "host": host, "port": port,
            "source": "upload" if upload else None,
            "status": result["status"], "daysLeft": result.get("daysLeft"),
            "error": result.get("error"), "authError": result.get("authError"),
            "validTo": result.get("validTo"), "issuer": result.get("issuer"),
            "subject": result.get("subject"), "serial": result.get("serial"),
            "sha256": result.get("sha256"), "ip": result.get("ip"),
            "protocol": result.get("protocol"), "responseMs": result.get("responseMs"),
        })
        evaluate_alarms(domain)
    finally:
        with LOCK:
            IN_PROGRESS.discard(domain["id"])


def check_many(domains):
    threads = [threading.Thread(target=run_check, args=(d,)) for d in domains]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    save()


def check_all():
    with LOCK:
        domains = list(db["domains"])
    check_many(domains)


def due_domains():
    """Domains whose last check is older than the configured interval."""
    every = max(1, float(db["settings"]["intervalHours"] or 24)) * 3600
    now = datetime.now(timezone.utc)
    due = []
    with LOCK:
        for d in db["domains"]:
            if d["id"] in IN_PROGRESS:
                continue
            checked = (d.get("last") or {}).get("checkedAt")
            if not checked:
                due.append(d)
                continue
            age = (now - datetime.fromisoformat(checked.replace("Z", "+00:00"))).total_seconds()
            if age >= every - 120:        # 2 minute margin so the check time does not drift
                due.append(d)
    return due


def scheduler():
    time.sleep(2)
    last_prune = 0
    while True:
        try:
            due = due_domains()
            if due:
                check_many(due)
        except Exception as e:
            print("Scheduled check failed:", e, flush=True)
        if time.time() - last_prune >= 86400:
            last_prune = time.time()
            try:
                prune_history()
            except Exception as e:
                print("History pruning failed:", e, flush=True)
        time.sleep(60)


# ---------- API ----------
def safe_settings():
    return {
        "intervalHours": db["settings"]["intervalHours"],
        "historyDays": db["settings"]["historyDays"],
    }


def parse_target(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ApiError("No URL provided")
    try:
        u = urlparse(raw if "://" in raw else "https://" + raw)
        host, port = u.hostname, u.port or 443
    except ValueError:
        raise ApiError("Invalid URL")
    if not host:
        raise ApiError("Invalid URL")
    return host, port


def network_duplicate(host, port, exclude=None):
    return any(d is not exclude and not is_upload(d) and d["host"] == host and d["port"] == port
               for d in db["domains"])


def upload_duplicate(name, exclude=None):
    return any(d is not exclude and is_upload(d) and d["host"].lower() == name.lower()
               for d in db["domains"])


def route(method, path, body, query):
    if method == "GET" and path == "/api/state":
        with LOCK:
            return {
                "domains": [public_domain(d) for d in db["domains"]],
                "alarms": [{k: v for k, v in a.items() if k != "sent"} for a in db["alarms"]],
                "settings": safe_settings(),
                "smtp": smtp_public(),
                "lastMailError": last_mail_error,
            }

    if method == "GET" and path == "/api/history":
        limit = min(500, max(1, int(query.get("limit", 100))))
        offset = max(0, int(query.get("offset", 0)))
        return search_history(
            q=query.get("q"),
            domain_id=query.get("domainId") or None,
            status=query.get("status") or None,
            type_=query.get("type") or None,
            date_from=norm_iso(query["from"]) if query.get("from") else None,
            date_to=norm_iso(query["to"]) if query.get("to") else None,
            limit=limit, offset=offset)

    # --- add a domain (network) or an uploaded certificate ---
    if method == "POST" and path == "/api/domains":
        if body.get("source") == "upload":
            pem, default_name = read_uploaded(body.get("certificate"))
            name = (body.get("name") or "").strip()[:200] or default_name
            with LOCK:
                if upload_duplicate(name):
                    raise ApiError("An uploaded certificate with this name already exists")
                domain = {"id": new_id(), "source": "upload", "host": name, "port": None,
                          "cert": pem, "addedAt": now_iso(), "last": None}
                db["domains"].append(domain)
        else:
            host, port = parse_target(body.get("url"))
            with LOCK:
                if network_duplicate(host, port):
                    raise ApiError("This domain is already in the list")
                domain = {"id": new_id(), "source": "network", "host": host, "port": port,
                          "addedAt": now_iso(), "last": None}
                db["domains"].append(domain)
        run_check(domain)
        save()
        return public_domain(domain)

    m = re.fullmatch(r"/api/domains/(\w+)", path)

    # --- edit ---
    if m and method == "PUT":
        domain_id = m.group(1)
        with LOCK:
            d = find_domain(domain_id)
        if not d:
            raise ApiError("Not found", 404)
        if is_upload(d):
            name = (body.get("name") or "").strip()[:200] or d["host"]
            new_pem = None
            if (body.get("certificate") or "").strip():
                new_pem, _ = read_uploaded(body["certificate"])
            with LOCK:
                if upload_duplicate(name, exclude=d):
                    raise ApiError("An uploaded certificate with this name already exists")
                d["host"] = name
                if new_pem and new_pem != d.get("cert"):
                    d["cert"] = new_pem
                    reset_alarm_state(domain_id)
        else:
            host, port = parse_target(body.get("url"))
            with LOCK:
                if network_duplicate(host, port, exclude=d):
                    raise ApiError("This domain is already in the list")
                if (host, port) != (d["host"], d["port"]):
                    d["host"], d["port"] = host, port
                    reset_alarm_state(domain_id)
        run_check(d)
        save()
        return public_domain(d)

    # --- delete ---
    if m and method == "DELETE":
        domain_id = m.group(1)
        with LOCK:
            db["domains"] = [d for d in db["domains"] if d["id"] != domain_id]
            db["alarms"] = [a for a in db["alarms"] if a["domainId"] != domain_id]
            for a in db["alarms"]:
                a.get("sent", {}).pop(domain_id, None)
        save()
        return {"ok": True}

    m = re.fullmatch(r"/api/domains/(\w+)/check", path)
    if m and method == "POST":
        with LOCK:
            d = find_domain(m.group(1))
        if not d:
            raise ApiError("Not found", 404)
        run_check(d)
        save()
        return public_domain(d)

    if method == "POST" and path == "/api/check-all":
        check_all()
        return {"ok": True}

    if method == "POST" and path == "/api/alarms":
        email = (body.get("email") or "").strip()
        if not EMAIL_RE.fullmatch(email):
            raise ApiError("Invalid email address")
        try:
            days = float(body.get("days"))
        except (TypeError, ValueError):
            days = -1
        if not 0 <= days <= 365:
            raise ApiError("Number of days must be between 0 and 365")
        domain_id = body.get("domainId")
        with LOCK:
            if domain_id != "all" and not find_domain(domain_id):
                raise ApiError("Unknown domain")
            db["alarms"].append({"id": new_id(), "email": email, "days": int(days),
                                 "domainId": domain_id, "sent": {}})
        save()

        def evaluate_now():
            # Fire immediately if a certificate is already below the new threshold
            with LOCK:
                domains = list(db["domains"])
            for d in domains:
                evaluate_alarms(d)
            save()
        threading.Thread(target=evaluate_now, daemon=True).start()
        return {"ok": True}

    m = re.fullmatch(r"/api/alarms/(\w+)", path)
    if m and method == "DELETE":
        with LOCK:
            db["alarms"] = [a for a in db["alarms"] if a["id"] != m.group(1)]
        save()
        return {"ok": True}

    # Only check interval and history retention; SMTP is environment-only
    if method == "PUT" and path == "/api/settings":
        with LOCK:
            db["settings"]["intervalHours"] = max(1, int(float(body.get("intervalHours") or 24)))
            days = body.get("historyDays")
            if days not in (None, ""):
                db["settings"]["historyDays"] = max(0, int(float(days)))
            result = safe_settings()
        save()
        return result

    if method == "POST" and path == "/api/settings/test-email":
        to = (body.get("to") or "").strip()
        if not EMAIL_RE.fullmatch(to):
            raise ApiError("Invalid email address")
        send_mail(to, "[SSL Monitor] Test email", "If you can read this, sending email works.")
        return {"ok": True}

    raise ApiError("Not found", 404)


# ---------- HTTP server ----------
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css",
        ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _authorized(self):
        if not (AUTH_USER and AUTH_PASS):
            return True
        header = self.headers.get("Authorization", "")
        try:
            user, password = base64.b64decode(header.replace("Basic ", "")).decode().split(":", 1)
            return (secrets.compare_digest(user.encode(), AUTH_USER.encode())
                    and secrets.compare_digest(password.encode(), AUTH_PASS.encode()))
        except Exception:
            return False

    def _send(self, code, data, ctype="application/json", extra=None):
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _static(self, path):
        rel = "index.html" if path == "/" else path.lstrip("/")
        f = (PUBLIC / rel).resolve()
        if PUBLIC.resolve() not in f.parents or not f.is_file():
            return self._send(404, {"error": "Not found"})
        self._send(200, f.read_bytes(), MIME.get(f.suffix, "application/octet-stream"))

    def _handle(self, method):
        # Health check endpoint: no login required (used by the Docker HEALTHCHECK)
        if method == "GET" and self.path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        if not self._authorized():
            return self._send(401, b"Login required", "text/plain",
                              {"WWW-Authenticate": 'Basic realm="SSL Monitor"'})
        u = urlparse(self.path)
        if not u.path.startswith("/api/"):
            return self._static(u.path) if method == "GET" else self._send(405, {"error": "Method not allowed"})
        try:
            query = {k: v[0] for k, v in parse_qs(u.query).items()}
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._send(413, {"error": "Request too large"})
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            if not isinstance(body, dict):
                raise ValueError("JSON object expected")
            result = route(method, u.path, body, query)
            with LOCK:                                   # serialize while nobody is writing
                payload = json.dumps(result).encode()
            self._send(200, payload)
        except ApiError as e:
            self._send(e.code, {"error": str(e)})
        except (ValueError, KeyError, TypeError) as e:
            self._send(400, {"error": f"Invalid request: {e}"})
        except Exception:
            traceback.print_exc()
            self._send(500, {"error": "Internal server error"})

    def do_GET(self):    self._handle("GET")
    def do_POST(self):   self._handle("POST")
    def do_PUT(self):    self._handle("PUT")
    def do_DELETE(self): self._handle("DELETE")


if __name__ == "__main__":
    load()
    repair_history()
    prune_history()
    # As PID 1 in a container, Python ignores SIGTERM by default; exit cleanly instead
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    threading.Thread(target=scheduler, daemon=True).start()
    smtp_state = f"{SMTP['host']}:{SMTP['port']} ({SMTP['security']})" if SMTP["host"] else "not configured"
    print(f"SSL Monitor running on http://localhost:{PORT}  (data: {DATA_DIR}, SMTP: {smtp_state})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
