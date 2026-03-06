from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf import CSRFProtect
import requests
from urllib.parse import urlencode
from flask_wtf.csrf import generate_csrf
from functools import wraps
from models import db, User
from datetime import datetime, timedelta
import re
import secrets
import string
import feedparser
import time

# ====================================================
#               APP CONFIGURATION
# ====================================================
app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- Secure session settings ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # set True if using HTTPS
    PERMANENT_SESSION_LIFETIME=1800  # 30 min auto logout
)

# Initialize extensions
db.init_app(app)
csrf = CSRFProtect(app)

# ====================================================
#        TEMPLATE CONTEXT HELPERS (CSRF + ROLE)
# ====================================================

@app.context_processor
def inject_csrf_token():
    # Makes csrf_token() available in all templates
    return dict(csrf_token=generate_csrf)

@app.context_processor
def inject_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return {"current_user": None, "current_user_role": None}

    user = db.session.get(User, user_id)  # avoids legacy Query.get warning
    return {
        "current_user": user,
        "current_user_role": user.role if user else None
    }

# ====================================================
#            VALIDATION FUNCTIONS
# ====================================================

# --- Password rules ---
def is_strong_password(password):
    """Check if password meets strength requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def generate_strong_password(length=14):
    """Generate a strong password that meets the same rules as is_strong_password()."""
    if length < 12:
        length = 12

    upper = secrets.choice(string.ascii_uppercase)
    lower = secrets.choice(string.ascii_lowercase)
    digit = secrets.choice(string.digits)
    special = secrets.choice("!@#$%^&*(),.?\":{}|<>")

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    rest = "".join(secrets.choice(alphabet) for _ in range(length - 4))

    pwd_list = list(upper + lower + digit + special + rest)
    secrets.SystemRandom().shuffle(pwd_list)
    return "".join(pwd_list)


# --- Email format validation ---
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

def is_valid_email(email):
    """Check if email follows the username@mailserver.domain format."""
    return re.match(EMAIL_REGEX, email) is not None
    
# --- Username format validation ---
    
USERNAME_REGEX = r"^[a-zA-Z0-9_]{3,20}$"

def is_valid_username(username: str) -> bool:
    return re.match(USERNAME_REGEX, username) is not None
    
# ====================================================
#                 NEWS CACHE
# ====================================================

NEWS_CACHE = {
    "data": [],
    "timestamp": 0
}

NEWS_CACHE_DURATION = 900  # 15 minutes

CVE_CACHE = {
    "timestamp": 0,
    "data": []
}

CVE_CACHE_DURATION = 1800  # 30 minutes

def fetch_wifi_security_news():
    """
    Fetch Wi-Fi / WLAN security news from RSS feeds with STRICT Wi-Fi matching.
    If too few strict matches are found, fall back to *network-device* security
    (router / access point / wireless) so the widget doesn't go empty.

    Returns: [{"title": str, "link": str, "source": str}, ...]  (max 12)
    """

    global NEWS_CACHE

    # Return cached data if still valid
    if time.time() - NEWS_CACHE["timestamp"] < NEWS_CACHE_DURATION:
        return NEWS_CACHE["data"]

    # More wireless/network-relevant feeds (still mixed with general security)
    feeds = [
        "https://www.wifi-alliance.org/rss.xml",
        "https://www.securityweek.com/feed/",
        "https://www.bleepingcomputer.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.darkreading.com/rss.xml",
        "https://thehackernews.com/feeds/posts/default/-/Wi-Fi%20hacking?alt=rss",
    ]

    # ---------- STRICT WI-FI ANCHORS ----------
    # Must match at least one of these (title preferred; summary allowed for strong anchors)
    anchor_patterns_title = [
        r"\bwi[- ]?fi\b",
        r"\bwlan\b",
        r"\b802\.11\b",
        r"\bwpa3\b",
        r"\bwpa2\b",
        r"\bwpa\b",
        r"\bssid\b",
        r"\beapol\b",
        r"\bpmkid\b",
        r"\bkrack\b",
        r"\bsae\b",
        r"\b802\.1x\b",
        r"\bradius\b",
        r"\baccess point\b",
        r"\brogue ap\b",
        r"\bevil twin\b",
        r"\bdeauth\b",
        r"\bdeauthentication\b",
        r"\bwardriv(?:e|ing)\b",
        r"\bwep\b",
    ]

    anchor_patterns_summary = [
        r"\bwi[- ]?fi\b",
        r"\bwlan\b",
        r"\b802\.11\b",
        r"\bwpa3\b",
        r"\bwpa2\b",
        r"\bssid\b",
        r"\beapol\b",
        r"\bpmkid\b",
        r"\bkrack\b",
        r"\bevil twin\b",
        r"\brogue ap\b",
        r"\bdeauth\b",
        r"\bdeauthentication\b",
        r"\b802\.1x\b",
    ]

    title_regexes = [re.compile(pat, re.IGNORECASE) for pat in anchor_patterns_title]
    summary_regexes = [re.compile(pat, re.IGNORECASE) for pat in anchor_patterns_summary]

    def title_is_wifi(text: str) -> bool:
        return bool(text) and any(rx.search(text) for rx in title_regexes)

    def summary_is_wifi(text: str) -> bool:
        return bool(text) and any(rx.search(text) for rx in summary_regexes)

    items = []
    seen_links = set()

    # ---------- PASS 1: STRICT WI-FI ONLY ----------
    for url in feeds:
        feed = feedparser.parse(url)
        source = feed.feed.get("title", "Security News")

        for entry in feed.entries[:50]:
            title = (entry.get("title") or "").strip()
            summary = (entry.get("summary") or "").strip()
            link = (entry.get("link") or "").strip()

            if not link or link in seen_links:
                continue

            if not title_is_wifi(title) and not summary_is_wifi(summary):
                continue

            items.append({
                "title": title if title else "Untitled",
                "link": link,
                "source": source,
            })
            seen_links.add(link)

            if len(items) >= 12:
                break

        if len(items) >= 12:
            break

    # ---------- PASS 2: FALLBACK (NETWORK DEVICE SECURITY) ----------
    # If strict Wi-Fi matches are too few, allow network-device terms in TITLE
    # (still keeps things relevant; avoids "totally unrelated" headlines).
    if len(items) < 5:
        fallback_patterns = [
            r"\brouter(s)?\b",
            r"\bwireless\b",
            r"\baccess point(s)?\b",
            r"\bmesh\b",
            r"\bwi[- ]?fi\b",
            r"\bwlan\b",
        ]
        fallback_regexes = [re.compile(p, re.IGNORECASE) for p in fallback_patterns]

        def title_is_fallback_relevant(text: str) -> bool:
            return bool(text) and any(rx.search(text) for rx in fallback_regexes)

        for url in feeds:
            feed = feedparser.parse(url)
            source = feed.feed.get("title", "Security News")

            for entry in feed.entries[:50]:
                title = (entry.get("title") or "").strip()
                link = (entry.get("link") or "").strip()

                if not link or link in seen_links:
                    continue

                if not title_is_fallback_relevant(title):
                    continue

                items.append({
                    "title": title if title else "Untitled",
                    "link": link,
                    "source": source,
                })
                seen_links.add(link)

                if len(items) >= 12:
                    break

            if len(items) >= 12:
                break

    # Cache result (even if empty; avoids repeated fetch storms)
    NEWS_CACHE["data"] = items[:12]
    NEWS_CACHE["timestamp"] = time.time()
    return NEWS_CACHE["data"]
    
def fetch_wifi_cves():
    """
    Fetch recent Wi-Fi-related CVEs from NVD API 2.0 using keywordSearch.
    Includes robust error/debug printing + retry behavior for NVD 404 quirks.
    """

    global CVE_CACHE

    if time.time() - CVE_CACHE["timestamp"] < CVE_CACHE_DURATION:
        return CVE_CACHE["data"]

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Single-keyword queries (because multiple keywords behave like AND)
    queries = [
        "wifi", "wlan", "802.11", "wpa2", "wpa3", "eapol", "pmkid",
        "access point", "evil twin", "deauthentication"
    ]

    # 120-day window (NVD often expects ISO-8601 with an offset; Z is UTC)
    end_dt = datetime.utcnow()
    start_dt = end_dt - timedelta(days=120)
    pub_start = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pub_end = end_dt.strftime("%Y-%m-%dT%H:%M:%S.999Z")

    # Optional API key (strongly recommended)
    # export NVD_API_KEY="your_key_here"
    import os
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    def extract_en_description(cve_obj: dict) -> str:
        for d in (cve_obj.get("descriptions") or []):
            if d.get("lang") == "en" and d.get("value"):
                return d["value"].strip()
        return ""

    def try_request(params: dict):
        """Make the request; return (data_json, response_obj)."""
        r = requests.get(base_url, params=params, headers=headers, timeout=15)
        r.raise_for_status()
        return r.json(), r

    merged = {}

    for kw in queries:
        # First attempt: with pub date window
        params = {
            "resultsPerPage": 20,
            "startIndex": 0,
            "keywordSearch": kw,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
        }

        try:
            data, r = try_request(params)

        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            body_preview = ""
            try:
                body_preview = (e.response.text or "")[:300] if e.response is not None else ""
            except Exception:
                body_preview = ""

            print("\n========== NVD API ERROR ==========")
            print("Keyword:", kw)
            print("Status :", status)
            print("URL    :", e.response.url if e.response is not None else "(no url)")
            if body_preview:
                print("Body   :", body_preview)
            print("==================================\n")

            # Retry if NVD returns 404 with date params (common quirk / gating)
            if status == 404:
                try:
                    params_retry = {
                        "resultsPerPage": 20,
                        "startIndex": 0,
                        "keywordSearch": kw,
                    }
                    data, r = try_request(params_retry)

                    print("\n====== NVD RETRY (NO DATES) ======")
                    print("Keyword:", kw)
                    print("URL    :", r.url)
                    print("totalResults:", data.get("totalResults"))
                    print("returned    :", len(data.get("vulnerabilities", []) or []))
                    print("=================================\n")

                except Exception as e2:
                    print("NVD retry failed:", e2)
                    continue
            else:
                continue

        except Exception as e:
            print("CVE fetch error:", e)
            continue

        # DEBUG: confirm what we fetched
        print("\n========== NVD API DEBUG ==========")
        print("Keyword:", kw)
        print("URL    :", r.url)
        print("totalResults:", data.get("totalResults"))
        print("returned    :", len(data.get("vulnerabilities", []) or []))
        print("===================================\n")

        for v in (data.get("vulnerabilities") or []):
            cve = (v.get("cve") or {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            desc = extract_en_description(cve)
            if not desc:
                continue

            # strict: ensure kw appears in description (keeps it Wi-Fi-ish)
            if kw.lower() not in desc.lower():
                continue

            merged[cve_id] = {
                "id": cve_id,
                "description": (desc[:180] + "...") if len(desc) > 180 else desc,
                "published": cve.get("published", ""),
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }

    items = sorted(merged.values(), key=lambda x: x.get("published", ""), reverse=True)[:12]
    CVE_CACHE["data"] = items
    CVE_CACHE["timestamp"] = time.time()
    return items


# ====================================================
#                 AUTH HELPERS
# ====================================================
def login_required(f):
    """Ensure the route is accessible only when logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated


def role_required(role):
    """Restrict route to a specific user role."""
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = User.query.get(session.get("user_id"))
            if not user or user.role != role:
                return "Access Denied", 403
            return f(*args, **kwargs)
        return decorated
    return wrapper


# ====================================================
#                    ROUTES
# ====================================================

# ---------- HOME / LANDING PAGE ----------
@app.route("/")
def home():
    """Landing page for role selection."""
    return render_template("home.html", page_style="home.css", title="Wi-Fi Labs – Choose Login")


# ---------- SMART DASHBOARD REDIRECT ----------
@app.route("/dashboard")
@login_required
def dashboard_redirect():
    """Redirect user to their correct dashboard based on role."""
    user = User.query.get(session["user_id"])
    if not user:
        return redirect(url_for("home"))

    if user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    elif user.role == "instructor":
        return redirect(url_for("instructor_dashboard"))
    elif user.role == "learner":
        return redirect(url_for("learner_dashboard"))
    else:
        return redirect(url_for("home"))


# ---------- GENERAL LOGIN (Admin only or fallback) ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()  # 🔐 Clear any existing session

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            user.last_login_at = datetime.utcnow()
            db.session.commit()

            session["user_id"] = user.id
            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            elif user.role == "instructor":
                return redirect(url_for("instructor_dashboard"))
            elif user.role == "learner":
                return redirect(url_for("learner_dashboard"))

        return render_template("login.html", error="Invalid credentials", page_style="login.css")

    return render_template("login.html", page_style="login.css", title="Admin Login – Wi-Fi Labs")


# ---------- INSTRUCTOR AUTH ----------
@app.route("/login/instructor", methods=["GET", "POST"])
def login_instructor():
    session.clear()
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email, role="instructor").first()
        if user and user.check_password(password):
            user.last_login_at = datetime.utcnow()
            db.session.commit()

            session["user_id"] = user.id
            return redirect(url_for("instructor_dashboard"))

        return render_template("login_instructor.html", error="Invalid credentials", page_style="login.css")

    return render_template("login_instructor.html", page_style="login.css", title="Instructor Login – Wi-Fi Labs")


@app.route("/signup/instructor", methods=["GET", "POST"])
def signup_instructor():
    session.clear()
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not is_valid_email(email):
            return render_template(
                "signup_instructor.html",
                error="Invalid email format. Use username@mailserver.domain",
                page_style="login.css"
            )

        if User.query.filter_by(email=email).first():
            return render_template("signup_instructor.html", error="Email already exists!", page_style="login.css")

        is_valid, message = is_strong_password(password)
        if not is_valid:
            return render_template("signup_instructor.html", error=message, page_style="login.css")

        new_user = User(email=email, role="instructor")
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login_instructor"))

    return render_template("signup_instructor.html", page_style="login.css", title="Instructor Signup – Wi-Fi Labs")
    
# ====================================================
#                INSTRUCTOR ROUTES
# ====================================================

@app.route("/instructor")
@login_required
@role_required("instructor")
def instructor_dashboard():
    return render_template("instructor_dashboard.html", page_style="instructor.css")


@app.route("/instructor/scenarios")
@login_required
@role_required("instructor")
def instructor_scenarios():
    return render_template("instructor_scenarios.html", page_style="instructor.css")


@app.route("/instructor/performance")
@login_required
@role_required("instructor")
def instructor_performance():
    return render_template("instructor_performance.html", page_style="instructor.css")


@app.route("/instructor/learners")
@login_required
@role_required("instructor")
def instructor_learners():
    return render_template("instructor_learners.html", page_style="instructor.css")


@app.route("/instructor/reports")
@login_required
@role_required("instructor")
def instructor_reports():
    return render_template("instructor_reports.html", page_style="instructor.css")


# ---------- LEARNER AUTH ----------
@app.route("/login/learner", methods=["GET", "POST"])
def login_learner():
    session.clear()
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email, role="learner").first()
        if user and user.check_password(password):
            user.last_login_at = datetime.utcnow()
            db.session.commit()

            session["user_id"] = user.id
            return redirect(url_for("learner_dashboard"))

        return render_template("login_learner.html", error="Invalid credentials", page_style="login.css")

    return render_template("login_learner.html", page_style="login.css", title="Learner Login – Wi-Fi Labs")


@app.route("/signup/learner", methods=["GET", "POST"])
def signup_learner():
    session.clear()
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not is_valid_email(email):
            return render_template(
                "signup_learner.html",
                error="Invalid email format. Use username@mailserver.domain",
                page_style="login.css"
            )

        if User.query.filter_by(email=email).first():
            return render_template("signup_learner.html", error="Email already exists!", page_style="login.css")

        is_valid, message = is_strong_password(password)
        if not is_valid:
            return render_template("signup_learner.html", error=message, page_style="login.css")

        new_user = User(email=email, role="learner")
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login_learner"))

    return render_template("signup_learner.html", page_style="login.css", title="Learner Signup – Wi-Fi Labs")
    
# ====================================================
#                LEARNER ROUTES
# ====================================================

@app.route("/learner")
@login_required
@role_required("learner")
def learner_dashboard():
    news = fetch_wifi_security_news()
    cves = fetch_wifi_cves()
    return render_template("learner_dashboard.html", page_style="learner.css", news=news, cves=cves)


@app.route("/learner/scenarios")
@login_required
@role_required("learner")
def learner_scenarios():
    return render_template("learner_scenarios.html", page_style="learner.css")


@app.route("/learner/submissions")
@login_required
@role_required("learner")
def learner_submissions():
    return render_template("learner_submissions.html", page_style="learner.css")


@app.route("/learner/resources")
@login_required
@role_required("learner")
def learner_resources():
    return render_template("learner_resources.html", page_style="learner.css")


@app.route("/learner/help")
@login_required
@role_required("learner")
def learner_help():
    return render_template("learner_help.html", page_style="learner.css")


# ====================================================
#                    ADMIN ROUTES
# ====================================================

@app.route("/admin")
@login_required
@role_required("admin")
def admin_dashboard():

    total_users = User.query.filter(User.role != "admin").count()
    instructors = User.query.filter_by(role="instructor").count()
    learners = User.query.filter_by(role="learner").count()

    recent_logins = (
        User.query
        .filter(User.role != "admin")
        .order_by(User.last_login_at.is_(None), User.last_login_at.desc())
        .limit(10)
        .all()
    )

    news = fetch_wifi_security_news()
    cves = fetch_wifi_cves()

    return render_template(
        "admin_dashboard.html",
        page_style="admin.css",
        total_users=total_users,
        instructors=instructors,
        learners=learners,
        recent_logins=recent_logins,
        news=news,
        cves=cves
    )

@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    users = User.query.filter(User.role != "admin").all()
    return render_template("admin_users.html", users=users, page_style="admin.css")


@app.route("/admin/scenarios")
@login_required
@role_required("admin")
def admin_scenarios():
    # Placeholder page for now
    return render_template("admin_scenarios.html", page_style="admin.css")

@app.route("/admin/assets")
@login_required
@role_required("admin")
def admin_assets():
    # Placeholder page for assets management
    return render_template("admin_assets.html", page_style="admin.css")

@app.route("/admin/reset-password/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)

    # Block admin accounts from appearing/being reset via this page
    if user.role == "admin":
        users = User.query.filter(User.role != "admin").all()
        return render_template(
            "admin_users.html",
            users=users,
            page_style="admin.css",
            error="Admin accounts cannot be managed from this page.",
        )

    new_password = request.form.get("new_password", "").strip()

    if new_password:
        ok, msg = is_strong_password(new_password)
        if not ok:
            users = User.query.filter(User.role != "admin").all()
            return render_template(
                "admin_users.html",
                users=users,
                page_style="admin.css",
                error=f"Password not reset for {user.email}: {msg}",
            )
    else:
        new_password = generate_strong_password()

    user.set_password(new_password)
    db.session.commit()

    users = User.query.filter(User.role != "admin").all()
    return render_template(
        "admin_users.html",
        users=users,
        page_style="admin.css",
        reset_email=user.email,
        temp_password=new_password,
    )


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # Prevent deleting admin accounts
    if user.role == "admin":
        users = User.query.filter(User.role != "admin").all()
        return render_template(
            "admin_users.html",
            users=users,
            page_style="admin.css",
            error="Admin accounts cannot be deleted."
        )

    # Prevent deleting yourself
    if user.id == session.get("user_id"):
        users = User.query.filter(User.role != "admin").all()
        return render_template(
            "admin_users.html",
            users=users,
            page_style="admin.css",
            error="You cannot delete your own account."
        )

    db.session.delete(user)
    db.session.commit()

    users = User.query.filter(User.role != "admin").all()
    return render_template(
        "admin_users.html",
        users=users,
        page_style="admin.css"
    )


# ---------- PROFILE ----------
@app.route("/profile")
@login_required
def profile():
    user = db.session.get(User, session["user_id"])
    return render_template("profile.html", user=user, page_style="profile.css", title="Your Profile – Wi-Fi Labs")


@app.route("/profile/update", methods=["POST"])
@login_required
def profile_update():
    user = db.session.get(User, session["user_id"])

    username = request.form.get("username", "").strip()
    bio = request.form.get("bio", "").strip()

    # Username validation
    if not is_valid_username(username):
        return render_template(
            "profile.html",
            user=user,
            page_style="profile.css",
            error="Username must be 3–20 characters and contain only letters, numbers, or underscores."
        )

    # Uniqueness check (exclude self)
    existing = User.query.filter(User.username == username, User.id != user.id).first()
    if existing:
        return render_template(
            "profile.html",
            user=user,
            page_style="profile.css",
            error="That username is already taken."
        )

    # Bio limit
    if len(bio) > 280:
        return render_template(
            "profile.html",
            user=user,
            page_style="profile.css",
            error="Bio must be 280 characters or fewer."
        )

    user.username = username
    user.bio = bio
    user.updated_at = datetime.utcnow()
    db.session.commit()

    return render_template(
        "profile.html",
        user=user,
        page_style="profile.css",
        success="Profile updated successfully."
    )


@app.route("/profile/change-password", methods=["POST"])
@login_required
def profile_change_password():
    user = db.session.get(User, session["user_id"])

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not user.check_password(current_password):
        return render_template(
            "profile.html",
            user=user,
            page_style="profile.css",
            error="Current password is incorrect."
        )

    if new_password != confirm_password:
        return render_template(
            "profile.html",
            user=user,
            page_style="profile.css",
            error="New password and confirmation do not match."
        )

    ok, msg = is_strong_password(new_password)
    if not ok:
        return render_template(
            "profile.html",
            user=user,
            page_style="profile.css",
            error=msg
        )

    user.set_password(new_password)
    user.updated_at = datetime.utcnow()
    db.session.commit()

    return render_template(
        "profile.html",
        user=user,
        page_style="profile.css",
        success="Password changed successfully."
    )


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    response = redirect(url_for("home"))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ====================================================
#             GLOBAL CACHE PROTECTION
# ====================================================
@app.after_request
def add_no_cache_headers(response):
    """Prevent caching of sensitive pages while logged in."""
    if session.get("user_id"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# ====================================================
#                INITIAL SETUP
# ====================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Create default admin if not exists
        if not User.query.filter_by(role="admin").first():
            admin = User(email="admin@test.com", role="admin")
            admin.set_password("admin")
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created: admin@test.com / admin")

    app.run(debug=True)
