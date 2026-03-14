from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
import re
from sqlalchemy import event


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4())
    )

    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    username = db.Column(db.String(40), unique=True, nullable=False)
    bio = db.Column(db.String(280), nullable=True)

    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Scenario(db.Model):
    __tablename__ = "scenario"

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4())
    )

    title = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(140), unique=True, nullable=False)
    summary = db.Column(db.String(280), nullable=True)
    description = db.Column(db.Text, nullable=False)

    country = db.Column(db.String(8), nullable=False, default="US")
    topology_json = db.Column(db.Text, nullable=True)
    manifest_json = db.Column(db.Text, nullable=True)
    generated_script = db.Column(db.Text, nullable=True)
    artifact_dir = db.Column(db.String(255), nullable=True)

    is_published = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_by = db.relationship("User", backref="created_scenarios")

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True)


@event.listens_for(User, "before_insert")
def user_before_insert(mapper, connection, target: User):
    if not target.public_id:
        target.public_id = str(uuid.uuid4())

    if not target.username:
        target.username = target.public_id

    if not target.created_at:
        target.created_at = datetime.utcnow()


@event.listens_for(Scenario, "before_insert")
def scenario_before_insert(mapper, connection, target: Scenario):
    if not target.public_id:
        target.public_id = str(uuid.uuid4())

    if not target.slug and target.title:
        base = re.sub(r"[^a-z0-9\s-]", "", target.title.lower()).strip()
        target.slug = re.sub(r"[\s-]+", "-", base).strip("-") or str(uuid.uuid4())

    if not target.created_at:
        target.created_at = datetime.utcnow()


@event.listens_for(Scenario, "before_update")
def scenario_before_update(mapper, connection, target: Scenario):
    target.updated_at = datetime.utcnow()

