from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
from sqlalchemy import event

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)

    # Public-facing random ID (keep numeric PK internal)
    public_id = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4())
    )

    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    # Profile fields
    username = db.Column(db.String(40), unique=True, nullable=False)
    bio = db.Column(db.String(280), nullable=True)

    # Audit fields
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password: str) -> None:
        """Hash and store the user’s password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify a provided password against the stored hash."""
        return check_password_hash(self.password_hash, password)


@event.listens_for(User, "before_insert")
def user_before_insert(mapper, connection, target: User):
    """
    Ensure public_id and username are set before insert.
    This is the reliable place to do it (defaults are applied here).
    """
    if not target.public_id:
        target.public_id = str(uuid.uuid4())

    if not target.username:
        # Default username to the same value as public_id (as you wanted)
        target.username = target.public_id

    if not target.created_at:
        target.created_at = datetime.utcnow()
