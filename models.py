from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import bcrypt

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    department = db.Column(db.String(100))
    system_role = db.Column(db.String(20), nullable=False, default="Employee")  # Admin, Manager, Employee
    status = db.Column(db.String(20), nullable=False, default="Active")          # Active, Inactive
    manager_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    last_login   = db.Column(db.DateTime, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    totp_secret  = db.Column(db.String(32), nullable=True)   # base32 TOTP secret
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)

    manager = db.relationship("User", remote_side=[id], backref="subordinates")
    user_roles = db.relationship("UserRole", foreign_keys="UserRole.user_id", backref="user", lazy="dynamic")

    def set_password(self, password: str):
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))

    def is_admin(self):
        return self.system_role == "Admin"

    def is_manager(self):
        return self.system_role == "Manager"

    def is_employee(self):
        return self.system_role == "Employee"

    def __repr__(self):
        return f"<User {self.email} [{self.system_role}]>"


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)   # HR, Finance, IT, Security
    description = db.Column(db.Text)
    classification = db.Column(db.String(20), default="Internal")  # Public, Internal, Confidential, Restricted
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Role {self.name}>"


class UserRole(db.Model):
    __tablename__ = "user_roles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    assigned_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default="Active")  # Active, Revoked, Expired

    role = db.relationship("Role", backref="user_roles")
    assigner = db.relationship("User", foreign_keys=[assigned_by])

    def __repr__(self):
        return f"<UserRole user={self.user_id} role={self.role_id} status={self.status}>"


class AccessRequest(db.Model):
    __tablename__ = "access_requests"

    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    resource_requested = db.Column(db.String(200), nullable=False)
    reason = db.Column(db.Text, nullable=False)

    # State machine: Pending → Manager Approved → Admin Approved → Provisioned (or Rejected at any stage)
    status = db.Column(db.String(30), default="Pending")
    stage = db.Column(db.String(30), default="manager_review")  # manager_review, admin_review, provisioned, rejected

    manager_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    manager_decision = db.Column(db.String(20), nullable=True)   # Approved, Rejected
    manager_comments = db.Column(db.Text)
    manager_action_at = db.Column(db.DateTime, nullable=True)

    admin_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    admin_decision = db.Column(db.String(20), nullable=True)     # Approved, Rejected
    admin_comments = db.Column(db.Text)
    admin_action_at = db.Column(db.DateTime, nullable=True)

    provisioned_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    requester = db.relationship("User", foreign_keys=[requester_id], backref="access_requests")
    manager = db.relationship("User", foreign_keys=[manager_id])
    admin = db.relationship("User", foreign_keys=[admin_id])

    def __repr__(self):
        return f"<AccessRequest {self.resource_requested} [{self.status}]>"


class AccessReview(db.Model):
    __tablename__ = "access_reviews"

    id = db.Column(db.Integer, primary_key=True)
    reviewer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user_role_id = db.Column(db.Integer, db.ForeignKey("user_roles.id"), nullable=False)
    decision = db.Column(db.String(10), nullable=False)   # Keep, Revoke
    comments = db.Column(db.Text)
    reviewed_at = db.Column(db.DateTime, default=datetime.utcnow)
    review_cycle = db.Column(db.String(20))               # e.g. Q2-2026

    reviewer = db.relationship("User", foreign_keys=[reviewer_id])
    subject = db.relationship("User", foreign_keys=[user_id])
    user_role = db.relationship("UserRole")

    def __repr__(self):
        return f"<AccessReview cycle={self.review_cycle} decision={self.decision}>"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    target_type = db.Column(db.String(30))    # User, AccessRequest, Role, System
    target_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text)              # Human-readable description
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))

    actor = db.relationship("User", foreign_keys=[actor_id])

    def __repr__(self):
        return f"<AuditLog {self.action} at {self.timestamp}>"


class SodRule(db.Model):
    __tablename__ = "sod_rules"

    id = db.Column(db.Integer, primary_key=True)
    role_id_1 = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    role_id_2 = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    role_1 = db.relationship("Role", foreign_keys=[role_id_1])
    role_2 = db.relationship("Role", foreign_keys=[role_id_2])
    creator = db.relationship("User", foreign_keys=[created_by])

    def __repr__(self):
        return f"<SodRule {self.role_id_1} ↔ {self.role_id_2}>"


def write_audit_log(actor_id, action, target_type=None, target_id=None, details=None, ip_address=None):
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
        ip_address=ip_address,
    )
    db.session.add(entry)
    db.session.commit()
