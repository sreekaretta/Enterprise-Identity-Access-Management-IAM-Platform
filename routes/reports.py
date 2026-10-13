import csv
import io
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, Response
from flask_login import login_required
from auth import role_required
from models import db, User, Role, UserRole, AccessRequest, AccessReview, AuditLog

reports_bp = Blueprint("reports", __name__)

DORMANT_DAYS = 90


# ── Governance Dashboard ───────────────────────────────────────────────────────

@reports_bp.route("/")
@login_required
@role_required("Admin")
def index():
    today  = datetime.utcnow()
    cutoff = today - timedelta(days=DORMANT_DAYS)
    month_ago = today - timedelta(days=30)

    # User stats
    total_users    = User.query.count()
    active_users   = User.query.filter_by(status="Active").count()
    inactive_users = User.query.filter_by(status="Inactive").count()

    # Access request stats
    pending_requests    = AccessRequest.query.filter(
        AccessRequest.stage.in_(["manager_review", "admin_review"])
    ).count()
    provisioned_requests = AccessRequest.query.filter_by(status="Provisioned").count()
    rejected_requests   = AccessRequest.query.filter_by(status="Rejected").count()

    # Role stats
    total_role_grants  = UserRole.query.filter_by(status="Active").count()
    expired_grants     = UserRole.query.filter(
        UserRole.status == "Active",
        UserRole.expires_at != None,
        UserRole.expires_at < today,
    ).count()

    # Orphan & dormant
    orphan_count = (
        User.query
        .join(UserRole, User.id == UserRole.user_id)
        .filter(User.status == "Inactive", UserRole.status == "Active")
        .distinct().count()
    )
    dormant_count = User.query.filter(
        User.status == "Active",
        db.or_(User.last_login == None, User.last_login < cutoff),
    ).count()

    # JML activity last 30 days
    jml_joiners = AuditLog.query.filter(
        AuditLog.action == "JML_JOINER",
        AuditLog.timestamp >= month_ago,
    ).count()
    jml_movers = AuditLog.query.filter(
        AuditLog.action == "JML_MOVER",
        AuditLog.timestamp >= month_ago,
    ).count()
    jml_leavers = AuditLog.query.filter(
        AuditLog.action == "JML_LEAVER",
        AuditLog.timestamp >= month_ago,
    ).count()

    # Role distribution
    role_counts = (
        db.session.query(Role.name, db.func.count(UserRole.id).label("cnt"))
        .join(UserRole, Role.id == UserRole.role_id)
        .filter(UserRole.status == "Active")
        .group_by(Role.name)
        .order_by(db.func.count(UserRole.id).desc())
        .all()
    )

    # Recent audit activity
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(15).all()

    return render_template(
        "reports/index.html",
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        pending_requests=pending_requests,
        provisioned_requests=provisioned_requests,
        rejected_requests=rejected_requests,
        total_role_grants=total_role_grants,
        expired_grants=expired_grants,
        orphan_count=orphan_count,
        dormant_count=dormant_count,
        jml_joiners=jml_joiners,
        jml_movers=jml_movers,
        jml_leavers=jml_leavers,
        role_counts=role_counts,
        recent_logs=recent_logs,
        today=today,
    )


# ── Full Audit Log ─────────────────────────────────────────────────────────────

@reports_bp.route("/audit")
@login_required
@role_required("Admin")
def audit_log():
    # Filters from query string
    action_filter = request.args.get("action", "").strip()
    actor_filter  = request.args.get("actor", "").strip().lower()
    date_from     = request.args.get("date_from", "").strip()
    date_to       = request.args.get("date_to", "").strip()

    query = AuditLog.query

    if action_filter:
        query = query.filter(AuditLog.action == action_filter)

    if actor_filter:
        query = query.join(User, AuditLog.actor_id == User.id, isouter=True).filter(
            db.func.lower(User.name).contains(actor_filter)
        )

    if date_from:
        try:
            query = query.filter(AuditLog.timestamp >= datetime.strptime(date_from, "%Y-%m-%d"))
        except ValueError:
            pass

    if date_to:
        try:
            dt_to = datetime.strptime(date_to, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            query = query.filter(AuditLog.timestamp <= dt_to)
        except ValueError:
            pass

    logs = query.order_by(AuditLog.timestamp.desc()).limit(500).all()

    # All distinct action types for filter dropdown
    action_types = [
        r[0] for r in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()
    ]

    return render_template(
        "reports/audit.html",
        logs=logs,
        action_types=action_types,
        action_filter=action_filter,
        actor_filter=actor_filter,
        date_from=date_from,
        date_to=date_to,
    )


# ── CSV Exports ────────────────────────────────────────────────────────────────

def _csv_response(filename, headers, rows):
    """Build a streaming CSV download response."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(headers)
    writer.writerows(rows)
    output = buf.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@reports_bp.route("/export/audit")
@login_required
@role_required("Admin")
def export_audit():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    rows = [
        (
            log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            log.actor.name if log.actor else "System",
            log.action,
            log.target_type or "",
            log.target_id or "",
            log.details or "",
            log.ip_address or "",
        )
        for log in logs
    ]
    return _csv_response(
        f"audit_log_{datetime.utcnow().strftime('%Y%m%d')}.csv",
        ["Timestamp", "Actor", "Action", "Target Type", "Target ID", "Details", "IP Address"],
        rows,
    )


@reports_bp.route("/export/user-roles")
@login_required
@role_required("Admin")
def export_user_roles():
    urs = (
        UserRole.query
        .join(User, UserRole.user_id == User.id)
        .order_by(User.name)
        .all()
    )
    rows = [
        (
            ur.user.name,
            ur.user.email,
            ur.user.department or "",
            ur.user.status,
            ur.role.name,
            ur.status,
            ur.assigned_at.strftime("%Y-%m-%d"),
            ur.expires_at.strftime("%Y-%m-%d") if ur.expires_at else "No expiry",
            ur.assigner.name if ur.assigner else "System",
        )
        for ur in urs
    ]
    return _csv_response(
        f"user_roles_{datetime.utcnow().strftime('%Y%m%d')}.csv",
        ["User", "Email", "Department", "Account Status", "Role",
         "Role Status", "Assigned Date", "Expiry Date", "Assigned By"],
        rows,
    )


@reports_bp.route("/export/orphans")
@login_required
@role_required("Admin")
def export_orphans():
    orphan_users = (
        User.query
        .join(UserRole, User.id == UserRole.user_id)
        .filter(User.status == "Inactive", UserRole.status == "Active")
        .distinct()
        .all()
    )
    rows = []
    for u in orphan_users:
        active_roles = UserRole.query.filter_by(user_id=u.id, status="Active").all()
        for ur in active_roles:
            rows.append((
                u.name, u.email, u.department or "", u.status,
                ur.role.name, ur.assigned_at.strftime("%Y-%m-%d"),
                "ORPHAN — Inactive user with active access",
            ))
    return _csv_response(
        f"orphan_accounts_{datetime.utcnow().strftime('%Y%m%d')}.csv",
        ["User", "Email", "Department", "Account Status",
         "Role", "Assigned Date", "Flag"],
        rows,
    )


@reports_bp.route("/export/reviews")
@login_required
@role_required("Admin")
def export_reviews():
    reviews = (
        AccessReview.query
        .join(User, AccessReview.user_id == User.id)
        .order_by(AccessReview.review_cycle, User.name)
        .all()
    )
    rows = [
        (
            r.review_cycle,
            r.subject.name,
            r.subject.email,
            r.subject.department or "",
            r.user_role.role.name if r.user_role else "",
            r.decision,
            r.comments or "",
            r.reviewer.name if r.reviewer else "",
            r.reviewed_at.strftime("%Y-%m-%d %H:%M:%S"),
        )
        for r in reviews
    ]
    return _csv_response(
        f"access_reviews_{datetime.utcnow().strftime('%Y%m%d')}.csv",
        ["Cycle", "User", "Email", "Department", "Role",
         "Decision", "Comments", "Reviewer", "Reviewed At"],
        rows,
    )
