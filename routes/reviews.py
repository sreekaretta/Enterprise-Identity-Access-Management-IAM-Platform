from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from auth import role_required
from models import db, User, Role, UserRole, AccessReview, AuditLog, write_audit_log

reviews_bp = Blueprint("reviews", __name__)

DORMANT_DAYS = 90  # flag accounts with no login beyond this


# ── Review Cycles List ─────────────────────────────────────────────────────────

@reviews_bp.route("/")
@login_required
@role_required("Admin")
def index():
    # Distinct cycles already run, with counts
    cycles_raw = (
        db.session.query(
            AccessReview.review_cycle,
            db.func.count(AccessReview.id).label("total"),
            db.func.sum(db.case((AccessReview.decision == "Revoke", 1), else_=0)).label("revoked"),
            db.func.min(AccessReview.reviewed_at).label("started"),
            db.func.max(AccessReview.reviewed_at).label("last_action"),
        )
        .group_by(AccessReview.review_cycle)
        .order_by(db.func.max(AccessReview.reviewed_at).desc())
        .all()
    )

    # Total active user-role assignments (denominator for progress)
    total_active_roles = UserRole.query.filter_by(status="Active").count()

    # Expired roles count
    today = datetime.utcnow()
    expired_count = UserRole.query.filter(
        UserRole.status == "Active",
        UserRole.expires_at != None,
        UserRole.expires_at < today,
    ).count()

    # Orphan accounts count
    orphan_count = (
        User.query
        .join(UserRole, User.id == UserRole.user_id)
        .filter(User.status == "Inactive", UserRole.status == "Active")
        .distinct().count()
    )

    # Dormant accounts count
    cutoff = today - timedelta(days=DORMANT_DAYS)
    dormant_count = User.query.filter(
        User.status == "Active",
        db.or_(User.last_login == None, User.last_login < cutoff),
    ).count()

    return render_template(
        "reviews/index.html",
        cycles=cycles_raw,
        total_active_roles=total_active_roles,
        expired_count=expired_count,
        orphan_count=orphan_count,
        dormant_count=dormant_count,
    )


# ── Start a New Review Cycle ───────────────────────────────────────────────────

@reviews_bp.route("/start", methods=["POST"])
@login_required
@role_required("Admin")
def start_cycle():
    cycle_name = request.form.get("cycle_name", "").strip()
    if not cycle_name:
        flash("Please provide a cycle name (e.g. Q3-2026).", "danger")
        return redirect(url_for("reviews.index"))

    existing = AccessReview.query.filter_by(review_cycle=cycle_name).first()
    if existing:
        flash(f"Cycle '{cycle_name}' already exists. Open it to continue reviewing.", "warning")
        return redirect(url_for("reviews.cycle", cycle_name=cycle_name))

    write_audit_log(
        actor_id=current_user.id,
        action="REVIEW_CYCLE_STARTED",
        target_type="System",
        target_id=None,
        details=f"{current_user.name} started access review cycle: {cycle_name}",
        ip_address=request.remote_addr,
    )

    flash(f"Review cycle '{cycle_name}' started.", "success")
    return redirect(url_for("reviews.cycle", cycle_name=cycle_name))


# ── Review Cycle Detail ────────────────────────────────────────────────────────

@reviews_bp.route("/cycle/<cycle_name>")
@login_required
@role_required("Admin")
def cycle(cycle_name):
    # All active user-role assignments
    all_urs = (
        UserRole.query
        .filter_by(status="Active")
        .join(User, UserRole.user_id == User.id)
        .order_by(User.name)
        .all()
    )

    # Which user-role ids have already been reviewed in this cycle
    reviewed = {
        r.user_role_id: r
        for r in AccessReview.query.filter_by(review_cycle=cycle_name).all()
    }

    today = datetime.utcnow()
    pending_count   = sum(1 for ur in all_urs if ur.id not in reviewed)
    completed_count = len(reviewed)

    return render_template(
        "reviews/cycle.html",
        cycle_name=cycle_name,
        all_urs=all_urs,
        reviewed=reviewed,
        today=today,
        pending_count=pending_count,
        completed_count=completed_count,
    )


# ── Submit Keep / Revoke Decision ──────────────────────────────────────────────

@reviews_bp.route("/cycle/<cycle_name>/decide/<int:ur_id>", methods=["POST"])
@login_required
@role_required("Admin")
def decide(cycle_name, ur_id):
    ur = db.session.get(UserRole, ur_id)
    if not ur or ur.status != "Active":
        flash("Role assignment not found.", "danger")
        return redirect(url_for("reviews.cycle", cycle_name=cycle_name))

    decision = request.form.get("decision")  # "Keep" or "Revoke"
    comments = request.form.get("comments", "").strip()

    if decision not in ("Keep", "Revoke"):
        flash("Invalid decision.", "danger")
        return redirect(url_for("reviews.cycle", cycle_name=cycle_name))

    # Upsert — update existing review if re-decided
    existing = AccessReview.query.filter_by(
        review_cycle=cycle_name, user_role_id=ur_id
    ).first()

    if existing:
        existing.decision    = decision
        existing.comments    = comments
        existing.reviewed_at = datetime.utcnow()
        existing.reviewer_id = current_user.id
    else:
        review = AccessReview(
            reviewer_id=current_user.id,
            user_id=ur.user_id,
            user_role_id=ur_id,
            decision=decision,
            comments=comments,
            review_cycle=cycle_name,
        )
        db.session.add(review)

    if decision == "Revoke":
        ur.status = "Revoked"
        write_audit_log(
            actor_id=current_user.id,
            action="ROLE_REVOKED",
            target_type="UserRole",
            target_id=ur_id,
            details=f"Access review [{cycle_name}]: {ur.role.name} revoked from {ur.user.name}",
            ip_address=request.remote_addr,
        )

    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="REVIEW_COMPLETED",
        target_type="UserRole",
        target_id=ur_id,
        details=f"Review [{cycle_name}]: {ur.user.name} / {ur.role.name} → {decision}",
        ip_address=request.remote_addr,
    )

    return redirect(url_for("reviews.cycle", cycle_name=cycle_name))


# ── Bulk Complete Cycle (mark all unreviewed as Keep) ─────────────────────────

@reviews_bp.route("/cycle/<cycle_name>/complete", methods=["POST"])
@login_required
@role_required("Admin")
def complete_cycle(cycle_name):
    all_urs = UserRole.query.filter_by(status="Active").all()
    reviewed_ids = {
        r.user_role_id
        for r in AccessReview.query.filter_by(review_cycle=cycle_name).all()
    }

    count = 0
    for ur in all_urs:
        if ur.id not in reviewed_ids:
            review = AccessReview(
                reviewer_id=current_user.id,
                user_id=ur.user_id,
                user_role_id=ur.id,
                decision="Keep",
                comments="Auto-certified at cycle close.",
                review_cycle=cycle_name,
            )
            db.session.add(review)
            count += 1

    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="REVIEW_CYCLE_CLOSED",
        target_type="System",
        target_id=None,
        details=f"{current_user.name} closed review cycle [{cycle_name}]. {count} role(s) auto-certified.",
        ip_address=request.remote_addr,
    )

    flash(f"Cycle '{cycle_name}' closed. {count} remaining role(s) auto-certified as Keep.", "success")
    return redirect(url_for("reviews.index"))


# ── Access Expiry ──────────────────────────────────────────────────────────────

@reviews_bp.route("/expiry")
@login_required
@role_required("Admin")
def expiry():
    today = datetime.utcnow()
    soon  = today + timedelta(days=30)

    expired = (
        UserRole.query
        .filter(
            UserRole.status == "Active",
            UserRole.expires_at != None,
            UserRole.expires_at < today,
        )
        .join(User, UserRole.user_id == User.id)
        .order_by(UserRole.expires_at)
        .all()
    )

    expiring_soon = (
        UserRole.query
        .filter(
            UserRole.status == "Active",
            UserRole.expires_at != None,
            UserRole.expires_at >= today,
            UserRole.expires_at <= soon,
        )
        .join(User, UserRole.user_id == User.id)
        .order_by(UserRole.expires_at)
        .all()
    )

    return render_template(
        "reviews/expiry.html",
        expired=expired,
        expiring_soon=expiring_soon,
        today=today,
    )


@reviews_bp.route("/expiry/<int:ur_id>/revoke", methods=["POST"])
@login_required
@role_required("Admin")
def revoke_expired(ur_id):
    ur = db.session.get(UserRole, ur_id)
    if not ur:
        flash("Role assignment not found.", "danger")
        return redirect(url_for("reviews.expiry"))

    ur.status = "Revoked"
    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="ACCESS_EXPIRED",
        target_type="UserRole",
        target_id=ur_id,
        details=f"Expired access revoked: {ur.role.name} from {ur.user.name} (expired {ur.expires_at.strftime('%Y-%m-%d')})",
        ip_address=request.remote_addr,
    )

    flash(f"{ur.role.name} revoked from '{ur.user.name}' (expired access).", "warning")
    return redirect(url_for("reviews.expiry"))


@reviews_bp.route("/expiry/revoke-all", methods=["POST"])
@login_required
@role_required("Admin")
def revoke_all_expired():
    today = datetime.utcnow()
    expired = UserRole.query.filter(
        UserRole.status == "Active",
        UserRole.expires_at != None,
        UserRole.expires_at < today,
    ).all()

    count = 0
    for ur in expired:
        ur.status = "Revoked"
        write_audit_log(
            current_user.id, "ACCESS_EXPIRED", "UserRole", ur.id,
            f"Bulk revoke: {ur.role.name} from {ur.user.name}",
            request.remote_addr,
        )
        count += 1

    db.session.commit()
    flash(f"{count} expired role(s) revoked.", "warning")
    return redirect(url_for("reviews.expiry"))


# ── Orphan & Dormant Accounts ──────────────────────────────────────────────────

@reviews_bp.route("/orphans")
@login_required
@role_required("Admin")
def orphans():
    today  = datetime.utcnow()
    cutoff = today - timedelta(days=DORMANT_DAYS)

    # Orphan: inactive user who still has active roles
    orphan_users = (
        User.query
        .join(UserRole, User.id == UserRole.user_id)
        .filter(User.status == "Inactive", UserRole.status == "Active")
        .distinct()
        .all()
    )
    orphan_roles = {
        u.id: UserRole.query.filter_by(user_id=u.id, status="Active").all()
        for u in orphan_users
    }

    # Dormant: active user with no login or last login > 90 days ago
    dormant_users = (
        User.query
        .filter(
            User.status == "Active",
            db.or_(User.last_login == None, User.last_login < cutoff),
        )
        .order_by(User.last_login)
        .all()
    )

    return render_template(
        "reviews/orphans.html",
        orphan_users=orphan_users,
        orphan_roles=orphan_roles,
        dormant_users=dormant_users,
        today=today,
        cutoff=cutoff,
        dormant_days=DORMANT_DAYS,
    )


@reviews_bp.route("/orphans/<int:user_id>/fix", methods=["POST"])
@login_required
@role_required("Admin")
def fix_orphan(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("reviews.orphans"))

    active_roles = UserRole.query.filter_by(user_id=user_id, status="Active").all()
    revoked = []
    for ur in active_roles:
        ur.status = "Revoked"
        revoked.append(ur.role.name)

    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="ORPHAN_REMEDIATED",
        target_type="User",
        target_id=user_id,
        details=f"Orphan account fixed: {user.name} — roles revoked: {', '.join(revoked)}",
        ip_address=request.remote_addr,
    )

    flash(f"Orphan account '{user.name}' remediated. Roles revoked: {', '.join(revoked)}.", "success")
    return redirect(url_for("reviews.orphans"))


@reviews_bp.route("/orphans/<int:user_id>/disable", methods=["POST"])
@login_required
@role_required("Admin")
def disable_dormant(user_id):
    user = db.session.get(User, user_id)
    if not user or user.id == current_user.id:
        flash("Cannot disable this account.", "danger")
        return redirect(url_for("reviews.orphans"))

    user.status = "Inactive"
    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="USER_DEACTIVATED",
        target_type="User",
        target_id=user_id,
        details=f"Dormant account disabled: {user.name} (no login in {DORMANT_DAYS}+ days)",
        ip_address=request.remote_addr,
    )

    flash(f"Dormant account '{user.name}' disabled.", "warning")
    return redirect(url_for("reviews.orphans"))
