from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from auth import role_required
from models import db, User, Role, UserRole, AccessRequest, AuditLog, write_audit_log
from policy import check_sod_batch, check_sod

jml_bp = Blueprint("jml", __name__)


# ── JML Dashboard ──────────────────────────────────────────────────────────────

@jml_bp.route("/")
@login_required
@role_required("Admin")
def dashboard():
    # Recent JML events from audit log
    joiner_logs = (
        AuditLog.query
        .filter_by(action="JML_JOINER")
        .order_by(AuditLog.timestamp.desc())
        .limit(10).all()
    )
    mover_logs = (
        AuditLog.query
        .filter_by(action="JML_MOVER")
        .order_by(AuditLog.timestamp.desc())
        .limit(10).all()
    )
    leaver_logs = (
        AuditLog.query
        .filter_by(action="JML_LEAVER")
        .order_by(AuditLog.timestamp.desc())
        .limit(10).all()
    )
    all_users = User.query.order_by(User.name).all()

    return render_template(
        "jml/dashboard.html",
        joiner_logs=joiner_logs,
        mover_logs=mover_logs,
        leaver_logs=leaver_logs,
        all_users=all_users,
    )


# ── JOINER — Onboard a new employee ───────────────────────────────────────────

@jml_bp.route("/joiner", methods=["GET", "POST"])
@login_required
@role_required("Admin")
def joiner():
    managers   = User.query.filter_by(system_role="Manager", status="Active").order_by(User.name).all()
    all_roles  = Role.query.order_by(Role.name).all()

    if request.method == "POST":
        name        = request.form.get("name", "").strip()
        email       = request.form.get("email", "").strip().lower()
        password    = request.form.get("password", "")
        department  = request.form.get("department", "").strip()
        system_role = request.form.get("system_role", "Employee")
        manager_id  = request.form.get("manager_id") or None
        role_ids    = request.form.getlist("role_ids")  # initial roles to assign

        errors = []
        if not name:    errors.append("Name is required.")
        if not email:   errors.append("Email is required.")
        if not password or len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if User.query.filter_by(email=email).first():
            errors.append(f"Email {email} is already registered.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("jml/joiner.html", managers=managers,
                                   all_roles=all_roles, form=request.form)

        # SoD check across the initial role set before creating the user
        if role_ids and len(role_ids) > 1:
            int_role_ids = [int(r) for r in role_ids if db.session.get(Role, int(r))]
            sod_violations = check_sod_batch(int_role_ids)
            if sod_violations:
                for v in sod_violations:
                    flash(f"Policy Violation — {v}", "danger")
                return render_template("jml/joiner.html", managers=managers,
                                       all_roles=all_roles, form=request.form)

        user = User(
            name=name,
            email=email,
            department=department,
            system_role=system_role,
            manager_id=int(manager_id) if manager_id else None,
            status="Active",
        )
        user.set_password(password)
        db.session.add(user)
        db.session.flush()  # get user.id before commit

        assigned_role_names = []
        for rid in role_ids:
            role = db.session.get(Role, int(rid))
            if role:
                ur = UserRole(
                    user_id=user.id,
                    role_id=role.id,
                    assigned_by=current_user.id,
                    status="Active",
                )
                db.session.add(ur)
                assigned_role_names.append(role.name)

        db.session.commit()

        roles_summary = ", ".join(assigned_role_names) if assigned_role_names else "None"

        write_audit_log(
            actor_id=current_user.id,
            action="JML_JOINER",
            target_type="User",
            target_id=user.id,
            details=f"JOINER: {user.name} ({user.email}) onboarded to {department or 'No Dept'} | Roles: {roles_summary}",
            ip_address=request.remote_addr,
        )
        write_audit_log(
            actor_id=current_user.id,
            action="USER_CREATED",
            target_type="User",
            target_id=user.id,
            details=f"{current_user.name} created user via JML Joiner: {user.name}",
            ip_address=request.remote_addr,
        )
        for rname in assigned_role_names:
            write_audit_log(
                actor_id=current_user.id,
                action="ROLE_ASSIGNED",
                target_type="User",
                target_id=user.id,
                details=f"{rname} role assigned to {user.name} during onboarding",
                ip_address=request.remote_addr,
            )

        flash(f"Joiner '{user.name}' onboarded successfully with roles: {roles_summary}.", "success")
        return redirect(url_for("admin.user_detail", user_id=user.id))

    return render_template("jml/joiner.html", managers=managers, all_roles=all_roles, form={})


# ── MOVER — Transfer / promote an existing employee ───────────────────────────

@jml_bp.route("/mover/<int:user_id>", methods=["GET", "POST"])
@login_required
@role_required("Admin")
def mover(user_id):
    user       = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("jml.dashboard"))

    managers      = User.query.filter(
        User.system_role == "Manager",
        User.status == "Active",
        User.id != user_id,
    ).order_by(User.name).all()
    all_roles     = Role.query.order_by(Role.name).all()
    current_roles = UserRole.query.filter_by(user_id=user_id, status="Active").all()

    if request.method == "POST":
        new_department  = request.form.get("department", "").strip()
        new_system_role = request.form.get("system_role", user.system_role)
        new_manager_id  = request.form.get("manager_id") or None
        revoke_ur_ids   = request.form.getlist("revoke_role_ids")   # user_role ids to revoke
        add_role_ids    = request.form.getlist("add_role_ids")       # role ids to add

        old_department  = user.department
        old_system_role = user.system_role

        user.department  = new_department
        user.system_role = new_system_role
        user.manager_id  = int(new_manager_id) if new_manager_id else None

        revoked_names = []
        revoked_role_ids = set()
        for ur_id in revoke_ur_ids:
            ur = db.session.get(UserRole, int(ur_id))
            if ur and ur.user_id == user_id:
                ur.status = "Revoked"
                revoked_names.append(ur.role.name)
                revoked_role_ids.add(ur.role_id)

        # SoD check: new roles vs (current active - revoked)
        if add_role_ids:
            remaining_role_ids = {
                ur.role_id for ur in UserRole.query.filter_by(user_id=user_id, status="Active").all()
            } - revoked_role_ids
            add_int_ids = [int(r) for r in add_role_ids]
            all_candidate_ids = list(remaining_role_ids | set(add_int_ids))
            sod_violations = check_sod_batch(all_candidate_ids)
            if sod_violations:
                # Rollback the revocations we just did
                db.session.rollback()
                for v in sod_violations:
                    flash(f"Policy Violation — {v}", "danger")
                return redirect(url_for("admin.user_detail", user_id=user_id))

        added_names = []
        for rid in add_role_ids:
            role = db.session.get(Role, int(rid))
            if role:
                already = UserRole.query.filter_by(
                    user_id=user_id, role_id=role.id, status="Active"
                ).first()
                if not already:
                    ur = UserRole(
                        user_id=user_id,
                        role_id=role.id,
                        assigned_by=current_user.id,
                        status="Active",
                    )
                    db.session.add(ur)
                    added_names.append(role.name)

        db.session.commit()

        details = (
            f"MOVER: {user.name} transferred | "
            f"Dept: {old_department or 'None'} → {new_department or 'None'} | "
            f"Role: {old_system_role} → {new_system_role} | "
            f"Revoked: {', '.join(revoked_names) or 'None'} | "
            f"Added: {', '.join(added_names) or 'None'}"
        )
        write_audit_log(
            actor_id=current_user.id,
            action="JML_MOVER",
            target_type="User",
            target_id=user.id,
            details=details,
            ip_address=request.remote_addr,
        )
        for rname in revoked_names:
            write_audit_log(current_user.id, "ROLE_REVOKED", "User", user.id,
                            f"{rname} revoked from {user.name} during transfer", request.remote_addr)
        for rname in added_names:
            write_audit_log(current_user.id, "ROLE_ASSIGNED", "User", user.id,
                            f"{rname} assigned to {user.name} during transfer", request.remote_addr)

        flash(f"Mover complete for '{user.name}'. Profile updated.", "success")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    return render_template(
        "jml/mover.html",
        user=user,
        managers=managers,
        all_roles=all_roles,
        current_roles=current_roles,
    )


# ── LEAVER — Offboard an employee ─────────────────────────────────────────────

@jml_bp.route("/leaver/<int:user_id>", methods=["GET", "POST"])
@login_required
@role_required("Admin")
def leaver(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("jml.dashboard"))

    if user.id == current_user.id:
        flash("You cannot offboard your own account.", "danger")
        return redirect(url_for("jml.dashboard"))

    active_roles    = UserRole.query.filter_by(user_id=user_id, status="Active").all()
    pending_requests = AccessRequest.query.filter(
        AccessRequest.requester_id == user_id,
        AccessRequest.stage.in_(["manager_review", "admin_review"]),
    ).all()

    if request.method == "POST":
        revoked_roles = []
        cancelled_requests = []

        # 1. Disable the account
        user.status = "Inactive"

        # 2. Revoke all active role assignments
        for ur in active_roles:
            ur.status = "Revoked"
            revoked_roles.append(ur.role.name)

        # 3. Cancel all pending access requests
        for req in pending_requests:
            req.status = "Rejected"
            req.stage  = "rejected"
            req.admin_comments = f"Auto-cancelled: {user.name} has been offboarded."
            cancelled_requests.append(req.resource_requested)

        db.session.commit()

        roles_summary    = ", ".join(revoked_roles) or "None"
        requests_summary = ", ".join(cancelled_requests) or "None"

        write_audit_log(
            actor_id=current_user.id,
            action="JML_LEAVER",
            target_type="User",
            target_id=user.id,
            details=(
                f"LEAVER: {user.name} ({user.email}) offboarded | "
                f"Roles revoked: {roles_summary} | "
                f"Requests cancelled: {requests_summary}"
            ),
            ip_address=request.remote_addr,
        )
        write_audit_log(current_user.id, "USER_DEACTIVATED", "User", user.id,
                        f"{user.name} deactivated during offboarding", request.remote_addr)
        for rname in revoked_roles:
            write_audit_log(current_user.id, "ROLE_REVOKED", "User", user.id,
                            f"{rname} revoked from {user.name} during offboarding", request.remote_addr)

        flash(
            f"'{user.name}' has been fully offboarded. "
            f"Roles revoked: {roles_summary}. "
            f"Requests cancelled: {requests_summary}.",
            "warning",
        )
        return redirect(url_for("admin.user_detail", user_id=user_id))

    return render_template(
        "jml/leaver.html",
        user=user,
        active_roles=active_roles,
        pending_requests=pending_requests,
    )
