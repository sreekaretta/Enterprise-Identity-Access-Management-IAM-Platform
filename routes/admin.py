from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from auth import role_required
from models import db, User, Role, UserRole, AccessRequest, AuditLog, SodRule, write_audit_log
from policy import check_policy

admin_bp = Blueprint("admin", __name__)


# ── Dashboard ──────────────────────────────────────────────────────────────────

@admin_bp.route("/dashboard")
@login_required
@role_required("Admin")
def dashboard():
    total_users    = User.query.count()
    active_users   = User.query.filter_by(status="Active").count()
    inactive_users = User.query.filter_by(status="Inactive").count()
    pending_requests = AccessRequest.query.filter_by(stage="admin_review").count()
    recent_logs    = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()

    orphan_accounts = (
        User.query
        .join(UserRole, User.id == UserRole.user_id)
        .filter(User.status == "Inactive", UserRole.status == "Active")
        .distinct()
        .all()
    )

    return render_template(
        "dashboard/admin.html",
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        pending_requests=pending_requests,
        recent_logs=recent_logs,
        orphan_accounts=orphan_accounts,
    )


# ── User List ──────────────────────────────────────────────────────────────────

@admin_bp.route("/users")
@login_required
@role_required("Admin")
def user_list():
    users = User.query.order_by(User.name).all()
    return render_template("users/list.html", users=users)


# ── Create User ────────────────────────────────────────────────────────────────

@admin_bp.route("/users/new", methods=["GET", "POST"])
@login_required
@role_required("Admin")
def user_create():
    managers = User.query.filter_by(system_role="Manager", status="Active").order_by(User.name).all()

    if request.method == "POST":
        name        = request.form.get("name", "").strip()
        email       = request.form.get("email", "").strip().lower()
        password    = request.form.get("password", "")
        department  = request.form.get("department", "").strip()
        system_role = request.form.get("system_role", "Employee")
        manager_id  = request.form.get("manager_id") or None
        status      = request.form.get("status", "Active")

        errors = []
        if not name:
            errors.append("Name is required.")
        if not email:
            errors.append("Email is required.")
        if not password or len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if User.query.filter_by(email=email).first():
            errors.append(f"Email {email} is already registered.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("users/form.html", managers=managers, form=request.form, action="create")

        user = User(
            name=name,
            email=email,
            department=department,
            system_role=system_role,
            manager_id=int(manager_id) if manager_id else None,
            status=status,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        write_audit_log(
            actor_id=current_user.id,
            action="USER_CREATED",
            target_type="User",
            target_id=user.id,
            details=f"{current_user.name} created user: {user.name} ({user.email}) [{user.system_role}]",
            ip_address=request.remote_addr,
        )

        flash(f"User '{user.name}' created successfully.", "success")
        return redirect(url_for("admin.user_detail", user_id=user.id))

    return render_template("users/form.html", managers=managers, form={}, action="create")


# ── User Detail ────────────────────────────────────────────────────────────────

@admin_bp.route("/users/<int:user_id>")
@login_required
@role_required("Admin")
def user_detail(user_id):
    user       = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.user_list"))

    all_roles    = Role.query.order_by(Role.name).all()
    active_roles = UserRole.query.filter_by(user_id=user_id, status="Active").all()
    active_role_ids = {ur.role_id for ur in active_roles}
    # SQLite returns naive datetimes — strip tzinfo for comparison
    today = datetime.utcnow()

    return render_template(
        "users/detail.html",
        user=user,
        all_roles=all_roles,
        active_roles=active_roles,
        active_role_ids=active_role_ids,
        today=today,
        today_str=today.strftime("%Y-%m-%d"),
    )


# ── Edit User ──────────────────────────────────────────────────────────────────

@admin_bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("Admin")
def user_edit(user_id):
    user     = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.user_list"))

    managers = User.query.filter(
        User.system_role == "Manager",
        User.status == "Active",
        User.id != user_id,
    ).order_by(User.name).all()

    if request.method == "POST":
        name        = request.form.get("name", "").strip()
        email       = request.form.get("email", "").strip().lower()
        department  = request.form.get("department", "").strip()
        system_role = request.form.get("system_role", user.system_role)
        manager_id  = request.form.get("manager_id") or None
        status      = request.form.get("status", user.status)
        new_password = request.form.get("password", "").strip()

        errors = []
        if not name:
            errors.append("Name is required.")
        if not email:
            errors.append("Email is required.")
        existing = User.query.filter_by(email=email).first()
        if existing and existing.id != user_id:
            errors.append(f"Email {email} is already in use by another account.")
        if new_password and len(new_password) < 8:
            errors.append("New password must be at least 8 characters.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("users/form.html", managers=managers, form=request.form, action="edit", user=user)

        old_status = user.status
        user.name        = name
        user.email       = email
        user.department  = department
        user.system_role = system_role
        user.manager_id  = int(manager_id) if manager_id else None
        user.status      = status
        if new_password:
            user.set_password(new_password)

        db.session.commit()

        action = "USER_MODIFIED"
        details = f"{current_user.name} edited user: {user.name} ({user.email})"

        # If status changed to Inactive, note it
        if old_status == "Active" and status == "Inactive":
            action = "USER_DEACTIVATED"
            details = f"{current_user.name} deactivated user: {user.name}"
        elif old_status == "Inactive" and status == "Active":
            action = "USER_REACTIVATED"
            details = f"{current_user.name} reactivated user: {user.name}"

        write_audit_log(
            actor_id=current_user.id,
            action=action,
            target_type="User",
            target_id=user.id,
            details=details,
            ip_address=request.remote_addr,
        )

        flash(f"User '{user.name}' updated successfully.", "success")
        return redirect(url_for("admin.user_detail", user_id=user.id))

    return render_template("users/form.html", managers=managers, form=user, action="edit", user=user)


# ── Toggle User Status ─────────────────────────────────────────────────────────

@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@role_required("Admin")
def user_toggle(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.user_list"))

    if user.id == current_user.id:
        flash("You cannot disable your own account.", "warning")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    if user.status == "Active":
        user.status = "Inactive"
        action  = "USER_DEACTIVATED"
        details = f"{current_user.name} deactivated user: {user.name}"
        msg     = f"'{user.name}' has been disabled."
        cat     = "warning"
    else:
        user.status = "Active"
        action  = "USER_REACTIVATED"
        details = f"{current_user.name} reactivated user: {user.name}"
        msg     = f"'{user.name}' has been re-enabled."
        cat     = "success"

    db.session.commit()
    write_audit_log(current_user.id, action, "User", user.id, details, request.remote_addr)
    flash(msg, cat)
    return redirect(url_for("admin.user_detail", user_id=user_id))


# ── Delete User ────────────────────────────────────────────────────────────────

@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required("Admin")
def user_delete(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.user_list"))

    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    name = user.name
    # Cascade: revoke all role assignments first
    UserRole.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="USER_DELETED",
        target_type="User",
        target_id=user_id,
        details=f"{current_user.name} permanently deleted user: {name}",
        ip_address=request.remote_addr,
    )
    flash(f"User '{name}' has been permanently deleted.", "danger")
    return redirect(url_for("admin.user_list"))


# ── Assign Role ────────────────────────────────────────────────────────────────

@admin_bp.route("/users/<int:user_id>/assign-role", methods=["POST"])
@login_required
@role_required("Admin")
def assign_role(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin.user_list"))

    role_id    = request.form.get("role_id", type=int)
    expires_at = request.form.get("expires_at") or None

    if not role_id:
        flash("Please select a role.", "warning")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    role = db.session.get(Role, role_id)
    if not role:
        flash("Role not found.", "danger")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    # Check if already assigned
    existing = UserRole.query.filter_by(user_id=user_id, role_id=role_id, status="Active").first()
    if existing:
        flash(f"'{user.name}' already has the {role.name} role.", "warning")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    # Policy check — SoD + classification
    passed, violations, warnings = check_policy(user_id, role_id)
    if not passed:
        for v in violations:
            flash(f"Policy Violation — {v}", "danger")
        write_audit_log(
            actor_id=current_user.id,
            action="SOD_VIOLATION_BLOCKED",
            target_type="User",
            target_id=user_id,
            details=f"Assignment blocked: {role.name} → {user.name} | {'; '.join(violations)}",
            ip_address=request.remote_addr,
        )
        return redirect(url_for("admin.user_detail", user_id=user_id))
    for w in warnings:
        flash(f"Policy Warning — {w}", "warning")

    expiry = None
    if expires_at:
        try:
            expiry = datetime.strptime(expires_at, "%Y-%m-%d")  # naive, consistent with SQLite
        except ValueError:
            flash("Invalid expiry date format.", "danger")
            return redirect(url_for("admin.user_detail", user_id=user_id))

    ur = UserRole(
        user_id=user_id,
        role_id=role_id,
        assigned_by=current_user.id,
        expires_at=expiry,
        status="Active",
    )
    db.session.add(ur)
    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="ROLE_ASSIGNED",
        target_type="UserRole",
        target_id=ur.id,
        details=f"{current_user.name} assigned {role.name} role to {user.name}",
        ip_address=request.remote_addr,
    )
    flash(f"{role.name} role assigned to '{user.name}'.", "success")
    return redirect(url_for("admin.user_detail", user_id=user_id))


# ── Revoke Role ────────────────────────────────────────────────────────────────

@admin_bp.route("/users/<int:user_id>/revoke-role/<int:ur_id>", methods=["POST"])
@login_required
@role_required("Admin")
def revoke_role(user_id, ur_id):
    ur = db.session.get(UserRole, ur_id)
    if not ur or ur.user_id != user_id:
        flash("Role assignment not found.", "danger")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    role_name = ur.role.name
    user_name = ur.user.name
    ur.status = "Revoked"
    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="ROLE_REVOKED",
        target_type="UserRole",
        target_id=ur_id,
        details=f"{current_user.name} revoked {role_name} role from {user_name}",
        ip_address=request.remote_addr,
    )
    flash(f"{role_name} role revoked from '{user_name}'.", "warning")
    return redirect(url_for("admin.user_detail", user_id=user_id))


# ── Access Request Queue ───────────────────────────────────────────────────────

@admin_bp.route("/requests")
@login_required
@role_required("Admin")
def request_queue():
    pending = (
        AccessRequest.query
        .filter_by(stage="admin_review")
        .order_by(AccessRequest.created_at.desc())
        .all()
    )
    history = (
        AccessRequest.query
        .filter(AccessRequest.stage.in_(["provisioned", "rejected"]))
        .order_by(AccessRequest.created_at.desc())
        .limit(30)
        .all()
    )
    return render_template("requests/admin_queue.html", pending=pending, history=history)


@admin_bp.route("/requests/<int:req_id>")
@login_required
@role_required("Admin")
def request_detail(req_id):
    req = db.session.get(AccessRequest, req_id)
    if not req:
        flash("Request not found.", "danger")
        return redirect(url_for("admin.request_queue"))
    from routes.employee import REQUESTABLE_RESOURCES
    role_name = REQUESTABLE_RESOURCES.get(req.resource_requested)
    resource_role = Role.query.filter_by(name=role_name).first() if role_name else None
    return render_template("requests/detail.html", req=req, viewer="admin",
                           resource_role=resource_role)


@admin_bp.route("/requests/<int:req_id>/approve", methods=["POST"])
@login_required
@role_required("Admin")
def approve_request(req_id):
    req = AccessRequest.query.filter_by(id=req_id, stage="admin_review").first()
    if not req:
        flash("Request not found or already actioned.", "warning")
        return redirect(url_for("admin.request_queue"))

    # Policy check BEFORE making any changes
    from routes.employee import REQUESTABLE_RESOURCES as _RR
    _role_name_pre = _RR.get(req.resource_requested)
    if _role_name_pre:
        _role_pre = Role.query.filter_by(name=_role_name_pre).first()
        if _role_pre:
            _passed, _violations, _warnings = check_policy(
                req.requester_id, _role_pre.id, justification=req.reason
            )
            if not _passed:
                write_audit_log(
                    actor_id=current_user.id,
                    action="SOD_VIOLATION_BLOCKED",
                    target_type="AccessRequest",
                    target_id=req.id,
                    details=f"Provisioning blocked for {req.requester.name} ({req.resource_requested}): {'; '.join(_violations)}",
                    ip_address=request.remote_addr,
                )
                flash(f"Cannot provision — Policy violation: {'; '.join(_violations)}", "danger")
                return redirect(url_for("admin.request_detail", req_id=req_id))
            for w in _warnings:
                flash(f"Policy Warning — {w}", "warning")

    comments = request.form.get("comments", "").strip()

    req.admin_id         = current_user.id
    req.admin_decision   = "Approved"
    req.admin_comments   = comments
    req.admin_action_at  = datetime.utcnow()
    req.status           = "Provisioned"
    req.stage            = "provisioned"
    req.provisioned_at   = datetime.utcnow()
    req.expires_at       = None  # no expiry unless set later in access review

    # Auto-provision: find a Role matching the requested resource name
    from routes.employee import REQUESTABLE_RESOURCES
    role_name = REQUESTABLE_RESOURCES.get(req.resource_requested)
    provisioned_role = None
    if role_name:
        role = Role.query.filter_by(name=role_name).first()
        if role:
            already = UserRole.query.filter_by(
                user_id=req.requester_id, role_id=role.id, status="Active"
            ).first()
            if not already:
                ur = UserRole(
                    user_id=req.requester_id,
                    role_id=role.id,
                    assigned_by=current_user.id,
                    status="Active",
                )
                db.session.add(ur)
                provisioned_role = role.name

    db.session.commit()

    details = f"{current_user.name} approved request #{req.id} ({req.resource_requested})"
    if provisioned_role:
        details += f" — {provisioned_role} role auto-provisioned"

    write_audit_log(
        actor_id=current_user.id,
        action="REQUEST_ADMIN_APPROVED",
        target_type="AccessRequest",
        target_id=req.id,
        details=details,
        ip_address=request.remote_addr,
    )
    if provisioned_role:
        write_audit_log(
            actor_id=current_user.id,
            action="ACCESS_PROVISIONED",
            target_type="User",
            target_id=req.requester_id,
            details=f"{provisioned_role} role provisioned for {req.requester.name} via request #{req.id}",
            ip_address=request.remote_addr,
        )

    flash(
        f"Request approved and access provisioned"
        + (f" ({provisioned_role} role granted)." if provisioned_role else "."),
        "success",
    )
    return redirect(url_for("admin.request_queue"))


@admin_bp.route("/requests/<int:req_id>/reject", methods=["POST"])
@login_required
@role_required("Admin")
def reject_request(req_id):
    req = AccessRequest.query.filter_by(id=req_id, stage="admin_review").first()
    if not req:
        flash("Request not found or already actioned.", "warning")
        return redirect(url_for("admin.request_queue"))

    comments = request.form.get("comments", "").strip()
    if not comments:
        flash("Please provide a reason for rejection.", "danger")
        return redirect(url_for("admin.request_detail", req_id=req_id))

    req.admin_id        = current_user.id
    req.admin_decision  = "Rejected"
    req.admin_comments  = comments
    req.admin_action_at = datetime.utcnow()
    req.status          = "Rejected"
    req.stage           = "rejected"
    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="REQUEST_ADMIN_REJECTED",
        target_type="AccessRequest",
        target_id=req.id,
        details=f"{current_user.name} rejected request #{req.id} ({req.resource_requested}): {comments}",
        ip_address=request.remote_addr,
    )

    flash("Request rejected.", "warning")
    return redirect(url_for("admin.request_queue"))


# ── SoD Rules Management ───────────────────────────────────────────────────────

@admin_bp.route("/sod")
@login_required
@role_required("Admin")
def sod_rules():
    rules = SodRule.query.order_by(SodRule.created_at.desc()).all()
    all_roles = Role.query.order_by(Role.name).all()
    return render_template("admin/sod_rules.html", rules=rules, all_roles=all_roles)


@admin_bp.route("/sod/add", methods=["POST"])
@login_required
@role_required("Admin")
def sod_add():
    role_id_1   = request.form.get("role_id_1", type=int)
    role_id_2   = request.form.get("role_id_2", type=int)
    description = request.form.get("description", "").strip()

    if not role_id_1 or not role_id_2 or role_id_1 == role_id_2:
        flash("Select two different roles.", "danger")
        return redirect(url_for("admin.sod_rules"))

    existing = SodRule.query.filter(
        db.or_(
            db.and_(SodRule.role_id_1 == role_id_1, SodRule.role_id_2 == role_id_2),
            db.and_(SodRule.role_id_1 == role_id_2, SodRule.role_id_2 == role_id_1),
        )
    ).first()
    if existing:
        flash("A SoD rule for these two roles already exists.", "warning")
        return redirect(url_for("admin.sod_rules"))

    rule = SodRule(
        role_id_1=role_id_1,
        role_id_2=role_id_2,
        description=description or "These roles must not be held by the same user.",
        created_by=current_user.id,
    )
    db.session.add(rule)
    db.session.commit()

    r1 = db.session.get(Role, role_id_1)
    r2 = db.session.get(Role, role_id_2)
    write_audit_log(
        actor_id=current_user.id,
        action="SOD_RULE_CREATED",
        target_type="SodRule",
        target_id=rule.id,
        details=f"SoD rule created: {r1.name} ↔ {r2.name} — {rule.description}",
        ip_address=request.remote_addr,
    )
    flash(f"SoD rule added: {r1.name} ↔ {r2.name}", "success")
    return redirect(url_for("admin.sod_rules"))


@admin_bp.route("/sod/delete/<int:rule_id>", methods=["POST"])
@login_required
@role_required("Admin")
def sod_delete(rule_id):
    rule = db.session.get(SodRule, rule_id)
    if not rule:
        flash("SoD rule not found.", "danger")
        return redirect(url_for("admin.sod_rules"))

    summary = f"{rule.role_1.name} ↔ {rule.role_2.name}"
    db.session.delete(rule)
    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="SOD_RULE_DELETED",
        target_type="SodRule",
        target_id=rule_id,
        details=f"SoD rule deleted: {summary}",
        ip_address=request.remote_addr,
    )
    flash(f"SoD rule deleted: {summary}", "warning")
    return redirect(url_for("admin.sod_rules"))
