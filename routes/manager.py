from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from auth import role_required
from models import db, User, AccessRequest, Role, write_audit_log

manager_bp = Blueprint("manager", __name__)


@manager_bp.route("/dashboard")
@login_required
@role_required("Manager")
def dashboard():
    pending_requests = (
        AccessRequest.query
        .filter_by(manager_id=current_user.id, stage="manager_review")
        .order_by(AccessRequest.created_at.desc())
        .all()
    )
    team = User.query.filter_by(manager_id=current_user.id).all()

    return render_template(
        "dashboard/manager.html",
        pending_requests=pending_requests,
        team=team,
    )


@manager_bp.route("/requests")
@login_required
@role_required("Manager")
def request_queue():
    # All requests this manager needs to act on
    pending = (
        AccessRequest.query
        .filter_by(manager_id=current_user.id, stage="manager_review")
        .order_by(AccessRequest.created_at.desc())
        .all()
    )
    # History: requests this manager already decided on
    history = (
        AccessRequest.query
        .filter(
            AccessRequest.manager_id == current_user.id,
            AccessRequest.stage.in_(["admin_review", "provisioned", "rejected"]),
        )
        .order_by(AccessRequest.created_at.desc())
        .limit(20)
        .all()
    )
    return render_template("requests/manager_queue.html", pending=pending, history=history)


@manager_bp.route("/requests/<int:req_id>")
@login_required
@role_required("Manager")
def request_detail(req_id):
    req = AccessRequest.query.filter_by(id=req_id, manager_id=current_user.id).first()
    if not req:
        flash("Request not found.", "danger")
        return redirect(url_for("manager.request_queue"))
    from routes.employee import REQUESTABLE_RESOURCES
    role_name = REQUESTABLE_RESOURCES.get(req.resource_requested)
    resource_role = Role.query.filter_by(name=role_name).first() if role_name else None
    return render_template("requests/detail.html", req=req, viewer="manager",
                           resource_role=resource_role)


@manager_bp.route("/requests/<int:req_id>/approve", methods=["POST"])
@login_required
@role_required("Manager")
def approve_request(req_id):
    req = AccessRequest.query.filter_by(
        id=req_id, manager_id=current_user.id, stage="manager_review"
    ).first()

    if not req:
        flash("Request not found or already actioned.", "warning")
        return redirect(url_for("manager.request_queue"))

    comments = request.form.get("comments", "").strip()

    from datetime import datetime
    req.manager_decision   = "Approved"
    req.manager_comments   = comments
    req.manager_action_at  = datetime.utcnow()
    req.status             = "Manager Approved"
    req.stage              = "admin_review"
    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="REQUEST_MANAGER_APPROVED",
        target_type="AccessRequest",
        target_id=req.id,
        details=f"{current_user.name} approved request #{req.id} ({req.resource_requested}) — forwarded to Admin",
        ip_address=request.remote_addr,
    )

    flash(f"Request approved and forwarded to Admin for final sign-off.", "success")
    return redirect(url_for("manager.request_queue"))


@manager_bp.route("/requests/<int:req_id>/reject", methods=["POST"])
@login_required
@role_required("Manager")
def reject_request(req_id):
    req = AccessRequest.query.filter_by(
        id=req_id, manager_id=current_user.id, stage="manager_review"
    ).first()

    if not req:
        flash("Request not found or already actioned.", "warning")
        return redirect(url_for("manager.request_queue"))

    comments = request.form.get("comments", "").strip()
    if not comments:
        flash("Please provide a reason for rejection.", "danger")
        return redirect(url_for("manager.request_detail", req_id=req_id))

    from datetime import datetime
    req.manager_decision   = "Rejected"
    req.manager_comments   = comments
    req.manager_action_at  = datetime.utcnow()
    req.status             = "Rejected"
    req.stage              = "rejected"
    db.session.commit()

    write_audit_log(
        actor_id=current_user.id,
        action="REQUEST_MANAGER_REJECTED",
        target_type="AccessRequest",
        target_id=req.id,
        details=f"{current_user.name} rejected request #{req.id} ({req.resource_requested}): {comments}",
        ip_address=request.remote_addr,
    )

    flash("Request rejected.", "warning")
    return redirect(url_for("manager.request_queue"))
