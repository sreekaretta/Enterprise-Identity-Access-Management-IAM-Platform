from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from auth import role_required
from models import db, AccessRequest, UserRole, User, Role, write_audit_log
from policy import CLASSIFICATION_BADGE, MIN_JUSTIFICATION_LEN

employee_bp = Blueprint("employee", __name__)

# Resources employees can request — maps display name to the Role name for auto-provisioning
REQUESTABLE_RESOURCES = {
    "Finance Application":  "Finance",
    "HR Portal":            "HR",
    "IT Systems Access":    "IT",
    "Security Tools":       "Security",
}


@employee_bp.route("/dashboard")
@login_required
@role_required("Employee")
def dashboard():
    my_requests = (
        AccessRequest.query
        .filter_by(requester_id=current_user.id)
        .order_by(AccessRequest.created_at.desc())
        .all()
    )
    my_roles = UserRole.query.filter_by(user_id=current_user.id, status="Active").all()

    return render_template(
        "dashboard/employee.html",
        my_requests=my_requests,
        my_roles=my_roles,
    )


@employee_bp.route("/requests")
@login_required
@role_required("Employee")
def my_requests():
    requests = (
        AccessRequest.query
        .filter_by(requester_id=current_user.id)
        .order_by(AccessRequest.created_at.desc())
        .all()
    )
    return render_template("requests/employee_list.html", requests=requests)


def _build_resources_info():
    """Return enriched resource dict with classification data for templates."""
    info = {}
    for resource, role_name in REQUESTABLE_RESOURCES.items():
        role = Role.query.filter_by(name=role_name).first()
        info[resource] = {
            "role_name": role_name,
            "classification": role.classification if role else "Internal",
            "badge": CLASSIFICATION_BADGE.get(role.classification if role else "Internal", "bg-secondary"),
        }
    return info


@employee_bp.route("/requests/new", methods=["GET", "POST"])
@login_required
@role_required("Employee")
def new_request():
    resources_info = _build_resources_info()

    if request.method == "POST":
        resource = request.form.get("resource", "").strip()
        reason   = request.form.get("reason", "").strip()

        if not resource or resource not in REQUESTABLE_RESOURCES:
            flash("Please select a valid resource.", "danger")
            return render_template("requests/new.html",
                                   resources=REQUESTABLE_RESOURCES, resources_info=resources_info)

        if len(reason) < MIN_JUSTIFICATION_LEN:
            flash(
                f"Business justification must be at least {MIN_JUSTIFICATION_LEN} characters. "
                "Describe specifically why you need this access and how you will use it.",
                "danger",
            )
            return render_template("requests/new.html",
                                   resources=REQUESTABLE_RESOURCES, resources_info=resources_info)

        # Check if a pending or approved request already exists for this resource
        existing = AccessRequest.query.filter(
            AccessRequest.requester_id == current_user.id,
            AccessRequest.resource_requested == resource,
            AccessRequest.stage.in_(["manager_review", "admin_review"]),
        ).first()
        if existing:
            flash(f"You already have a pending request for {resource}.", "warning")
            return redirect(url_for("employee.my_requests"))

        # Route to the employee's manager; fall back to any admin if no manager set
        manager = current_user.manager
        if not manager:
            manager = User.query.filter_by(system_role="Admin", status="Active").first()

        req = AccessRequest(
            requester_id=current_user.id,
            resource_requested=resource,
            reason=reason,
            status="Pending",
            stage="manager_review",
            manager_id=manager.id if manager else None,
        )
        db.session.add(req)
        db.session.commit()

        write_audit_log(
            actor_id=current_user.id,
            action="REQUEST_SUBMITTED",
            target_type="AccessRequest",
            target_id=req.id,
            details=f"{current_user.name} requested access to: {resource}",
            ip_address=request.remote_addr,
        )

        flash(f"Access request for '{resource}' submitted. Awaiting manager approval.", "success")
        return redirect(url_for("employee.my_requests"))

    return render_template("requests/new.html",
                           resources=REQUESTABLE_RESOURCES, resources_info=resources_info)


@employee_bp.route("/requests/<int:req_id>")
@login_required
@role_required("Employee")
def request_detail(req_id):
    req = AccessRequest.query.filter_by(id=req_id, requester_id=current_user.id).first()
    if not req:
        flash("Request not found.", "danger")
        return redirect(url_for("employee.my_requests"))
    role_name = REQUESTABLE_RESOURCES.get(req.resource_requested)
    resource_role = Role.query.filter_by(name=role_name).first() if role_name else None
    return render_template("requests/detail.html", req=req, viewer="employee",
                           resource_role=resource_role)
