from models import db, UserRole, SodRule, Role

CLASSIFICATION_LEVELS = {"Public": 0, "Internal": 1, "Confidential": 2, "Restricted": 3}

CLASSIFICATION_BADGE = {
    "Public":       "bg-success",
    "Internal":     "bg-secondary",
    "Confidential": "bg-warning text-dark",
    "Restricted":   "bg-danger",
}

MIN_JUSTIFICATION_LEN = 30


def check_sod(user_id, role_id, extra_role_ids=None):
    """Check SoD violations for adding role_id to a user.
    extra_role_ids: additional role IDs being assigned in the same batch (joiner/mover).
    Returns list of violation strings (empty = no violation).
    """
    active_role_ids = {
        ur.role_id for ur in UserRole.query.filter_by(user_id=user_id, status="Active").all()
    }
    if extra_role_ids:
        active_role_ids = (active_role_ids | set(extra_role_ids)) - {role_id}

    if not active_role_ids:
        return []

    violations = []
    rules = SodRule.query.filter(
        db.or_(
            db.and_(SodRule.role_id_1 == role_id, SodRule.role_id_2.in_(active_role_ids)),
            db.and_(SodRule.role_id_2 == role_id, SodRule.role_id_1.in_(active_role_ids)),
        )
    ).all()

    for rule in rules:
        conflicting_id = rule.role_id_2 if rule.role_id_1 == role_id else rule.role_id_1
        new_role = db.session.get(Role, role_id)
        conflicting = db.session.get(Role, conflicting_id)
        violations.append(
            f"SoD Conflict: '{new_role.name}' cannot be combined with '{conflicting.name}' — {rule.description}"
        )

    return violations


def check_sod_batch(role_ids):
    """Check SoD conflicts within a set of role IDs (for batch assignments like Joiner).
    Returns list of violation strings.
    """
    role_list = list(role_ids)
    violations = []
    seen = set()

    for i, r1_id in enumerate(role_list):
        for r2_id in role_list[i + 1:]:
            pair = tuple(sorted([r1_id, r2_id]))
            if pair in seen:
                continue
            seen.add(pair)
            rules = SodRule.query.filter(
                db.or_(
                    db.and_(SodRule.role_id_1 == r1_id, SodRule.role_id_2 == r2_id),
                    db.and_(SodRule.role_id_1 == r2_id, SodRule.role_id_2 == r1_id),
                )
            ).all()
            for rule in rules:
                r1 = db.session.get(Role, r1_id)
                r2 = db.session.get(Role, r2_id)
                violations.append(
                    f"SoD Conflict: '{r1.name}' and '{r2.name}' cannot both be assigned — {rule.description}"
                )

    return violations


def check_policy(user_id, role_id, justification=None):
    """Run all policy checks before granting access.
    Returns (passed: bool, violations: list[str], warnings: list[str])
      violations — hard blocks (SoD); provisioning must not proceed
      warnings   — soft flags (classification); provisioning may proceed with note
    """
    violations = check_sod(user_id, role_id)
    warnings = []

    role = db.session.get(Role, role_id)
    if role:
        level = CLASSIFICATION_LEVELS.get(role.classification or "Internal", 1)
        if level >= 3:  # Restricted
            if not justification or len(justification.strip()) < MIN_JUSTIFICATION_LEN:
                warnings.append(
                    f"'{role.name}' is classified Restricted. "
                    f"Ensure the business justification is detailed before provisioning."
                )

    return len(violations) == 0, violations, warnings
