"""
Run this once to populate the database with demo users and roles.
Usage: python seed.py
"""
from app import create_app
from models import db, User, Role, UserRole, SodRule, write_audit_log
from datetime import datetime, timedelta


def seed():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        # --- Roles (with data classification) ---
        roles = [
            Role(name="HR",       description="Access to HR systems and employee records",
                 classification="Confidential"),
            Role(name="Finance",  description="Access to financial systems and reports",
                 classification="Restricted"),
            Role(name="IT",       description="Access to IT infrastructure and tooling",
                 classification="Internal"),
            Role(name="Security", description="Access to security tools and audit systems",
                 classification="Restricted"),
        ]
        db.session.add_all(roles)
        db.session.commit()

        hr_role       = Role.query.filter_by(name="HR").first()
        finance_role  = Role.query.filter_by(name="Finance").first()
        it_role       = Role.query.filter_by(name="IT").first()
        security_role = Role.query.filter_by(name="Security").first()

        # --- Users ---
        admin = User(
            name="Admin User",
            email="admin@iam.lab",
            department="IT",
            system_role="Admin",
            status="Active",
        )
        admin.set_password("Password123!")

        manager = User(
            name="Sarah Manager",
            email="manager@iam.lab",
            department="Finance",
            system_role="Manager",
            status="Active",
        )
        manager.set_password("Password123!")

        employee1 = User(
            name="John Employee",
            email="employee@iam.lab",
            department="Finance",
            system_role="Employee",
            status="Active",
        )
        employee1.set_password("Password123!")

        employee2 = User(
            name="Ravi Kumar",
            email="ravi@iam.lab",
            department="HR",
            system_role="Employee",
            status="Active",
        )
        employee2.set_password("Password123!")

        # Inactive user — used to demo orphan account detection
        inactive_user = User(
            name="Left Company",
            email="leftco@iam.lab",
            department="IT",
            system_role="Employee",
            status="Inactive",
        )
        inactive_user.set_password("Password123!")

        db.session.add_all([admin, manager, employee1, employee2, inactive_user])
        db.session.commit()

        # Assign manager to employees
        employee1.manager_id = manager.id
        employee2.manager_id = manager.id
        inactive_user.manager_id = manager.id
        db.session.commit()

        # --- Role Assignments ---
        now = datetime.utcnow()

        assignments = [
            UserRole(user_id=employee1.id, role_id=finance_role.id, assigned_by=admin.id,
                     assigned_at=now, expires_at=now + timedelta(days=90), status="Active"),
            UserRole(user_id=employee2.id, role_id=hr_role.id, assigned_by=admin.id,
                     assigned_at=now, expires_at=now + timedelta(days=90), status="Active"),
            UserRole(user_id=admin.id, role_id=security_role.id, assigned_by=admin.id,
                     assigned_at=now, status="Active"),
            # Orphan: inactive user still has an active role
            UserRole(user_id=inactive_user.id, role_id=it_role.id, assigned_by=admin.id,
                     assigned_at=now - timedelta(days=30), status="Active"),
        ]
        db.session.add_all(assignments)
        db.session.commit()

        # --- SoD Rules ---
        sod_rules = [
            SodRule(
                role_id_1=finance_role.id,
                role_id_2=security_role.id,
                description="Finance and Security access must be separate — "
                            "combined access could allow financial fraud to be concealed from audit tools.",
                created_by=admin.id,
            ),
            SodRule(
                role_id_1=finance_role.id,
                role_id_2=hr_role.id,
                description="Finance and HR access must be separate — "
                            "combined access enables unauthorised manipulation of payroll and compensation data.",
                created_by=admin.id,
            ),
        ]
        db.session.add_all(sod_rules)
        db.session.commit()

        # Seed audit log entries
        write_audit_log(admin.id, "USER_CREATED", "User", admin.id, f"Admin account created: {admin.email}")
        write_audit_log(admin.id, "USER_CREATED", "User", manager.id, f"Manager account created: {manager.email}")
        write_audit_log(admin.id, "USER_CREATED", "User", employee1.id, f"Employee account created: {employee1.email}")
        write_audit_log(admin.id, "USER_CREATED", "User", employee2.id, f"Employee account created: {employee2.email}")
        write_audit_log(admin.id, "USER_DEACTIVATED", "User", inactive_user.id, f"Account deactivated: {inactive_user.email}")
        write_audit_log(admin.id, "ROLE_ASSIGNED", "UserRole", employee1.id, f"Finance role assigned to {employee1.name}")
        write_audit_log(admin.id, "ROLE_ASSIGNED", "UserRole", employee2.id, f"HR role assigned to {employee2.name}")

        print("Database seeded successfully.")
        print()
        print("Demo accounts:")
        print("  admin@iam.lab     / Password123!  [Admin]")
        print("  manager@iam.lab   / Password123!  [Manager]")
        print("  employee@iam.lab  / Password123!  [Employee]")
        print("  ravi@iam.lab      / Password123!  [Employee]")
        print()
        print("Orphan account demo: leftco@iam.lab (Inactive, still has IT role)")
        print()
        print("SoD rules seeded:")
        print("  Finance <-> Security (fraud masking prevention)")
        print("  Finance <-> HR      (payroll manipulation prevention)")


if __name__ == "__main__":
    seed()
