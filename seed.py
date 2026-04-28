from sqlalchemy.orm import Session

from auth_methods import hash_password
from models import Role, User


def _get_or_create_role(
    db: Session,
    name: str,
    description: str,
    level: int,
):
    role = db.query(Role).filter(Role.name == name).first()
    if not role:
        role = Role(name=name)
        db.add(role)
        db.flush()

    role.description = description
    role.level = level
    return role


def seed_roles(db: Session):
    roles = {
        "student": _get_or_create_role(db, "student", "Студент", 1),
        "teacher": _get_or_create_role(db, "teacher", "Преподаватель", 2),
        "dean_office": _get_or_create_role(db, "dean_office", "Сотрудник деканата", 3),
        "admin": _get_or_create_role(db, "admin", "Администратор", 4),
    }
    db.commit()
    return roles


def seed_users(db: Session, roles: dict[str, Role]):
    clearance_map = {"student": 1, "teacher": 2, "dean_office": 3, "admin": 4}
    users_data = [
        ("admin", "admin123", "Администратор системы", "admin"),
        ("student", "student123", "Студент", "student"),
        ("teacher", "teacher123", "Преподаватель", "teacher"),
        ("dean", "dean123", "Сотрудник деканата", "dean_office"),
    ]

    for username, password, full_name, role_name in users_data:
        role = roles[role_name]
        user = db.query(User).filter(User.username == username).first()

        if not user:
            user = User(username=username)
            db.add(user)

        user.password_hash = hash_password(password)
        user.full_name = full_name
        user.is_active = True
        user.clearance_level = clearance_map[role_name]
        user.secret_key = 100
        user.primary_role = role
        user.roles = [role]

    db.commit()


def seed_data(db: Session):
    roles = seed_roles(db)
    seed_users(db, roles)
