from dataclasses import dataclass

from sqlalchemy.orm import Session

from models import ACLEntry, Capability, ProtectedObject, RolePermission, User
from rbac import get_effective_roles

READ_OPERATIONS = {"read"}
WRITE_OPERATIONS = {"create", "update", "delete"}


@dataclass
class AuthorizationResult:
    allowed: bool
    reason: str


def _get_object(db: Session, object_name: str):
    return db.query(ProtectedObject).filter(ProtectedObject.name == object_name).first()


def check_matrix_access(db: Session, user: User, object_name: str, operation: str) -> AuthorizationResult:
    obj = _get_object(db, object_name)
    if not obj:
        return AuthorizationResult(False, "Объект не найден.")

    roles = get_effective_roles(user)
    role_ids = [role.id for role in roles]
    if not role_ids:
        return AuthorizationResult(False, "У пользователя нет ролей для проверки матрицы доступа.")

    allowed = (
        db.query(RolePermission)
        .filter(
            RolePermission.role_id.in_(role_ids),
            RolePermission.object_id == obj.id,
            RolePermission.operation == operation,
            RolePermission.allow.is_(True),
        )
        .first()
    )
    if allowed:
        return AuthorizationResult(True, "Матрица доступа: найдено разрешение для одной из ролей пользователя.")
    return AuthorizationResult(False, "Матрица доступа: разрешение отсутствует.")


def check_acl_access(db: Session, user: User, object_name: str, operation: str) -> AuthorizationResult:
    obj = _get_object(db, object_name)
    if not obj:
        return AuthorizationResult(False, "Объект не найден.")

    user_entry = (
        db.query(ACLEntry)
        .filter(ACLEntry.object_id == obj.id, ACLEntry.user_id == user.id, ACLEntry.operation == operation)
        .first()
    )
    if user_entry:
        if user_entry.allow:
            return AuthorizationResult(True, "ACL: явное пользовательское разрешение.")
        return AuthorizationResult(False, "ACL: явный пользовательский запрет.")

    role_ids = [role.id for role in get_effective_roles(user)]
    if role_ids:
        role_entry = (
            db.query(ACLEntry)
            .filter(
                ACLEntry.object_id == obj.id,
                ACLEntry.role_id.in_(role_ids),
                ACLEntry.operation == operation,
            )
            .first()
        )
        if role_entry:
            if role_entry.allow:
                return AuthorizationResult(True, "ACL: разрешение через роль.")
            return AuthorizationResult(False, "ACL: запрет через роль.")

    return AuthorizationResult(False, "ACL: подходящих записей не найдено.")


def check_capability_access(db: Session, user: User, object_name: str, operation: str) -> AuthorizationResult:
    obj = _get_object(db, object_name)
    if not obj:
        return AuthorizationResult(False, "Объект не найден.")

    capability = (
        db.query(Capability)
        .filter(
            Capability.user_id == user.id,
            Capability.object_id == obj.id,
            Capability.operation == operation,
            Capability.allow.is_(True),
        )
        .first()
    )
    if capability:
        return AuthorizationResult(True, "Capability list: у пользователя есть токен на операцию.")
    return AuthorizationResult(False, "Capability list: токен отсутствует.")


def check_lock_key_access(db: Session, user: User, object_name: str, operation: str) -> AuthorizationResult:
    obj = _get_object(db, object_name)
    if not obj:
        return AuthorizationResult(False, "Объект не найден.")

    if operation == "delete" and obj.name == "admin_panel":
        # Небольшой учебный пример дополнительного ограничения.
        pass

    keys = set()
    if user.key_value:
        keys.add(user.key_value)
    for role in get_effective_roles(user):
        if role.key_value:
            keys.add(role.key_value)

    if obj.lock_value in keys:
        return AuthorizationResult(True, f"Lock-Key: найден ключ {obj.lock_value}.")
    return AuthorizationResult(False, f"Lock-Key: ни один ключ пользователя не открывает lock={obj.lock_value}.")


def check_mandatory_access(db: Session, user: User, object_name: str, operation: str) -> AuthorizationResult:
    obj = _get_object(db, object_name)
    if not obj:
        return AuthorizationResult(False, "Объект не найден.")

    clearance = user.clearance_level
    secrecy = obj.secrecy_level

    if operation in READ_OPERATIONS:
        if clearance >= secrecy:
            return AuthorizationResult(
                True,
                f"Мандатная модель: read разрешён, т.к. clearance={clearance} >= secrecy={secrecy}.",
            )
        return AuthorizationResult(
            False,
            f"Мандатная модель: read запрещён, т.к. clearance={clearance} < secrecy={secrecy}.",
        )

    if operation in WRITE_OPERATIONS:
        if secrecy >= clearance:
            return AuthorizationResult(
                True,
                f"Мандатная модель: write разрешён, т.к. secrecy={secrecy} >= clearance={clearance}.",
            )
        return AuthorizationResult(
            False,
            f"Мандатная модель: write запрещён, т.к. secrecy={secrecy} < clearance={clearance}.",
        )

    return AuthorizationResult(False, "Неизвестная операция.")


def check_authorization(db: Session, method: str, user: User, object_name: str, operation: str):
    method_map = {
        "matrix": check_matrix_access,
        "acl": check_acl_access,
        "capability": check_capability_access,
        "lock_key": check_lock_key_access,
        "mandatory": check_mandatory_access,
    }
    checker = method_map.get(method)
    if not checker:
        return AuthorizationResult(False, "Неизвестный метод авторизации.")
    return checker(db, user, object_name, operation)
