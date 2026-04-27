from collections import defaultdict

from sqlalchemy.orm import Session

from models import ProtectedObject, Role, RolePermission, User

MAX_ROLES_PER_USER = 3
MAX_ACTIVE_ROLES = 2
ALL_OPERATIONS = ("read", "create", "update", "delete")


def _collect_role_with_ancestors(role: Role | None, bucket: dict[int, Role]):
    if not role:
        return
    if role.id in bucket:
        return
    bucket[role.id] = role
    _collect_role_with_ancestors(role.parent, bucket)


def get_user_assigned_roles(user: User):
    roles = {}
    if user.primary_role:
        roles[user.primary_role.id] = user.primary_role
    for role in user.roles:
        roles[role.id] = role
    return list(roles.values())


def get_effective_roles(user: User, active_role_ids: list[int] | None = None):
    assigned = get_user_assigned_roles(user)
    assigned_map = {role.id: role for role in assigned}

    if active_role_ids:
        chosen = [assigned_map[rid] for rid in active_role_ids if rid in assigned_map]
    else:
        chosen = assigned

    result = {}
    for role in chosen:
        _collect_role_with_ancestors(role, result)
    return list(result.values())


def get_role_names(roles: list[Role]):
    return sorted({role.name for role in roles})


def assign_role_with_limit(user: User, role: Role):
    assigned = get_user_assigned_roles(user)
    assigned_ids = {r.id for r in assigned}

    if role.id in assigned_ids:
        return False, "Роль уже назначена пользователю."
    if len(assigned_ids) >= MAX_ROLES_PER_USER:
        return False, f"Превышен лимит ролей для пользователя ({MAX_ROLES_PER_USER})."

    user.roles.append(role)
    return True, "Роль добавлена пользователю."


def remove_role(user: User, role: Role):
    if user.primary_role_id == role.id:
        return False, "Нельзя удалить первичную роль через эту операцию. Сначала смените primary role."
    user.roles = [r for r in user.roles if r.id != role.id]
    return True, "Роль удалена."


def activate_roles_for_session(user: User, requested_role_ids: list[int]):
    assigned_ids = {role.id for role in get_user_assigned_roles(user)}
    valid_ids = [rid for rid in requested_role_ids if rid in assigned_ids]

    if not valid_ids:
        return [], "Нужно выбрать хотя бы одну назначенную роль."
    if len(valid_ids) > MAX_ACTIVE_ROLES:
        return [], f"Можно активировать не более {MAX_ACTIVE_ROLES} ролей в одной сессии."
    return valid_ids, "Активные роли обновлены."


def get_effective_permissions(
    db: Session, user: User, active_role_ids: list[int] | None = None
) -> dict[str, set[str]]:
    effective_roles = get_effective_roles(user, active_role_ids)
    role_ids = [r.id for r in effective_roles]
    permission_map = defaultdict(set)

    if not role_ids:
        return permission_map

    rows = (
        db.query(RolePermission, ProtectedObject)
        .join(ProtectedObject, RolePermission.object_id == ProtectedObject.id)
        .filter(RolePermission.role_id.in_(role_ids), RolePermission.allow.is_(True))
        .all()
    )
    for perm, obj in rows:
        permission_map[obj.name].add(perm.operation)

    return permission_map


def can_access_rbac(
    db: Session,
    user: User,
    object_name: str,
    operation: str,
    active_role_ids: list[int] | None = None,
):
    permissions = get_effective_permissions(db, user, active_role_ids)
    allowed_ops = permissions.get(object_name, set())
    if operation in allowed_ops:
        return True, f"RBAC разрешил операцию: {operation} для {object_name}."
    return False, f"RBAC запретил: у активных ролей нет права {operation} для {object_name}."


def inheritance_chain(role: Role):
    chain = []
    cursor = role
    while cursor:
        chain.append(cursor.name)
        cursor = cursor.parent
    return chain
