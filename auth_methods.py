from passlib.context import CryptContext
from sqlalchemy.orm import Session

from models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def verify_persistent_password(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None, False, "Пользователь не найден."
    if not user.is_active:
        return user, False, "Пользователь деактивирован."
    if not verify_password(password, user.password_hash):
        return user, False, "Неверный пароль."
    return user, True, "Аутентификация по постоянному паролю успешна."
