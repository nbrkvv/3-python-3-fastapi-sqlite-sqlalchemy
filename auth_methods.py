import random
from datetime import datetime

from passlib.context import CryptContext
from sqlalchemy.orm import Session

from models import OTPCode, User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def normalize_answer(answer: str) -> str:
    return answer.strip().lower()


def verify_persistent_password(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None, False, "Пользователь не найден."
    if not user.is_active:
        return user, False, "Пользователь деактивирован."
    if not verify_password(password, user.password_hash):
        return user, False, "Неверный пароль."
    return user, True, "Аутентификация по постоянному паролю успешна."


def get_next_otp(db: Session, user: User):
    return (
        db.query(OTPCode)
        .filter(OTPCode.user_id == user.id, OTPCode.is_used.is_(False))
        .order_by(OTPCode.sequence_number.asc())
        .first()
    )


def verify_one_time_password(db: Session, user: User, provided_code: str):
    next_otp = get_next_otp(db, user)
    if not next_otp:
        return False, "У пользователя закончился список одноразовых паролей."

    if next_otp.code != provided_code.strip():
        return False, f"Неверный OTP. Требуется пароль с номером {next_otp.sequence_number}."

    next_otp.is_used = True
    next_otp.used_at = datetime.utcnow()
    db.commit()
    return True, f"Одноразовый пароль №{next_otp.sequence_number} принят."


def verify_question_answer(user: User, answer: str):
    if not user.secret_question or not user.secret_answer_hash:
        return False, "Для пользователя не настроен метод вопрос-ответ."
    if verify_password(normalize_answer(answer), user.secret_answer_hash):
        return True, "Ответ верный. Метод вопрос-ответ пройден."
    return False, "Ответ неверный."


def generate_function_challenge() -> int:
    return random.randint(10, 99)


def functional_transform(x: int) -> int:
    return x * 2 + 7


def verify_functional_answer(x: int, provided_answer: str):
    try:
        answer = int(provided_answer)
    except ValueError:
        return False, "Ответ должен быть целым числом."

    expected = functional_transform(x)
    if answer == expected:
        return True, "Функциональное преобразование выполнено верно."
    return False, f"Неверно. Для x={x} ожидается y={expected}."


def generate_handshake_challenge() -> int:
    return random.randint(0, 999)


def handshake_transform(x: int, secret_key: int) -> int:
    return (x + secret_key) % 1000


def verify_handshake_answer(user: User, x: int, provided_answer: str):
    try:
        answer = int(provided_answer)
    except ValueError:
        return False, "Ответ должен быть целым числом."

    expected = handshake_transform(x, user.secret_key)
    if answer == expected:
        return True, "Рукопожатие выполнено успешно."
    return False, f"Неверно. Для x={x} ожидается y={expected}."
