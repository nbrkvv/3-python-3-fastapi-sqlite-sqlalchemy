from sqlalchemy.orm import Session

from auth_methods import hash_password
from models import (
    Attestation,
    Department,
    Discipline,
    Group,
    Role,
    Schedule,
    Student,
    Teacher,
    User,
)


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
        "management": _get_or_create_role(db, "management", "Руководство", 3),
        "admin": _get_or_create_role(db, "admin", "Администратор", 4),
    }
    db.commit()
    return roles


def seed_users(db: Session, roles: dict[str, Role]):
    clearance_map = {"student": 1, "teacher": 2, "dean_office": 3, "management": 3, "admin": 4}
    users_data = [
        ("admin", "admin123", "Администратор системы", "admin"),
        ("student", "student123", "Иван Петров", "student"),
        ("student2", "student123", "Мария Сидорова", "student"),
        ("student3", "student123", "Петр Иванов", "student"),
        ("teacher", "teacher123", "Профессор Смирнов", "teacher"),
        ("teacher2", "teacher123", "Доцент Кузнецов", "teacher"),
        ("dean", "dean123", "Сотрудник деканата", "dean_office"),
        ("management", "manage123", "Руководитель", "management"),
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


def seed_departments(db: Session):
    depts_data = [
        ("Информационные технологии", "Кафедра ИТ"),
        ("Математика", "Кафедра математики"),
        ("Физика", "Кафедра физики"),
    ]

    for name, desc in depts_data:
        if not db.query(Department).filter(Department.name == name).first():
            dept = Department(name=name, description=desc)
            db.add(dept)

    db.commit()


def seed_teachers(db: Session):
    depts = db.query(Department).all()
    if not depts:
        return

    teachers_data = [
        ("Иван Смирнов", "ivan.smirnov@university.ru", depts[0]),
        ("Мария Петрова", "maria.petrova@university.ru", depts[0]),
        ("Петр Кузнецов", "petr.kuznetsov@university.ru", depts[1]),
        ("Анна Волкова", "anna.volkova@university.ru", depts[1]),
        ("Сергей Соколов", "sergey.sokolov@university.ru", depts[2]),
    ]

    for full_name, email, dept in teachers_data:
        if not db.query(Teacher).filter(Teacher.email == email).first():
            teacher = Teacher(full_name=full_name, email=email, department=dept)
            db.add(teacher)

    db.commit()


def seed_disciplines(db: Session):
    disciplines_data = [
        ("Программирование на Python", "Основы программирования на Python", 3),
        ("Базы данных", "Проектирование и администрирование БД", 4),
        ("Веб-разработка", "Создание веб-приложений", 3),
        ("Математический анализ", "Дифференциальное и интегральное исчисление", 4),
        ("Линейная алгебра", "Основы линейной алгебры", 3),
        ("Физика", "Общая физика", 4),
        ("Ядерная физика", "Основы ядерной физики", 3),
        ("Механика", "Классическая механика", 3),
    ]

    for name, desc, credits in disciplines_data:
        if not db.query(Discipline).filter(Discipline.name == name).first():
            disc = Discipline(name=name, description=desc, credits=credits)
            db.add(disc)

    db.commit()


def seed_groups(db: Session):
    groups_data = [
        ("ПИ-101", "Первая группа направления программная инженерия"),
        ("ПИ-102", "Вторая группа направления программная инженерия"),
        ("МА-201", "Первая группа направления математика и анализ"),
    ]

    for name, desc in groups_data:
        if not db.query(Group).filter(Group.name == name).first():
            group = Group(name=name, description=desc)
            db.add(group)

    db.commit()


def seed_students(db: Session):
    groups = db.query(Group).all()
    if not groups:
        return

    students_data = [
        ("Иван Петров", "ivan.petrov@student.ru", groups[0]),
        ("Мария Сидорова", "maria.sidorova@student.ru", groups[0]),
        ("Петр Иванов", "petr.ivanov@student.ru", groups[0]),
        ("Елена Смирнова", "elena.smirnova@student.ru", groups[0]),
        ("Анна Кузнецова", "anna.kuznetsova@student.ru", groups[0]),
        ("Максим Волков", "maxim.volkov@student.ru", groups[1]),
        ("Ольга Соколова", "olga.sokolova@student.ru", groups[1]),
        ("Дмитрий Морозов", "dmitry.morozov@student.ru", groups[1]),
        ("Наталья Лебедева", "natalia.lebedeva@student.ru", groups[1]),
        ("Алексей Орлов", "alexey.orlov@student.ru", groups[2]),
        ("Виктория Павлова", "victoria.pavlova@student.ru", groups[2]),
        ("Константин Антонов", "konstantin.antonov@student.ru", groups[2]),
        ("Яна Герасимова", "yana.gerasimova@student.ru", groups[2]),
        ("Сергей Львов", "sergey.lvov@student.ru", groups[2]),
        ("Ирина Зайцева", "irina.zaitseva@student.ru", groups[2]),
    ]

    for full_name, email, group in students_data:
        if not db.query(Student).filter(Student.email == email).first():
            student = Student(full_name=full_name, email=email, group=group)
            db.add(student)

    db.commit()


def seed_group_disciplines(db: Session):
    groups = db.query(Group).all()
    disciplines = db.query(Discipline).all()

    if not groups or not disciplines:
        return

    group_disc_map = {
        groups[0].id: [disciplines[0], disciplines[1], disciplines[2]],
        groups[1].id: [disciplines[0], disciplines[1]],
        groups[2].id: [disciplines[3], disciplines[4]],
    }

    for group_id, discs in group_disc_map.items():
        group = db.query(Group).filter(Group.id == group_id).first()
        for disc in discs:
            if disc not in group.disciplines:
                group.disciplines.append(disc)

    db.commit()


def seed_teacher_disciplines(db: Session):
    teachers = db.query(Teacher).all()
    disciplines = db.query(Discipline).all()

    if not teachers or not disciplines:
        return

    teacher_disc_map = {
        teachers[0].id: [disciplines[0], disciplines[1]],
        teachers[1].id: [disciplines[2]],
        teachers[2].id: [disciplines[3], disciplines[4]],
        teachers[3].id: [disciplines[3]],
        teachers[4].id: [disciplines[5], disciplines[6]],
    }

    for teacher_id, discs in teacher_disc_map.items():
        teacher = db.query(Teacher).filter(Teacher.id == teacher_id).first()
        for disc in discs:
            if disc not in teacher.disciplines:
                teacher.disciplines.append(disc)

    db.commit()


def seed_schedules(db: Session):
    groups = db.query(Group).all()
    if not groups:
        return

    schedules_data = [
        (groups[0], "Программирование на Python", "Иван Смирнов", "Понедельник", "09:00", "10:30", "101"),
        (groups[0], "Базы данных", "Мария Петрова", "Вторник", "11:00", "12:30", "102"),
        (groups[0], "Веб-разработка", "Иван Смирнов", "Среда", "14:00", "15:30", "103"),
        (groups[1], "Программирование на Python", "Мария Петрова", "Четверг", "09:00", "10:30", "104"),
        (groups[1], "Базы данных", "Иван Смирнов", "Пятница", "11:00", "12:30", "105"),
        (groups[2], "Математический анализ", "Петр Кузнецов", "Понедельник", "10:00", "11:30", "201"),
        (groups[2], "Линейная алгебра", "Анна Волкова", "Среда", "14:00", "15:30", "202"),
    ]

    from models import Discipline, Teacher

    for group, disc_name, teacher_name, day, time_start, time_end, room in schedules_data:
        disc = db.query(Discipline).filter(Discipline.name == disc_name).first()
        teacher = db.query(Teacher).filter(Teacher.full_name == teacher_name).first()

        if disc and teacher:
            existing = (
                db.query(Schedule)
                .filter(
                    Schedule.group_id == group.id,
                    Schedule.discipline_id == disc.id,
                    Schedule.day_of_week == day,
                )
                .first()
            )
            if not existing:
                schedule = Schedule(
                    group=group,
                    discipline=disc,
                    teacher=teacher,
                    day_of_week=day,
                    time_start=time_start,
                    time_end=time_end,
                    classroom=room,
                )
                db.add(schedule)

    db.commit()


def seed_attestations(db: Session):
    students = db.query(Student).all()
    disciplines = db.query(Discipline).all()
    teachers = db.query(Teacher).all()

    if not students or not disciplines or not teachers:
        return

    attestations_data = [
        (students[0], disciplines[0], teachers[0], "exam", 4.0, "2026-05-15", "completed"),
        (students[0], disciplines[1], teachers[1], "exam", 3.5, "2026-05-18", "completed"),
        (students[0], disciplines[2], teachers[0], "credit", 5.0, "2026-05-20", "completed"),
        (students[1], disciplines[0], teachers[0], "exam", 5.0, "2026-05-15", "completed"),
        (students[1], disciplines[1], teachers[1], "exam", 4.5, "2026-05-18", "completed"),
        (students[2], disciplines[0], teachers[0], "exam", 3.0, "2026-05-15", "completed"),
        (students[2], disciplines[2], teachers[0], "exam", 2.5, "2026-05-20", "completed"),
        (students[3], disciplines[1], teachers[1], "credit", 4.0, "2026-05-18", "completed"),
        (students[4], disciplines[0], teachers[0], "exam", 4.5, "2026-05-15", "completed"),
        (students[5], disciplines[0], teachers[0], "exam", 3.5, "2026-05-15", "completed"),
    ]

    for student, disc, teacher, att_type, grade, date, status in attestations_data:
        existing = (
            db.query(Attestation)
            .filter(
                Attestation.student_id == student.id,
                Attestation.discipline_id == disc.id,
                Attestation.attestation_type == att_type,
            )
            .first()
        )
        if not existing:
            attestation = Attestation(
                student=student,
                group=student.group,
                discipline=disc,
                teacher=teacher,
                attestation_type=att_type,
                grade=grade,
                date=date,
                status=status,
            )
            db.add(attestation)

    db.commit()


def seed_data(db: Session):
    roles = seed_roles(db)
    seed_users(db, roles)
    seed_departments(db)
    seed_teachers(db)
    seed_disciplines(db)
    seed_groups(db)
    seed_students(db)
    seed_group_disciplines(db)
    seed_teacher_disciplines(db)
    seed_schedules(db)
    seed_attestations(db)
