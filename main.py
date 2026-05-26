from datetime import datetime
from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from auth_methods import hash_password, verify_persistent_password
from database import Base, SessionLocal, engine, get_db
from models import (
    ActionLog,
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
from seed import seed_data

SECTION_DEFINITIONS = {
    "academic-process": {
        "title": "Учебный процесс",
        "path": "/academic-process",
        "description": "Управление студентами, группами, дисциплинами и расписанием.",
    },
    "attestation": {
        "title": "Аттестация",
        "path": "/attestation",
        "description": "Ввод результатов аттестации и просмотр ведомостей.",
    },
    "academic-results": {
        "title": "Результаты обучения",
        "path": "/academic-results",
        "description": "Анализ результатов и задолженности студентов.",
    },
    "analytics": {
        "title": "Аналитика",
        "path": "/analytics",
        "description": "Отчеты и статистика по успеваемости.",
    },
    "references": {
        "title": "Справочники",
        "path": "/references",
        "description": "Управление студентами, группами, преподавателями, дисциплинами.",
    },
    "administration": {
        "title": "Администрирование",
        "path": "/administration",
        "description": "Управление пользователями и журнал действий.",
    },
    "schedule": {
        "title": "Расписание",
        "path": "/schedule",
        "description": "Просмотр расписания занятий.",
    },
    "my-grades": {
        "title": "Мои оценки",
        "path": "/my-grades",
        "description": "Просмотр своих оценок.",
    },
    "documents": {
        "title": "Документы",
        "path": "/documents",
        "description": "Раздел находится в разработке.",
    },
}

SECTION_ORDER = [
    "academic-process",
    "attestation",
    "academic-results",
    "analytics",
    "references",
    "administration",
    "schedule",
    "my-grades",
    "documents",
]

ROLE_SECTION_ACCESS = {
    "student": {"schedule", "my-grades", "documents"},
    "teacher": {"academic-process", "attestation", "schedule", "analytics"},
    "dean_office": {
        "academic-process",
        "attestation",
        "academic-results",
        "analytics",
        "references",
        "administration",
        "documents",
    },
    "management": {"analytics", "academic-results"},
    "admin": set(SECTION_DEFINITIONS.keys()),
}

DEFAULT_REGISTER_ROLE = "student"

app = FastAPI(
    title="Виртуальный деканат",
    description="Информационная система управления учебным процессом.",
)
app.add_middleware(SessionMiddleware, secret_key="virtual-dean-office-secret-key")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_data(db)
    finally:
        db.close()


def set_flash(request: Request, message: str, category: str = "info"):
    request.session["flash"] = {"message": message, "category": category}


def pop_flash(request: Request):
    return request.session.pop("flash", None)


def get_current_user(request: Request, db: Session):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def get_user_role_names(user: User):
    role_names = set()
    if user.primary_role:
        role_names.add(user.primary_role.name)
    for role in user.roles:
        role_names.add(role.name)
    return role_names


def get_available_section_keys(role_names: set[str]):
    if "admin" in role_names:
        return set(SECTION_DEFINITIONS.keys())

    available = set()
    for role_name in role_names:
        available.update(ROLE_SECTION_ACCESS.get(role_name, set()))
    return available


def get_available_sections(role_names: set[str]):
    keys = get_available_section_keys(role_names)
    return [
        {"key": key, **SECTION_DEFINITIONS[key]}
        for key in SECTION_ORDER
        if key in keys
    ]


def login_user(request: Request, user: User):
    request.session["user_id"] = user.id
    request.session["auth_method"] = "Постоянный пароль"


def build_context(request: Request, db: Session, extra: dict | None = None):
    current_user = get_current_user(request, db)
    role_names = set()
    available_sections = []
    primary_role_name = None

    if current_user:
        role_names = get_user_role_names(current_user)
        available_sections = get_available_sections(role_names)
        if current_user.primary_role:
            primary_role_name = current_user.primary_role.name

    context = {
        "request": request,
        "current_user": current_user,
        "role_names": sorted(role_names),
        "primary_role_name": primary_role_name,
        "available_sections": available_sections,
        "auth_method": request.session.get("auth_method"),
        "flash": pop_flash(request),
    }
    if extra:
        context.update(extra)
    return context


def login_required(request: Request, db: Session):
    user = get_current_user(request, db)
    if not user:
        return None, RedirectResponse(url="/login", status_code=303)
    return user, None


def section_guard(request: Request, db: Session, section_key: str):
    user, redirect = login_required(request, db)
    if redirect:
        return None, redirect

    available = get_available_section_keys(get_user_role_names(user))
    if section_key not in available:
        set_flash(request, "У вас нет доступа к этому разделу.", "error")
        return None, RedirectResponse(url="/dashboard", status_code=303)
    return user, None


def log_action(db: Session, user_id: int, action: str, resource_type: str, resource_id: int | None = None):
    log = ActionLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=datetime.utcnow(),
    )
    db.add(log)
    try:
        db.commit()
    except Exception:
        db.rollback()


# PUBLIC ROUTES
@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    users_count = db.query(User).count()
    context = build_context(request, db, {"users_count": users_count})
    return templates.TemplateResponse("index.html", context)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("register.html", build_context(request, db))


@app.post("/register")
def register_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    db: Session = Depends(get_db),
):
    username = username.strip()
    full_name = full_name.strip()

    if db.query(User).filter(User.username == username).first():
        set_flash(request, "Пользователь с таким логином уже существует.", "error")
        return RedirectResponse(url="/register", status_code=303)

    student_role = db.query(Role).filter(Role.name == DEFAULT_REGISTER_ROLE).first()
    if not student_role:
        set_flash(request, "Роль student не найдена. Проверьте seed-данные.", "error")
        return RedirectResponse(url="/register", status_code=303)

    user = User(
        username=username,
        password_hash=hash_password(password),
        full_name=full_name,
        is_active=True,
        clearance_level=1,
        secret_key=100,
        primary_role=student_role,
    )
    user.roles.append(student_role)

    try:
        db.add(user)
        db.commit()
        set_flash(request, "Регистрация успешна. Теперь выполните вход.", "success")
        return RedirectResponse(url="/login", status_code=303)
    except IntegrityError:
        db.rollback()
        set_flash(request, "Ошибка целостности данных при регистрации.", "error")
        return RedirectResponse(url="/register", status_code=303)
    except Exception as exc:
        db.rollback()
        set_flash(request, f"Не удалось зарегистрировать пользователя: {exc}", "error")
        return RedirectResponse(url="/register", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("login.html", build_context(request, db))


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user, ok, message = verify_persistent_password(db, username.strip(), password)
    if not ok or not user:
        set_flash(request, message, "error")
        return RedirectResponse(url="/login", status_code=303)

    login_user(request, user)
    set_flash(request, message, "success")
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)


# PROTECTED ROUTES
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user, redirect = login_required(request, db)
    if redirect:
        return redirect

    context = build_context(request, db)
    return templates.TemplateResponse("dashboard.html", context)


# REFERENCES SECTION
@app.get("/references/students", response_class=HTMLResponse)
def students_list(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    students = db.query(Student).all()
    context = build_context(request, db, {"students": students})
    return templates.TemplateResponse("references/students_list.html", context)


@app.get("/references/students/add", response_class=HTMLResponse)
def students_add_form(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    groups = db.query(Group).all()
    context = build_context(request, db, {"groups": groups})
    return templates.TemplateResponse("references/students_form.html", context)


@app.post("/references/students/add")
def students_add(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    group_id: int = Form(...),
    db: Session = Depends(get_db),
):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    try:
        student = Student(full_name=full_name.strip(), email=email.strip(), group_id=group_id)
        db.add(student)
        db.commit()
        log_action(db, user.id, "create", "student", student.id)
        set_flash(request, "Студент успешно добавлен.", "success")
        return RedirectResponse(url="/references/students", status_code=303)
    except IntegrityError:
        db.rollback()
        set_flash(request, "Студент с таким email уже существует.", "error")
    except Exception as e:
        db.rollback()
        set_flash(request, f"Ошибка при добавлении студента: {e}", "error")
    return RedirectResponse(url="/references/students/add", status_code=303)


@app.get("/references/groups", response_class=HTMLResponse)
def groups_list(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    groups = db.query(Group).all()
    context = build_context(request, db, {"groups": groups})
    return templates.TemplateResponse("references/groups_list.html", context)


@app.get("/references/groups/add", response_class=HTMLResponse)
def groups_add_form(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    context = build_context(request, db)
    return templates.TemplateResponse("references/groups_form.html", context)


@app.post("/references/groups/add")
def groups_add(
    request: Request,
    name: str = Form(...),
    description: str = Form(default=""),
    db: Session = Depends(get_db),
):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    try:
        group = Group(name=name.strip(), description=description.strip())
        db.add(group)
        db.commit()
        log_action(db, user.id, "create", "group", group.id)
        set_flash(request, "Группа успешно добавлена.", "success")
        return RedirectResponse(url="/references/groups", status_code=303)
    except IntegrityError:
        db.rollback()
        set_flash(request, "Группа с таким названием уже существует.", "error")
    except Exception as e:
        db.rollback()
        set_flash(request, f"Ошибка при добавлении группы: {e}", "error")
    return RedirectResponse(url="/references/groups/add", status_code=303)


@app.get("/references/teachers", response_class=HTMLResponse)
def teachers_list(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    teachers = db.query(Teacher).all()
    context = build_context(request, db, {"teachers": teachers})
    return templates.TemplateResponse("references/teachers_list.html", context)


@app.get("/references/teachers/add", response_class=HTMLResponse)
def teachers_add_form(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    departments = db.query(Department).all()
    context = build_context(request, db, {"departments": departments})
    return templates.TemplateResponse("references/teachers_form.html", context)


@app.post("/references/teachers/add")
def teachers_add(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    department_id: int = Form(...),
    db: Session = Depends(get_db),
):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    try:
        teacher = Teacher(
            full_name=full_name.strip(),
            email=email.strip(),
            department_id=department_id,
        )
        db.add(teacher)
        db.commit()
        log_action(db, user.id, "create", "teacher", teacher.id)
        set_flash(request, "Преподаватель успешно добавлен.", "success")
        return RedirectResponse(url="/references/teachers", status_code=303)
    except IntegrityError:
        db.rollback()
        set_flash(request, "Преподаватель с таким email уже существует.", "error")
    except Exception as e:
        db.rollback()
        set_flash(request, f"Ошибка при добавлении преподавателя: {e}", "error")
    return RedirectResponse(url="/references/teachers/add", status_code=303)


@app.get("/references/disciplines", response_class=HTMLResponse)
def disciplines_list(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    disciplines = db.query(Discipline).all()
    context = build_context(request, db, {"disciplines": disciplines})
    return templates.TemplateResponse("references/disciplines_list.html", context)


@app.get("/references/disciplines/add", response_class=HTMLResponse)
def disciplines_add_form(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    context = build_context(request, db)
    return templates.TemplateResponse("references/disciplines_form.html", context)


@app.post("/references/disciplines/add")
def disciplines_add(
    request: Request,
    name: str = Form(...),
    description: str = Form(default=""),
    credits: int = Form(default=3),
    db: Session = Depends(get_db),
):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    try:
        discipline = Discipline(
            name=name.strip(),
            description=description.strip(),
            credits=credits,
        )
        db.add(discipline)
        db.commit()
        log_action(db, user.id, "create", "discipline", discipline.id)
        set_flash(request, "Дисциплина успешно добавлена.", "success")
        return RedirectResponse(url="/references/disciplines", status_code=303)
    except IntegrityError:
        db.rollback()
        set_flash(request, "Дисциплина с таким названием уже существует.", "error")
    except Exception as e:
        db.rollback()
        set_flash(request, f"Ошибка при добавлении дисциплины: {e}", "error")
    return RedirectResponse(url="/references/disciplines/add", status_code=303)


@app.get("/references/departments", response_class=HTMLResponse)
def departments_list(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "references")
    if redirect:
        return redirect

    departments = db.query(Department).all()
    context = build_context(request, db, {"departments": departments})
    return templates.TemplateResponse("references/departments_list.html", context)


# ACADEMIC PROCESS SECTION
@app.get("/academic-process", response_class=HTMLResponse)
def academic_process(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "academic-process")
    if redirect:
        return redirect

    context = build_context(request, db, {
        "section": SECTION_DEFINITIONS["academic-process"]
    })
    return templates.TemplateResponse("academic_process/index.html", context)


@app.get("/academic-process/schedule", response_class=HTMLResponse)
def schedules_list(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "academic-process")
    if redirect:
        return redirect

    schedules = db.query(Schedule).all()
    context = build_context(request, db, {"schedules": schedules})
    return templates.TemplateResponse("academic_process/schedule_list.html", context)


@app.get("/academic-process/schedule/add", response_class=HTMLResponse)
def schedules_add_form(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "academic-process")
    if redirect:
        return redirect

    groups = db.query(Group).all()
    disciplines = db.query(Discipline).all()
    teachers = db.query(Teacher).all()
    context = build_context(request, db, {
        "groups": groups,
        "disciplines": disciplines,
        "teachers": teachers,
    })
    return templates.TemplateResponse("academic_process/schedule_form.html", context)


@app.post("/academic-process/schedule/add")
def schedules_add(
    request: Request,
    group_id: int = Form(...),
    discipline_id: int = Form(...),
    teacher_id: int = Form(...),
    day_of_week: str = Form(...),
    time_start: str = Form(...),
    time_end: str = Form(...),
    classroom: str = Form(...),
    db: Session = Depends(get_db),
):
    user, redirect = section_guard(request, db, "academic-process")
    if redirect:
        return redirect

    try:
        schedule = Schedule(
            group_id=group_id,
            discipline_id=discipline_id,
            teacher_id=teacher_id,
            day_of_week=day_of_week,
            time_start=time_start,
            time_end=time_end,
            classroom=classroom.strip(),
        )
        db.add(schedule)
        db.commit()
        log_action(db, user.id, "create", "schedule", schedule.id)
        set_flash(request, "Расписание успешно добавлено.", "success")
        return RedirectResponse(url="/academic-process/schedule", status_code=303)
    except Exception as e:
        db.rollback()
        set_flash(request, f"Ошибка при добавлении расписания: {e}", "error")
    return RedirectResponse(url="/academic-process/schedule/add", status_code=303)


# ATTESTATION SECTION
@app.get("/attestation", response_class=HTMLResponse)
def attestation_index(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "attestation")
    if redirect:
        return redirect

    context = build_context(request, db, {
        "section": SECTION_DEFINITIONS["attestation"]
    })
    return templates.TemplateResponse("attestation/index.html", context)


@app.get("/attestation/input", response_class=HTMLResponse)
def attestation_input_form(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "attestation")
    if redirect:
        return redirect

    groups = db.query(Group).all()
    disciplines = db.query(Discipline).all()
    students = db.query(Student).all()
    teachers = db.query(Teacher).all()
    context = build_context(request, db, {
        "groups": groups,
        "disciplines": disciplines,
        "students": students,
        "teachers": teachers,
    })
    return templates.TemplateResponse("attestation/input.html", context)


@app.post("/attestation/input")
def attestation_input(
    request: Request,
    student_id: int = Form(...),
    group_id: int = Form(...),
    discipline_id: int = Form(...),
    teacher_id: int = Form(...),
    attestation_type: str = Form(...),
    grade: float = Form(...),
    date: str = Form(...),
    db: Session = Depends(get_db),
):
    user, redirect = section_guard(request, db, "attestation")
    if redirect:
        return redirect

    try:
        attestation = Attestation(
            student_id=student_id,
            group_id=group_id,
            discipline_id=discipline_id,
            teacher_id=teacher_id,
            attestation_type=attestation_type,
            grade=grade,
            date=date,
            status="completed",
        )
        db.add(attestation)
        db.commit()
        log_action(db, user.id, "create", "attestation", attestation.id)
        set_flash(request, "Оценка успешно добавлена.", "success")
        return RedirectResponse(url="/attestation/input", status_code=303)
    except Exception as e:
        db.rollback()
        set_flash(request, f"Ошибка при добавлении оценки: {e}", "error")
    return RedirectResponse(url="/attestation/input", status_code=303)


@app.get("/attestation/register", response_class=HTMLResponse)
def attestation_register(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "attestation")
    if redirect:
        return redirect

    groups = db.query(Group).all()
    disciplines = db.query(Discipline).all()
    context = build_context(request, db, {
        "groups": groups,
        "disciplines": disciplines,
    })
    return templates.TemplateResponse("attestation/register.html", context)


@app.get("/my-grades", response_class=HTMLResponse)
def my_grades(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "my-grades")
    if redirect:
        return redirect

    student = db.query(Student).first()
    attestations = []
    if student:
        attestations = db.query(Attestation).filter(Attestation.student_id == student.id).all()

    context = build_context(request, db, {"attestations": attestations})
    return templates.TemplateResponse("my_grades.html", context)


# ANALYTICS SECTION
@app.get("/analytics", response_class=HTMLResponse)
def analytics_index(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "analytics")
    if redirect:
        return redirect

    context = build_context(request, db, {
        "section": SECTION_DEFINITIONS["analytics"]
    })
    return templates.TemplateResponse("analytics/index.html", context)


@app.get("/analytics/performance", response_class=HTMLResponse)
def analytics_performance(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "analytics")
    if redirect:
        return redirect

    disciplines = db.query(Discipline).all()
    stats = []
    for disc in disciplines:
        attestations = db.query(Attestation).filter(Attestation.discipline_id == disc.id).all()
        if attestations:
            avg_grade = sum(a.grade for a in attestations if a.grade) / len([a for a in attestations if a.grade])
            count = len(attestations)
            stats.append({
                "discipline": disc.name,
                "count": count,
                "avg_grade": f"{avg_grade:.2f}",
            })

    context = build_context(request, db, {"stats": stats})
    return templates.TemplateResponse("analytics/performance.html", context)


@app.get("/analytics/failing-students", response_class=HTMLResponse)
def analytics_failing(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "analytics")
    if redirect:
        return redirect

    students = db.query(Student).all()
    failing = []
    for student in students:
        attestations = db.query(Attestation).filter(Attestation.student_id == student.id).all()
        if attestations:
            grades = [a.grade for a in attestations if a.grade]
            if grades:
                avg = sum(grades) / len(grades)
                if avg < 3.0:
                    failing.append({
                        "student": student.full_name,
                        "group": student.group.name,
                        "avg_grade": f"{avg:.2f}",
                    })

    context = build_context(request, db, {"failing": failing})
    return templates.TemplateResponse("analytics/failing_students.html", context)


# ACADEMIC RESULTS SECTION
@app.get("/academic-results", response_class=HTMLResponse)
def academic_results(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "academic-results")
    if redirect:
        return redirect

    context = build_context(request, db, {
        "section": SECTION_DEFINITIONS["academic-results"]
    })
    return templates.TemplateResponse("academic_results/index.html", context)


# SCHEDULE SECTION (Student view)
@app.get("/schedule", response_class=HTMLResponse)
def student_schedule(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "schedule")
    if redirect:
        return redirect

    student = db.query(Student).first()
    schedules = []
    if student:
        schedules = db.query(Schedule).filter(Schedule.group_id == student.group_id).all()

    context = build_context(request, db, {"schedules": schedules})
    return templates.TemplateResponse("schedule.html", context)


# ADMINISTRATION SECTION
@app.get("/administration", response_class=HTMLResponse)
def administration(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "administration")
    if redirect:
        return redirect

    context = build_context(request, db, {
        "section": SECTION_DEFINITIONS["administration"]
    })
    return templates.TemplateResponse("administration/index.html", context)


@app.get("/administration/action-log", response_class=HTMLResponse)
def action_log(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "administration")
    if redirect:
        return redirect

    logs = db.query(ActionLog).order_by(ActionLog.timestamp.desc()).limit(100).all()
    context = build_context(request, db, {"logs": logs})
    return templates.TemplateResponse("administration/action_log.html", context)


@app.get("/administration/users", response_class=HTMLResponse)
def admin_users(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "administration")
    if redirect:
        return redirect

    users = db.query(User).all()
    context = build_context(request, db, {"users": users})
    return templates.TemplateResponse("administration/users.html", context)


# DOCUMENTS SECTION (stub)
@app.get("/documents", response_class=HTMLResponse)
def documents(request: Request, db: Session = Depends(get_db)):
    user, redirect = section_guard(request, db, "documents")
    if redirect:
        return redirect

    context = build_context(request, db, {
        "section": SECTION_DEFINITIONS["documents"]
    })
    return templates.TemplateResponse("documents.html", context)
