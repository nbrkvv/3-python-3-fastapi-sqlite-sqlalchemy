from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from auth_methods import hash_password, verify_persistent_password
from database import Base, SessionLocal, engine, get_db
from models import Role, User
from seed import seed_data

SECTION_DEFINITIONS = {
    "students": {
        "title": "Студенты",
        "path": "/students",
        "description": "Раздел находится в разработке.",
    },
    "teachers": {
        "title": "Преподаватели",
        "path": "/teachers",
        "description": "Раздел находится в разработке.",
    },
    "applications": {
        "title": "Заявления",
        "path": "/applications",
        "description": "Раздел находится в разработке.",
    },
    "schedule": {
        "title": "Расписание",
        "path": "/schedule",
        "description": "Раздел находится в разработке.",
    },
    "documents": {
        "title": "Документы",
        "path": "/documents",
        "description": "Раздел находится в разработке.",
    },
}

SECTION_ORDER = ["students", "teachers", "applications", "schedule", "documents"]

ROLE_SECTION_ACCESS = {
    "student": {"schedule", "documents", "applications"},
    "teacher": {"schedule", "students", "documents"},
    "dean_office": {"students", "teachers", "applications", "documents"},
    "admin": set(SECTION_DEFINITIONS.keys()),
}

DEFAULT_REGISTER_ROLE = "student"

app = FastAPI(
    title="Виртуальный деканат",
    description="Заготовка веб-приложения с регистрацией, авторизацией и ролевым доступом.",
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


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user, redirect = login_required(request, db)
    if redirect:
        return redirect

    context = build_context(request, db)
    return templates.TemplateResponse("dashboard.html", context)


def render_section(request: Request, db: Session, section_key: str):
    _, redirect = section_guard(request, db, section_key)
    if redirect:
        return redirect

    section = SECTION_DEFINITIONS[section_key]
    context = build_context(request, db, {"section": section})
    return templates.TemplateResponse("section_stub.html", context)


@app.get("/students", response_class=HTMLResponse)
def students_page(request: Request, db: Session = Depends(get_db)):
    return render_section(request, db, "students")


@app.get("/teachers", response_class=HTMLResponse)
def teachers_page(request: Request, db: Session = Depends(get_db)):
    return render_section(request, db, "teachers")


@app.get("/applications", response_class=HTMLResponse)
def applications_page(request: Request, db: Session = Depends(get_db)):
    return render_section(request, db, "applications")


@app.get("/schedule", response_class=HTMLResponse)
def schedule_page(request: Request, db: Session = Depends(get_db)):
    return render_section(request, db, "schedule")


@app.get("/documents", response_class=HTMLResponse)
def documents_page(request: Request, db: Session = Depends(get_db)):
    return render_section(request, db, "documents")
