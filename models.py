from datetime import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from database import Base


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    level = Column(Integer, nullable=False, default=1)

    users = relationship("User", secondary="user_roles", back_populates="roles")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(120), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    clearance_level = Column(Integer, default=1, nullable=False)
    secret_key = Column(Integer, default=100, nullable=False)
    primary_role_id = Column(Integer, ForeignKey("roles.id"), nullable=True)

    primary_role = relationship("Role", foreign_keys=[primary_role_id])
    roles = relationship("Role", secondary="user_roles", back_populates="users")
    action_logs = relationship("ActionLog", back_populates="user")


class Department(Base):
    __tablename__ = "departments"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)

    teachers = relationship("Teacher", back_populates="department")


class Teacher(Base):
    __tablename__ = "teachers"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(120), nullable=False)
    email = Column(String(100), unique=True, nullable=False, index=True)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=False, index=True)

    department = relationship("Department", back_populates="teachers")
    disciplines = relationship("Discipline", secondary="teacher_disciplines", back_populates="teachers")
    schedules = relationship("Schedule", back_populates="teacher")
    attestations = relationship("Attestation", back_populates="teacher")


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)

    students = relationship("Student", back_populates="group")
    disciplines = relationship("Discipline", secondary="group_disciplines", back_populates="groups")
    schedules = relationship("Schedule", back_populates="group")


class Student(Base):
    __tablename__ = "students"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(120), nullable=False)
    email = Column(String(100), unique=True, nullable=False, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False, index=True)

    group = relationship("Group", back_populates="students")
    attestations = relationship("Attestation", back_populates="student")


class Discipline(Base):
    __tablename__ = "disciplines"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    credits = Column(Integer, default=3, nullable=False)

    groups = relationship("Group", secondary="group_disciplines", back_populates="disciplines")
    teachers = relationship("Teacher", secondary="teacher_disciplines", back_populates="disciplines")
    schedules = relationship("Schedule", back_populates="discipline")
    attestations = relationship("Attestation", back_populates="discipline")


class GroupDiscipline(Base):
    __tablename__ = "group_disciplines"

    group_id = Column(Integer, ForeignKey("groups.id"), primary_key=True, index=True)
    discipline_id = Column(Integer, ForeignKey("disciplines.id"), primary_key=True, index=True)


class TeacherDiscipline(Base):
    __tablename__ = "teacher_disciplines"

    teacher_id = Column(Integer, ForeignKey("teachers.id"), primary_key=True, index=True)
    discipline_id = Column(Integer, ForeignKey("disciplines.id"), primary_key=True, index=True)


class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False, index=True)
    discipline_id = Column(Integer, ForeignKey("disciplines.id"), nullable=False, index=True)
    teacher_id = Column(Integer, ForeignKey("teachers.id"), nullable=False, index=True)
    day_of_week = Column(String(20), nullable=False)
    time_start = Column(String(5), nullable=False)
    time_end = Column(String(5), nullable=False)
    classroom = Column(String(20), nullable=False)

    group = relationship("Group", back_populates="schedules")
    discipline = relationship("Discipline", back_populates="schedules")
    teacher = relationship("Teacher", back_populates="schedules")


class Attestation(Base):
    __tablename__ = "attestations"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("students.id"), nullable=False, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False, index=True)
    discipline_id = Column(Integer, ForeignKey("disciplines.id"), nullable=False, index=True)
    teacher_id = Column(Integer, ForeignKey("teachers.id"), nullable=False, index=True)
    attestation_type = Column(String(20), nullable=False)
    grade = Column(Float, nullable=True)
    date = Column(String(10), nullable=False)
    status = Column(String(20), default="pending", nullable=False)

    student = relationship("Student", back_populates="attestations")
    group = relationship("Group")
    discipline = relationship("Discipline", back_populates="attestations")
    teacher = relationship("Teacher", back_populates="attestations")


class ActionLog(Base):
    __tablename__ = "action_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    action = Column(String(50), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="action_logs")
