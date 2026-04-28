from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
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
