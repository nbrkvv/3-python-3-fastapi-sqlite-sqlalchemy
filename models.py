from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
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
    key_value = Column(String(100), nullable=True)
    level = Column(Integer, nullable=False, default=1)
    parent_id = Column(Integer, ForeignKey("roles.id"), nullable=True)

    parent = relationship("Role", remote_side=[id], backref="children")
    users = relationship("User", secondary="user_roles", back_populates="roles")
    permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(120), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    clearance_level = Column(Integer, default=1, nullable=False)
    secret_question = Column(String(255), nullable=True)
    secret_answer_hash = Column(String(255), nullable=True)
    secret_key = Column(Integer, default=100, nullable=False)
    key_value = Column(String(100), nullable=True)
    primary_role_id = Column(Integer, ForeignKey("roles.id"), nullable=True)

    primary_role = relationship("Role", foreign_keys=[primary_role_id])
    roles = relationship("Role", secondary="user_roles", back_populates="users")
    otp_codes = relationship("OTPCode", back_populates="user", cascade="all, delete-orphan")
    capabilities = relationship("Capability", back_populates="user", cascade="all, delete-orphan")


class OTPCode(Base):
    __tablename__ = "otp_codes"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    code = Column(String(50), nullable=False)
    sequence_number = Column(Integer, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="otp_codes")

    __table_args__ = (UniqueConstraint("user_id", "sequence_number", name="uq_user_otp_sequence"),)


class ProtectedObject(Base):
    __tablename__ = "protected_objects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    secrecy_level = Column(Integer, nullable=False, default=1)
    lock_value = Column(String(100), nullable=False)

    permissions = relationship("RolePermission", back_populates="object", cascade="all, delete-orphan")
    acl_entries = relationship("ACLEntry", back_populates="object", cascade="all, delete-orphan")
    capabilities = relationship("Capability", back_populates="object", cascade="all, delete-orphan")


class RolePermission(Base):
    __tablename__ = "role_permissions"

    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)
    object_id = Column(Integer, ForeignKey("protected_objects.id"), nullable=False, index=True)
    operation = Column(String(20), nullable=False)
    allow = Column(Boolean, default=True, nullable=False)

    role = relationship("Role", back_populates="permissions")
    object = relationship("ProtectedObject", back_populates="permissions")

    __table_args__ = (UniqueConstraint("role_id", "object_id", "operation", name="uq_role_object_operation"),)


class ACLEntry(Base):
    __tablename__ = "acl_entries"

    id = Column(Integer, primary_key=True)
    object_id = Column(Integer, ForeignKey("protected_objects.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=True, index=True)
    operation = Column(String(20), nullable=False)
    allow = Column(Boolean, default=True, nullable=False)

    object = relationship("ProtectedObject", back_populates="acl_entries")
    user = relationship("User")
    role = relationship("Role")

    __table_args__ = (UniqueConstraint("object_id", "user_id", "role_id", "operation", name="uq_acl_entry"),)


class Capability(Base):
    __tablename__ = "capabilities"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    object_id = Column(Integer, ForeignKey("protected_objects.id"), nullable=False, index=True)
    operation = Column(String(20), nullable=False)
    allow = Column(Boolean, default=True, nullable=False)
    issued_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="capabilities")
    object = relationship("ProtectedObject", back_populates="capabilities")

    __table_args__ = (UniqueConstraint("user_id", "object_id", "operation", name="uq_user_capability"),)
