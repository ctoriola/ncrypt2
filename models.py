from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, BigInteger, Text, func
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import JSONB
import datetime

Base = declarative_base()

class AdminUser(Base):
    __tablename__ = 'admin_users'
    id = Column(Integer, primary_key=True)
    username = Column(String(128), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=func.now())

class File(Base):
    __tablename__ = 'files'
    id = Column(String(64), primary_key=True)
    share_id = Column(String(32), unique=True, nullable=True)
    filename = Column(String(256), nullable=False)
    size = Column(BigInteger, nullable=False)
    upload_date = Column(DateTime, default=func.now())
    encrypted = Column(Boolean, default=True)
    mime_type = Column(String(128), nullable=True)
    user_id = Column(String(128), nullable=True)
    # Add more fields as needed
    histories = relationship('FileHistory', back_populates='file')

class FileHistory(Base):
    __tablename__ = 'file_history'
    id = Column(Integer, primary_key=True)
    file_id = Column(String(64), ForeignKey('files.id'))
    action = Column(String(64), nullable=False)
    user_id = Column(String(128), nullable=True)
    ip_address = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=func.now())
    file = relationship('File', back_populates='histories')

class Stats(Base):
    __tablename__ = 'stats'
    id = Column(Integer, primary_key=True)
    total_visits = Column(Integer, default=0)
    unique_visitors = Column(Integer, default=0)
    daily_visits = Column(JSONB, default=dict)
    page_views = Column(JSONB, default=dict)
    upload_stats = Column(JSONB, default=dict)
    download_stats = Column(JSONB, default=dict)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now()) 