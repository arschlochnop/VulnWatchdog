import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text, inspect
from sqlalchemy.sql import func
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from config import get_config
import logging


logger = logging.getLogger(__name__)
# 创建数据库连接
db_url = get_config('DB_URL')

class Base(DeclarativeBase):  # 改这里
    pass

class CVE(Base):
    __tablename__ = 'cves'
    
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20), unique=True, nullable=False)
    title = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    cve_data = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Repository(Base):
    __tablename__ = 'repositories'
    
    id = Column(Integer, primary_key=True)
    github_id = Column(Integer, nullable=False)
    cve_id = Column(String(20), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String(255), nullable=False)
    repo_data = Column(JSON, nullable=False)
    repo_pushed_at = Column(String(20), nullable=False)
    action_log = Column(String(10), nullable=False)  # new/update
    gpt_analysis = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    
def init_db():
    engine = create_engine(db_url)
    Base.metadata.create_all(engine) 

def get_db():
    engine = create_engine(db_url)
    # 确保表存在
    inspector = inspect(engine)
    if not inspector.has_table("cves") or not inspector.has_table("repositories"):
        logger.info(f"数据库表不存在，正在创建: {db_url}")
        init_db()
    Session = sessionmaker(bind=engine)
    return Session()