import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import event
from pathlib import Path

current_file = Path(__file__)
current_file_dir = current_file.parent
project_root = current_file_dir.parent
project_root_absolute = project_root.resolve()
static_root_absolute = project_root_absolute 

#SQLALCHEMY_DATABASE_URL = 'sqlite:///C:\\Users\\jnrdrgz\\Desktop\\prg\\prode_api\\test.db?check_same_thread=False'
SQLALCHEMY_DATABASE_URL = 'sqlite:///' + str(project_root_absolute) +'/prode_app_test.db?check_same_thread=False'

engine = create_engine(SQLALCHEMY_DATABASE_URL)

def _fk_pragma_on_connect(dbapi_con, con_record):
    dbapi_con.execute('pragma journal_mode=WAL')

event.listen(engine, 'connect', _fk_pragma_on_connect)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

