from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class Person(Base):
    __tablename__ = 'people'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    full_name = Column(String)
    email = Column(String)
    hashed_client_key = Column(String)
    disabled = Column(Boolean)
    is_admin = Column(Boolean)
    tgt = Column(String) 

    def __init__(self, username, full_name, email, hashed_client_key, disabled=False, is_admin=False, tgt=None):
        self.username = username
        self.full_name = full_name
        self.email = email
        self.hashed_client_key = hashed_client_key
        self.disabled = disabled
        self.is_admin = is_admin
        self.tgt = tgt
      
    def __repr__(self):
        return f"<Person(username={self.username}, full_name={self.full_name}, email={self.email}, " \
               f"hashed_client_key={self.hashed_client_key}, disabled={self.disabled}, is_admin={self.is_admin}, tgt={self.tgt} )>"

# Update the connection string for PostgreSQL
postgres_conn_str = "postgresql://postgres:12345@localhost:5432/SecurityKerberos"
engine = create_engine(postgres_conn_str, echo=True)
Base.metadata.create_all(bind=engine)
Session = sessionmaker(bind=engine)
session = Session()

p1 = Person(username="Alice", full_name="Alice", email="alice@gmail.com",
            hashed_client_key="$2b$12$UELPs0QUEUaStEx.pRIw4.g3GwAA9arm6LJkWsrMea6381JY/rjF2")
p2 = Person(username="Admin", full_name="Admin User", email="admin@example.com",
            hashed_client_key="$2b$12$0MTmZ.e3PF.3Qy9XqN7sveP4fVt9ZRcUlIQT/FfIi82wmjkCTxSze", is_admin=True)

session.add(p1)
session.add(p2)
session.commit()

results = session.query(Person).all()
print(results)

class SecretKeyTable(Base):
    __tablename__ = 'secret_keys'
    id = Column(Integer, primary_key=True)
    secret_key = Column(String)
    algorithm = Column(String)

    def __init__(self, secret_key, algorithm="HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def __repr__(self):
        return f"<SecretKeyTable(secret_key={self.secret_key}, algorithm={self.algorithm})>"
    
class Log(Base):
    __tablename__ = 'logs'
    id = Column(Integer, primary_key=True)
    status = Column(String)
    username = Column(String)
    time = Column(String)
    message = Column(String)

    def __init__(self, status, username, time, message):
        self.status = status
        self.username = username
        self.time = time
        self.message = message


engine = create_engine(postgres_conn_str, echo=True)
Base.metadata.create_all(bind=engine)
Session = sessionmaker(bind=engine)
session = Session()

SECRET_KEY = "e7a78adc486ac275d4f36cabb0e2cdb4d68ed79574801831b4c873c95039703a"

secret_key_entry = SecretKeyTable(secret_key=SECRET_KEY, algorithm="HS256")
session.add(secret_key_entry)
session.commit()

results = session.query(SecretKeyTable).all()
print(results)
