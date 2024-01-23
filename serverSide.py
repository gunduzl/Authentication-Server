from fastapi import FastAPI, HTTPException, status, Depends, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from urllib.parse import parse_qsl
import rsa
import base64
import os
import subprocess
import pytz

Base = declarative_base()
SECRET_KEY = None
ALGORITHM = None
ACCESS_TOKEN_EXPIRE_MINUTES = 5

DATABASE_URL = "postgresql://postgres:12345@localhost:5432/SecurityKerberos"
engine = create_engine(DATABASE_URL)

Base = declarative_base()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


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


class SecretKeyTable(Base):
    __tablename__ = 'secret_keys'
    id = Column(Integer, primary_key=True)
    secret_key = Column(String)
    algorithm = Column(String)


class Log(Base):
    __tablename__ = 'logs'
    id = Column(Integer, primary_key=True)
    status = Column(String)
    username = Column(String)
    time = Column(String)
    message = Column(String)


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str or None = None

class TgsResponse(BaseModel):
    access_token: str
    token_type: str

class UpdateClientKey(BaseModel):
    new_client_key: str

class UpdateServerKey(BaseModel):
    new_server_key: str


class client_tgt(BaseModel):
    tgt: str

class UserResponse(BaseModel):
    id: int
    username: str
    full_name: str
    email: str
    disabled: bool
    is_admin: bool
    tgt: str 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_secret_key_and_algorithm(db_session):
    try:
        secret_key_entry = db_session.query(SecretKeyTable).first()
        if secret_key_entry:
            return secret_key_entry.secret_key, secret_key_entry.algorithm
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Secret key entry not found in the database",
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred in get_secret_key_and_algorithm: {str(e)}",
        )

SECRET_KEY, ALGORITHM = get_secret_key_and_algorithm(SessionLocal())

def verify_password(plain_password, hashed_client_key):
    return pwd_context.verify(plain_password, hashed_client_key)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    return db.query(Person).filter(Person.username == username).first()

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_client_key):
        return False
    return user


def istanbul_time():
    utc_plus_3 = pytz.timezone('Europe/Istanbul')
    current_time_utc_plus_3 = datetime.now(utc_plus_3)
    formatted_time = current_time_utc_plus_3.strftime("%Y-%m-%d %H:%M:%S")
    return formatted_time


def add_log_entry(db_session, status, username, message):
    log_entry = Log(status=status, username=username, time=istanbul_time(), message=message)
    db_session.add(log_entry)
    db_session.commit()


def generate_new_server_key():
    # Generate a new server key using openssl rand -hex 32
    result = subprocess.run(['openssl', 'rand', '-hex', '32'], stdout=subprocess.PIPE)
    new_server_key = result.stdout.decode().strip()
    return new_server_key

def create_access_token(data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



async def get_current_user(token: str = Depends(oauth2_scheme), db_session = Depends(get_db)):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credential_exception
    user = get_user(db_session, username=token_data.username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


async def get_current_activate_user(current_user: Person = Depends(get_current_user)):
        if current_user.disabled:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
        return current_user

def decrypt_message(encrypted_message, private_key):
    try:
        decrypted_message = rsa.decrypt(base64.b64decode(encrypted_message.encode()), private_key).decode()
        add_log_entry(SessionLocal(), "SUCCESS", "Server", "Message decrypted successfully")
        return decrypted_message
    except rsa.DecryptionError as e:
        add_log_entry(SessionLocal(), "ERROR", "Server", f"An error occurred in decrypt_message: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid encrypted message")
    except Exception as e:
        add_log_entry(SessionLocal(), "ERROR", "Server", f"An error occurred in decrypt_message: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@app.post("/token", response_model=Token)
async def login_for_access_token(encrypted_form_data: OAuth2PasswordRequestForm = Depends(), db_session = Depends(get_db)):
    private_key = rsa.PrivateKey.load_pkcs1(open("private.pem", "rb").read())

    try:
        decrypted_form_data = decrypt_message(encrypted_form_data.password, private_key)
        decrypted_form_data_dict = dict(parse_qsl(decrypted_form_data))
        form_data = OAuth2PasswordRequestForm(**decrypted_form_data_dict)
        add_log_entry(db_session, "SUCCESS", "Server", "Encrypted data decrypted successfully")
    except Exception as e:
        add_log_entry(db_session, "ERROR", "Server", f"An error occurred in login_for_access_token: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid encrypted data: {str(e)}")

    user = authenticate_user(db_session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )


    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

    # access this user in database with get_db() and update tgt
    user.tgt = access_token
    db_session.commit()
    add_log_entry(db_session, "SUCCESS", user.username, "User logged in successfully")
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/tgt-validation-and-tgs", response_model=TgsResponse)
async def tgt_tgs(
    update_data: client_tgt,
    current_user: Person = Depends(get_current_activate_user),
    db_session = Depends(get_db)
):  
    try:
        if current_user.tgt == update_data.tgt:
            tgs_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            tgs_token = create_access_token(data={"sub": current_user.username}, expires_delta=tgs_token_expires)
            add_log_entry(db_session, "SUCCESS", current_user.username, "TGT validated successfully")
            return {"access_token": tgs_token, "token_type": "bearer"}
        else:
            add_log_entry(db_session, "ERROR", current_user.username, "TGT validation failed")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    except Exception as e:
        add_log_entry(db_session, "ERROR", current_user.username, f"An error occurred in tgt_tgs: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    


@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: Person = Depends(get_current_activate_user), db_session=Depends(get_db)):
    userinfo = UserResponse(**current_user.__dict__)
    current_user_dict = userinfo.dict()  # Convert UserResponse object to a dictionary
    current_user_dict['username'] = current_user_dict.get('username')  # Set the 'username' attribute
    add_log_entry(db_session, "SUCCESS", current_user_dict['username'], "User information is read successfully")
    return UserResponse(**current_user_dict)

@app.post("/update-client-key", response_model=str)
async def update_client_key(
    update_data: UpdateClientKey,
    current_user: Person = Depends(get_current_activate_user),
    db_session = Depends(get_db)
):
    private_key = rsa.PrivateKey.load_pkcs1(open("private.pem", "rb").read())
    new_client_key = decrypt_message(update_data.new_client_key, private_key)
    
    try:
        if new_client_key:

            # Update the person in the database
            current_user.hashed_client_key = get_password_hash(new_client_key)
            add_log_entry(db_session, "SUCCESS", current_user.username, "Client Key updated successfully")
            db_session.commit()

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        create_access_token(data={"sub": current_user.username}, expires_delta=access_token_expires)
        return "Client Key updated successfully also a new token for the client is generated"
    except Exception as e:
        add_log_entry(db_session, "ERROR", current_user.username, f"An error occurred in update_client_key: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@app.post("/update-server-key", response_model=str)
async def update_server_key(
    update_data: UpdateServerKey,
    current_user: Person = Depends(get_current_activate_user),
    db_session = Depends(get_db)
):
    if not current_user.is_admin:
        add_log_entry(db_session, "ERROR", current_user.username, "You don't have permission to update the server key")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to update the server key",
        )
    new_server_key = generate_new_server_key()
    secret_key_entry = db_session.query(SecretKeyTable).first()
    if secret_key_entry:
        secret_key_entry.secret_key = new_server_key
        db_session.commit()
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Secret key entry not found in the database",
        )
    os.environ["SECRET_KEY"] = new_server_key
    add_log_entry(db_session, "SUCCESS", current_user.username, "Server Key updated successfully")
    return "Server Key updated successfully"

@app.get("/generate-new-server-key", response_model=str)
async def generate_new_server_key_route(
    current_user: Person = Depends(get_current_activate_user),
    db_session = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to generate a new server key",
        )
    try:
        new_server_key = generate_new_server_key()
        add_log_entry(db_session, "SUCCESS", current_user.username, "Server Key generated successfully")
        return new_server_key
    except Exception as e:
        add_log_entry(db_session, "ERROR", current_user.username, f"An error occurred in generate_new_server_key_route: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

@app.get("/current-time")
async def get_current_time(current_user: Person = Depends(get_current_user),db_session = Depends(get_db)):
    utc_plus_3 = pytz.timezone('Europe/Istanbul')
    current_time_utc_plus_3 = datetime.now(utc_plus_3)
    formatted_time = current_time_utc_plus_3.strftime("%Y-%m-%d %H:%M:%S")
    add_log_entry(db_session, "SUCCESS", current_user.username, "Current time is read successfully")
    return {"current_time_utc_plus_3": formatted_time}

@app.get("/users", response_model=UserResponse)
async def read_users_me(current_user: Person = Depends(get_current_activate_user), db_session=Depends(get_db)):
    userinfo = UserResponse(**current_user.__dict__)
    current_user_dict = userinfo.dict()  # Convert UserResponse object to a dictionary
    current_user_dict['username'] = current_user_dict.get('username')  # Set the 'username' attribute
    add_log_entry(db_session, "SUCCESS", current_user_dict['username'], "TICKET GRATING SERVICE validated successfully")
    return UserResponse(**current_user_dict)

@app.get("/logout", response_model=str)
async def logout(current_user: Person = Depends(get_current_activate_user), db_session = Depends(get_db)):
    current_user.tgt = None
    db_session.commit()
    add_log_entry(db_session, "SUCCESS", current_user.username, "User logged out and tgt is removed successfully")
    return "User logged out successfully"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("srvr:app", host="127.0.0.1", port=8000)
