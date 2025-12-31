from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models, schemas, auth

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Authentication API")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------- USER CREATE ----------------
@app.post("/user_auth/create", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User)\
        .filter(models.User.username == user.username)\
        .first()

    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    new_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=auth.hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# ---------------- USER LOGIN ----------------
@app.post("/user_auth/login")
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User)\
        .filter(models.User.username == user.username)\
        .first()

    if not db_user or not auth.verify_password(
        user.password, db_user.hashed_password
    ):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = auth.create_access_token(
        data={"sub": db_user.username}
    )
    return {"access_token": token, "token_type": "bearer"}

# ---------------- USER PROFILE ----------------
@app.get("/user_auth/user-profile", response_model=schemas.UserResponse)
def get_user_profile(db: Session = Depends(get_db)):
    user = db.query(models.User).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/user_auth/username/available")
def check_username_available(username: str, db: Session = Depends(get_db)):
    user = db.query(models.User)\
        .filter(models.User.username == username)\
        .first()

    if user:
        return {
            "available": False,
            "message": "Username already exists"
        }

    return {
        "available": True,
        "message": "Username is available"
    }

@app.get("/user_auth/email/available")
def check_email_available(email: str, db: Session = Depends(get_db)):
    user = db.query(models.User)\
        .filter(models.User.email == email)\
        .first()

    if user:
        return {
            "available": False,
            "message": "Email already exists"
        }

    return {
        "available": True,
        "message": "Email is available"
    }
