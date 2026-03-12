from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, firestore
import secrets
import os

# -------------------------
# Firebase Setup
# -------------------------

# -------------------------
# Firebase Setup
# -------------------------

import json

if not firebase_admin._apps:
    firebase_key = os.environ.get("FIREBASE_KEY")

    cred = credentials.Certificate(json.loads(firebase_key))
    firebase_admin.initialize_app(cred)

db = firestore.client()


# -------------------------
# FastAPI Setup
# -------------------------

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=secrets.token_hex(32)
)

# -------------------------
# Password Hashing
# -------------------------

# -------------------------
# Models
# -------------------------

class UserCreate(BaseModel):
    username: str
    password: str
    role: str
    name: str
    room: str | None = None
    bed: str | None = None
    photo: str | None = None   # base64 image

class LeaveRequest(BaseModel):
    student: str
    room: str
    reason: str


class RoomCreate(BaseModel):
    room_number: str
    bedA: str
    bedB: str
    bedC: str | None = None
    bedD: str | None = None
    bedE: str | None = None

# -------------------------
# Role Security
# -------------------------

def require_role(request: Request, role: str):
    if request.session.get("role") != role:
        raise HTTPException(status_code=403, detail="Unauthorized")

# -------------------------
# Helper
# -------------------------

def read_html(path):
    if not os.path.exists(path):
        raise HTTPException(status_code=500, detail=f"Missing template: {path}")
    return open(path, encoding="utf-8").read()

# -------------------------
# Pages
# -------------------------

@app.get("/", response_class=HTMLResponse)
def home():
    return read_html("templates/index.html")


@app.get("/warden", response_class=HTMLResponse)
def warden(request: Request):
    require_role(request, "warden")
    return read_html("templates/warden.html")


@app.get("/security", response_class=HTMLResponse)
def security(request: Request):
    require_role(request, "security")
    return read_html("templates/security.html")


@app.get("/student", response_class=HTMLResponse)
def student(request: Request):
    require_role(request, "student")
    return read_html("templates/student.html")

# -------------------------
# LOGIN
# -------------------------

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):

    doc = db.collection("users").document(username).get()

    if not doc.exists:
        return RedirectResponse("/", status_code=302)

    user = doc.to_dict()
    stored_password = user.get("password")

    if not stored_password:
        return RedirectResponse("/", status_code=302)

    if password != stored_password:
        return RedirectResponse("/", status_code=302)

    request.session["user"] = username
    request.session["role"] = user["role"]

    if user["role"] == "warden":
        return RedirectResponse("/warden", status_code=302)

    elif user["role"] == "security":
        return RedirectResponse("/security", status_code=302)

    elif user["role"] == "student":
        return RedirectResponse("/student", status_code=302)

    return RedirectResponse("/", status_code=302)

# -------------------------
# LOGOUT
# -------------------------

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")

# -------------------------
# CREATE USER
# -------------------------


@app.post("/api/create_user")
def create_user(user: UserCreate):

    db.collection("users").document(user.username).set({
        "username": user.username,
        "password": user.password,
        "role": user.role,
        "name": user.name,
        "room": user.room,
        "bed": user.bed,
        "photo": user.photo,   # store base64 image
        "created": datetime.utcnow()
    })

    return {"status": "user created"}
# -------------------------
# ADD STUDENT
# -------------------------

@app.post("/api/add_student")
def add_student(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    name: str = Form(...),
    room: str = Form(...),
    bed: str = Form(...),
    photo: str = Form(None)
):

    require_role(request, "warden")

    existing = db.collection("users").document(username).get()

    if existing.exists:
        raise HTTPException(status_code=400, detail="Username already exists")

    db.collection("users").document(username).set({
        "username": username,
        "password": password,
        "role": "student",
        "name": name,
        "room": room,
        "bed": bed,
        "photo": photo,   # save base64 image
        "created": datetime.utcnow()
    })

    return {"status": "student added"}
# -------------------------
# GET STUDENTS
# -------------------------

@app.get("/api/students")
def get_students(request: Request):

    require_role(request, "warden")

    docs = db.collection("users").where("role", "==", "student").stream()

    students = []

    for doc in docs:
        data = doc.to_dict()

        students.append({
            "id": doc.id,
            "name": data.get("name"),
            "room": data.get("room"),
            "bed": data.get("bed"),
            "username": data.get("username"),
            "photo": data.get("photo")   # return photo
        })

    return students
# -------------------------
# CREATE ROOM
# -------------------------





@app.post("/api/add_security")
def add_security(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    name: str = Form(...),
    shift: str = Form(...)
):

    require_role(request, "warden")

 
  
    db.collection("users").document(username).set({
        "username": username,
        "password": password,
        "role": "security",
        "name": name,
        "shift": shift,
        "created": datetime.utcnow()
    })

    return {"status": "security added"}

@app.get("/api/security_staff")
def get_security(request: Request):

    require_role(request, "warden")

    docs = db.collection("users").where("role","==","security").stream()

    guards = []

    for doc in docs:
        data = doc.to_dict()

        guards.append({
            "username": data.get("username"),
            "name": data.get("name"),
            "shift": data.get("shift")
        })

    return guards




@app.post("/api/create_room")
def create_room(room: RoomCreate):

    db.collection("rooms").document(room.room_number).set({
        "A": room.bedA,
        "B": room.bedB,
        "C": room.bedC,
        "D": room.bedD,
        "E": room.bedE
    })

    return {"status":"room created"}
# -------------------------
# GET ROOMS
# -------------------------

@app.get("/api/rooms")
def get_rooms():

    docs = db.collection("rooms").stream()

    rooms = []

    for doc in docs:
        data = doc.to_dict()
        data["room"] = doc.id
        rooms.append(data)

    return rooms

# -------------------------
# STUDENT REQUEST LEAVE
# -------------------------

@app.post("/api/request")
def request_leave(req: LeaveRequest, request: Request):

    require_role(request, "student")

    db.collection("leave_requests").add({
        "student": req.student,
        "room": req.room,
        "reason": req.reason,
        "status": "pending",
        "created": datetime.utcnow()
    })

    return {"status": "submitted"}

# -------------------------
# GET REQUESTS
# -------------------------

@app.get("/api/requests")
def get_requests(request: Request):

    require_role(request, "warden")

    docs = db.collection("leave_requests").stream()

    requests = []

    for doc in docs:
        data = doc.to_dict()

        requests.append({
            "id": doc.id,
            "student": data.get("student"),
            "room": data.get("room"),
            "reason": data.get("reason"),
            "status": data.get("status")
        })

    return requests
# -------------------------
# STUDENT VIEW THEIR REQUESTS
# -------------------------

@app.get("/api/my_requests")
def my_requests(request: Request):

    require_role(request, "student")

    username = request.session.get("user")

    docs = db.collection("leave_requests").where("student", "==", username).stream()

    requests = []

    for doc in docs:
        data = doc.to_dict()

        requests.append({
            "id": doc.id,
            "student": data.get("student"),
            "room": data.get("room"),
            "reason": data.get("reason"),
            "status": data.get("status"),
            "created": data.get("created")
        })

    return requests

@app.get("/api/me")
def me(request: Request):

    username = request.session.get("user")

    if not username:
        raise HTTPException(status_code=401)

    doc = db.collection("users").document(username).get()
    user = doc.to_dict()

    return {
        "username": username,
        "room": user.get("room"),
        "name": user.get("name"),
        "photo": user.get("photo")
    }
# -------------------------
# APPROVE REQUEST
# -------------------------

@app.post("/api/approve/{request_id}")
def approve_request(request_id: str, request: Request):

    require_role(request, "warden")

    ref = db.collection("leave_requests").document(request_id)

    ref.update({
        "status": "approved"
    })

    return {"status": "approved"}

# -------------------------
# REJECT REQUEST
# -------------------------

@app.post("/api/reject/{request_id}")
def reject_request(request_id: str, request: Request):

    require_role(request, "warden")

    db.collection("leave_requests").document(request_id).update({
        "status": "rejected"
    })

    return {"status": "rejected"}

# -------------------------
# SECURITY APPROVED LIST
# -------------------------

@app.get("/api/approved")
def approved_students(request: Request):

    require_role(request, "security")

    docs = db.collection("leave_requests").where("status", "==", "approved").stream()

    approved = []

    for doc in docs:

        data = doc.to_dict()

        student_username = data.get("student")

        # get student details
        user_doc = db.collection("users").document(student_username).get()

        user = user_doc.to_dict() if user_doc.exists else {}

        approved.append({
            "id": doc.id,
            "username": student_username,
            "name": user.get("name"),
            "room": data.get("room"),
            "reason": data.get("reason"),
            "photo": user.get("photo")
        })

    return approved
