from fastapi import FastAPI, Request, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, List
import firebase_admin
from firebase_admin import credentials, firestore
import secrets
import os
import json

# -------------------------
# Firebase Setup
# -------------------------

if not firebase_admin._apps:
    firebase_key = os.environ.get("FIREBASE_KEY")
    cred = credentials.Certificate(json.loads(firebase_key))
    firebase_admin.initialize_app(cred)

db = firestore.client()

# -------------------------
# FastAPI Setup
# -------------------------

app = FastAPI(title="Hostel Management System", version="2.0.0")

app.add_middleware(
    SessionMiddleware,
    secret_key=secrets.token_hex(32)
)

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
    photo: str | None = None

class LeaveRequest(BaseModel):
    student: str
    room: str
    reason: str
    from_date: str | None = None
    to_date: str | None = None

class RoomCreate(BaseModel):
    room_number: str
    floor: str | None = None
    block: str | None = None
    bedA: str
    bedB: str
    bedC: str | None = None
    bedD: str | None = None
    bedE: str | None = None

class AnnouncementCreate(BaseModel):
    title: str
    message: str
    priority: str = "normal"   # normal | urgent | info

class ComplaintCreate(BaseModel):
    category: str             # maintenance | food | security | other
    description: str
    room: str | None = None

class VisitorLog(BaseModel):
    visitor_name: str
    visitor_phone: str
    student_username: str
    purpose: str

class AttendanceRecord(BaseModel):
    student_username: str
    date: str
    present: bool
    note: str | None = None

class NoticeCreate(BaseModel):
    title: str
    body: str
    target_role: str = "all"   # all | student | security

class FeeRecord(BaseModel):
    student_username: str
    amount: float
    month: str
    description: str | None = None

# -------------------------
# Role Security
# -------------------------

def require_role(request: Request, role: str):
    if request.session.get("role") != role:
        raise HTTPException(status_code=403, detail="Unauthorized")

def require_any_role(request: Request, roles: list):
    if request.session.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Unauthorized")

def get_current_user(request: Request):
    username = request.session.get("user")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return username

# -------------------------
# Helper
# -------------------------

def read_html(path):
    if not os.path.exists(path):
        raise HTTPException(status_code=500, detail=f"Missing template: {path}")
    return open(path, encoding="utf-8").read()

def log_activity(action: str, performed_by: str, target: str = None, details: dict = None):
    """Log all warden/security actions for audit trail."""
    db.collection("activity_logs").add({
        "action": action,
        "performed_by": performed_by,
        "target": target,
        "details": details or {},
        "timestamp": datetime.utcnow()
    })

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
        return RedirectResponse("/?error=invalid", status_code=302)
    user = doc.to_dict()
    stored_password = user.get("password")
    if not stored_password or password != stored_password:
        return RedirectResponse("/?error=invalid", status_code=302)

    request.session["user"] = username
    request.session["role"] = user["role"]

    # Update last login
    db.collection("users").document(username).update({
        "last_login": datetime.utcnow()
    })

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
# CREATE USER (API utility)
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
        "photo": user.photo,
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
    phone: str = Form(None),
    email: str = Form(None),
    guardian_name: str = Form(None),
    guardian_phone: str = Form(None),
    photo: str = Form(None)
):
    require_role(request, "warden")
    existing = db.collection("users").document(username).get()
    if existing.exists:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Check if room+bed is already occupied
    occupants = db.collection("users").where("room", "==", room).where("bed", "==", bed).where("role", "==", "student").stream()
    for _ in occupants:
        raise HTTPException(status_code=400, detail=f"Room {room} Bed {bed} is already occupied")

    db.collection("users").document(username).set({
        "username": username,
        "password": password,
        "role": "student",
        "name": name,
        "room": room,
        "bed": bed,
        "phone": phone,
        "email": email,
        "guardian_name": guardian_name,
        "guardian_phone": guardian_phone,
        "photo": photo,
        "status": "active",
        "created": datetime.utcnow()
    })

    # Update room bed occupancy
    bed_key = f"occupant_{bed}"
    db.collection("rooms").document(room).update({bed_key: username})

    log_activity("add_student", request.session.get("user"), username, {"room": room, "bed": bed})
    return {"status": "student added"}

# -------------------------
# DELETE STUDENT
# -------------------------

@app.delete("/api/student/{username}")
def delete_student(username: str, request: Request):
    require_role(request, "warden")
    doc = db.collection("users").document(username).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Student not found")

    user = doc.to_dict()
    room = user.get("room")
    bed = user.get("bed")

    # Clear room bed occupancy
    if room and bed:
        bed_key = f"occupant_{bed}"
        db.collection("rooms").document(room).update({bed_key: None})

    # Archive before delete
    db.collection("archived_students").document(username).set({
        **user,
        "archived_at": datetime.utcnow(),
        "archived_by": request.session.get("user")
    })

    db.collection("users").document(username).delete()
    log_activity("delete_student", request.session.get("user"), username, {"room": room, "bed": bed})
    return {"status": "student deleted"}

# -------------------------
# UPDATE STUDENT (by warden)
# -------------------------

@app.put("/api/student/{username}")
def update_student(
    username: str,
    request: Request,
    name: str = Form(None),
    room: str = Form(None),
    bed: str = Form(None),
    phone: str = Form(None),
    email: str = Form(None),
    guardian_name: str = Form(None),
    guardian_phone: str = Form(None),
    status: str = Form(None)   # active | suspended | graduated
):
    require_role(request, "warden")
    doc = db.collection("users").document(username).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Student not found")

    old_data = doc.to_dict()
    update_data = {}
    if name: update_data["name"] = name
    if phone: update_data["phone"] = phone
    if email: update_data["email"] = email
    if guardian_name: update_data["guardian_name"] = guardian_name
    if guardian_phone: update_data["guardian_phone"] = guardian_phone
    if status: update_data["status"] = status

    # Handle room/bed reassignment
    if room and bed and (room != old_data.get("room") or bed != old_data.get("bed")):
        # Check new bed not occupied
        occupants = db.collection("users").where("room", "==", room).where("bed", "==", bed).where("role", "==", "student").stream()
        for _ in occupants:
            raise HTTPException(status_code=400, detail=f"Room {room} Bed {bed} is already occupied")

        # Free old bed
        if old_data.get("room") and old_data.get("bed"):
            old_bed_key = f"occupant_{old_data['bed']}"
            db.collection("rooms").document(old_data["room"]).update({old_bed_key: None})

        # Occupy new bed
        new_bed_key = f"occupant_{bed}"
        db.collection("rooms").document(room).update({new_bed_key: username})
        update_data["room"] = room
        update_data["bed"] = bed

    db.collection("users").document(username).update(update_data)
    log_activity("update_student", request.session.get("user"), username, update_data)
    return {"status": "student updated"}

# -------------------------
# GET STUDENTS
# -------------------------

@app.get("/api/students")
def get_students(request: Request, status: str = Query(None), room: str = Query(None)):
    require_role(request, "warden")
    query = db.collection("users").where("role", "==", "student")
    if status:
        query = query.where("status", "==", status)
    docs = query.stream()
    students = []
    for doc in docs:
        data = doc.to_dict()
        if room and data.get("room") != room:
            continue
        students.append({
            "id": doc.id,
            "name": data.get("name"),
            "room": data.get("room"),
            "bed": data.get("bed"),
            "username": data.get("username"),
            "phone": data.get("phone"),
            "email": data.get("email"),
            "guardian_name": data.get("guardian_name"),
            "guardian_phone": data.get("guardian_phone"),
            "status": data.get("status", "active"),
            "last_login": str(data.get("last_login", "")),
            "photo": data.get("photo")
        })
    return students

# -------------------------
# GET STUDENT BY ROOM + BED
# -------------------------

@app.get("/api/room/{room_number}/bed/{bed_code}")
def get_student_by_room_bed(room_number: str, bed_code: str, request: Request):
    require_any_role(request, ["warden", "security"])
    docs = db.collection("users")\
        .where("role", "==", "student")\
        .where("room", "==", room_number)\
        .where("bed", "==", bed_code.upper())\
        .stream()
    for doc in docs:
        data = doc.to_dict()
        return {
            "username": doc.id,
            "name": data.get("name"),
            "room": data.get("room"),
            "bed": data.get("bed"),
            "phone": data.get("phone"),
            "email": data.get("email"),
            "guardian_name": data.get("guardian_name"),
            "guardian_phone": data.get("guardian_phone"),
            "status": data.get("status", "active"),
            "photo": data.get("photo")
        }
    raise HTTPException(status_code=404, detail="No student found in this room/bed")

# -------------------------
# ROOM OCCUPANCY MAP
# -------------------------

@app.get("/api/rooms/occupancy")
def rooms_occupancy(request: Request):
    require_any_role(request, ["warden", "security"])
    room_docs = db.collection("rooms").stream()
    result = []
    for rdoc in room_docs:
        room_data = rdoc.to_dict()
        room_id = rdoc.id
        beds = {}
        for bed_code in ["A", "B", "C", "D", "E"]:
            occupant_username = room_data.get(f"occupant_{bed_code}")
            if room_data.get(bed_code) is not None or occupant_username:  # bed exists in room
                if occupant_username:
                    udoc = db.collection("users").document(occupant_username).get()
                    if udoc.exists:
                        udata = udoc.to_dict()
                        beds[bed_code] = {
                            "username": occupant_username,
                            "name": udata.get("name"),
                            "photo": udata.get("photo"),
                            "status": udata.get("status", "active")
                        }
                    else:
                        beds[bed_code] = None
                else:
                    beds[bed_code] = None  # empty bed
        result.append({
            "room": room_id,
            "floor": room_data.get("floor"),
            "block": room_data.get("block"),
            "beds": beds,
            "total_beds": len(beds),
            "occupied": sum(1 for v in beds.values() if v is not None),
            "available": sum(1 for v in beds.values() if v is None)
        })
    return result

# -------------------------
# ADD SECURITY
# -------------------------

@app.post("/api/add_security")
def add_security(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    name: str = Form(...),
    shift: str = Form(...),
    phone: str = Form(None)
):
    require_role(request, "warden")
    db.collection("users").document(username).set({
        "username": username,
        "password": password,
        "role": "security",
        "name": name,
        "shift": shift,
        "phone": phone,
        "created": datetime.utcnow()
    })
    log_activity("add_security", request.session.get("user"), username)
    return {"status": "security added"}

@app.get("/api/security_staff")
def get_security(request: Request):
    require_role(request, "warden")
    docs = db.collection("users").where("role", "==", "security").stream()
    guards = []
    for doc in docs:
        data = doc.to_dict()
        guards.append({
            "username": data.get("username"),
            "name": data.get("name"),
            "shift": data.get("shift"),
            "phone": data.get("phone"),
            "last_login": str(data.get("last_login", ""))
        })
    return guards

@app.delete("/api/security/{username}")
def delete_security(username: str, request: Request):
    require_role(request, "warden")
    db.collection("users").document(username).delete()
    log_activity("delete_security", request.session.get("user"), username)
    return {"status": "security deleted"}

# -------------------------
# CREATE ROOM
# -------------------------

@app.post("/api/create_room")
def create_room(room: RoomCreate, request: Request):
    require_role(request, "warden")
    db.collection("rooms").document(room.room_number).set({
        "A": room.bedA,
        "B": room.bedB,
        "C": room.bedC,
        "D": room.bedD,
        "E": room.bedE,
        "floor": room.floor,
        "block": room.block,
        "occupant_A": None,
        "occupant_B": None,
        "occupant_C": None,
        "occupant_D": None,
        "occupant_E": None
    })
    log_activity("create_room", request.session.get("user"), room.room_number)
    return {"status": "room created"}

@app.delete("/api/room/{room_number}")
def delete_room(room_number: str, request: Request):
    require_role(request, "warden")
    # Check if room has occupants
    occupants = db.collection("users").where("room", "==", room_number).where("role", "==", "student").stream()
    for _ in occupants:
        raise HTTPException(status_code=400, detail="Cannot delete room with active occupants")
    db.collection("rooms").document(room_number).delete()
    log_activity("delete_room", request.session.get("user"), room_number)
    return {"status": "room deleted"}

# -------------------------
# GET ROOMS
# -------------------------

@app.get("/api/rooms")
def get_rooms(request: Request):
    require_any_role(request, ["warden", "security"])
    docs = db.collection("rooms").stream()
    rooms = []
    for doc in docs:
        data = doc.to_dict()
        data["room"] = doc.id
        rooms.append(data)
    return rooms

# -------------------------
# UPDATE STUDENT PROFILE (by student)
# -------------------------

@app.post("/api/update_profile")
def update_profile(
    request: Request,
    name: str = Form(...),
    phone: str = Form(None),
    photo: str = Form(None)
):
    require_role(request, "student")
    username = request.session.get("user")
    if not username:
        raise HTTPException(status_code=401)
    update_data = {"name": name}
    if phone:
        update_data["phone"] = phone
    if photo:
        update_data["photo"] = photo
    db.collection("users").document(username).update(update_data)
    return {"status": "profile updated"}

# -------------------------
# STUDENT REQUEST LEAVE
# -------------------------

@app.post("/api/request")
def request_leave(req: LeaveRequest, request: Request):
    require_role(request, "student")
    username = request.session.get("user")
    db.collection("leave_requests").add({
        "student": req.student,
        "room": req.room,
        "reason": req.reason,
        "from_date": req.from_date,
        "to_date": req.to_date,
        "status": "pending",
        "created": datetime.utcnow(),
        "last_updated": datetime.utcnow()
    })
    return {"status": "submitted"}

# -------------------------
# GET ALL REQUESTS (warden)
# -------------------------

@app.get("/api/requests")
def get_requests(request: Request, status: str = Query(None)):
    require_role(request, "warden")
    query = db.collection("leave_requests")
    if status:
        query = query.where("status", "==", status)
    docs = query.stream()
    requests_list = []
    for doc in docs:
        data = doc.to_dict()
        # Enrich with student info
        student_username = data.get("student")
        user_doc = db.collection("users").document(student_username).get()
        user = user_doc.to_dict() if user_doc.exists else {}
        requests_list.append({
            "id": doc.id,
            "student": student_username,
            "student_name": user.get("name"),
            "room": data.get("room"),
            "bed": user.get("bed"),
            "reason": data.get("reason"),
            "from_date": data.get("from_date"),
            "to_date": data.get("to_date"),
            "status": data.get("status"),
            "created": str(data.get("created", "")),
            "warden_note": data.get("warden_note"),
            "photo": user.get("photo")
        })
    return requests_list

# -------------------------
# SECURITY: VIEW PENDING + APPROVED REQUESTS
# -------------------------

@app.get("/api/security/requests")
def security_get_requests(request: Request, status: str = Query(None)):
    require_role(request, "security")
    query = db.collection("leave_requests")
    if status:
        query = query.where("status", "==", status)
    docs = query.stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        student_username = data.get("student")
        user_doc = db.collection("users").document(student_username).get()
        user = user_doc.to_dict() if user_doc.exists else {}
        result.append({
            "id": doc.id,
            "student": student_username,
            "student_name": user.get("name"),
            "room": data.get("room"),
            "bed": user.get("bed"),
            "reason": data.get("reason"),
            "from_date": data.get("from_date"),
            "to_date": data.get("to_date"),
            "status": data.get("status"),
            "created": str(data.get("created", "")),
            "photo": user.get("photo")
        })
    return result

# -------------------------
# SECURITY: MARK STUDENT EXIT/ENTRY
# -------------------------

@app.post("/api/security/gate_log")
def gate_log(
    request: Request,
    leave_request_id: str = Form(...),
    action: str = Form(...),   # exit | entry
    note: str = Form(None)
):
    require_role(request, "security")
    ref = db.collection("leave_requests").document(leave_request_id)
    doc = ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Leave request not found")

    data = doc.to_dict()
    if data.get("status") != "approved":
        raise HTTPException(status_code=400, detail="Can only log gate activity for approved requests")

    gate_field = "exit_time" if action == "exit" else "entry_time"
    ref.update({
        gate_field: datetime.utcnow(),
        f"gate_note_{action}": note,
        "gate_logged_by": request.session.get("user")
    })

    # Log in dedicated gate log
    db.collection("gate_logs").add({
        "leave_request_id": leave_request_id,
        "student": data.get("student"),
        "action": action,
        "logged_by": request.session.get("user"),
        "note": note,
        "timestamp": datetime.utcnow()
    })

    log_activity(f"gate_{action}", request.session.get("user"), data.get("student"), {"leave_request_id": leave_request_id})
    return {"status": f"{action} logged"}

# -------------------------
# STUDENT VIEW THEIR REQUESTS
# -------------------------

@app.get("/api/my_requests")
def my_requests(request: Request):
    require_role(request, "student")
    username = request.session.get("user")
    docs = db.collection("leave_requests").where("student", "==", username).stream()
    requests_list = []
    for doc in docs:
        data = doc.to_dict()
        requests_list.append({
            "id": doc.id,
            "student": data.get("student"),
            "room": data.get("room"),
            "reason": data.get("reason"),
            "from_date": data.get("from_date"),
            "to_date": data.get("to_date"),
            "status": data.get("status"),
            "warden_note": data.get("warden_note"),
            "created": str(data.get("created", ""))
        })
    return requests_list

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
        "bed": user.get("bed"),
        "name": user.get("name"),
        "phone": user.get("phone"),
        "email": user.get("email"),
        "guardian_name": user.get("guardian_name"),
        "guardian_phone": user.get("guardian_phone"),
        "role": user.get("role"),
        "status": user.get("status", "active"),
        "photo": user.get("photo")
    }

# -------------------------
# APPROVE / REJECT REQUEST
# -------------------------

@app.post("/api/approve/{request_id}")
def approve_request(request_id: str, request: Request, note: str = Form(None)):
    require_role(request, "warden")
    ref = db.collection("leave_requests").document(request_id)
    ref.update({
        "status": "approved",
        "warden_note": note,
        "approved_by": request.session.get("user"),
        "last_updated": datetime.utcnow()
    })
    log_activity("approve_request", request.session.get("user"), request_id)
    return {"status": "approved"}

@app.post("/api/reject/{request_id}")
def reject_request(request_id: str, request: Request, note: str = Form(None)):
    require_role(request, "warden")
    db.collection("leave_requests").document(request_id).update({
        "status": "rejected",
        "warden_note": note,
        "rejected_by": request.session.get("user"),
        "last_updated": datetime.utcnow()
    })
    log_activity("reject_request", request.session.get("user"), request_id)
    return {"status": "rejected"}

# -------------------------
# SECURITY: APPROVED LIST (original route preserved)
# -------------------------

@app.get("/api/approved")
def approved_students(request: Request):
    require_role(request, "security")
    docs = db.collection("leave_requests").where("status", "==", "approved").stream()
    approved = []
    for doc in docs:
        data = doc.to_dict()
        student_username = data.get("student")
        user_doc = db.collection("users").document(student_username).get()
        user = user_doc.to_dict() if user_doc.exists else {}
        approved.append({
            "id": doc.id,
            "username": student_username,
            "name": user.get("name"),
            "room": data.get("room"),
            "bed": user.get("bed"),
            "reason": data.get("reason"),
            "from_date": data.get("from_date"),
            "to_date": data.get("to_date"),
            "exit_time": str(data.get("exit_time", "")),
            "entry_time": str(data.get("entry_time", "")),
            "photo": user.get("photo")
        })
    return approved

# -------------------------
# ANNOUNCEMENTS
# -------------------------

@app.post("/api/announcements")
def create_announcement(ann: AnnouncementCreate, request: Request):
    require_role(request, "warden")
    db.collection("announcements").add({
        "title": ann.title,
        "message": ann.message,
        "priority": ann.priority,
        "created_by": request.session.get("user"),
        "created": datetime.utcnow(),
        "active": True
    })
    return {"status": "announcement posted"}

@app.get("/api/announcements")
def get_announcements(request: Request):
    require_any_role(request, ["warden", "student", "security"])
    docs = db.collection("announcements").where("active", "==", True).stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        result.append({
            "id": doc.id,
            "title": data.get("title"),
            "message": data.get("message"),
            "priority": data.get("priority"),
            "created": str(data.get("created", ""))
        })
    return sorted(result, key=lambda x: x["created"], reverse=True)

@app.delete("/api/announcements/{ann_id}")
def delete_announcement(ann_id: str, request: Request):
    require_role(request, "warden")
    db.collection("announcements").document(ann_id).update({"active": False})
    return {"status": "announcement removed"}

# -------------------------
# COMPLAINTS
# -------------------------

@app.post("/api/complaint")
def raise_complaint(comp: ComplaintCreate, request: Request):
    require_role(request, "student")
    username = request.session.get("user")
    user_doc = db.collection("users").document(username).get()
    user = user_doc.to_dict()
    db.collection("complaints").add({
        "student": username,
        "student_name": user.get("name"),
        "room": comp.room or user.get("room"),
        "category": comp.category,
        "description": comp.description,
        "status": "open",
        "created": datetime.utcnow()
    })
    return {"status": "complaint raised"}

@app.get("/api/complaints")
def get_complaints(request: Request, status: str = Query(None), category: str = Query(None)):
    require_any_role(request, ["warden", "security"])
    query = db.collection("complaints")
    if status:
        query = query.where("status", "==", status)
    if category:
        query = query.where("category", "==", category)
    docs = query.stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        result.append({
            "id": doc.id,
            "student": data.get("student"),
            "student_name": data.get("student_name"),
            "room": data.get("room"),
            "category": data.get("category"),
            "description": data.get("description"),
            "status": data.get("status"),
            "resolution_note": data.get("resolution_note"),
            "created": str(data.get("created", ""))
        })
    return result

@app.get("/api/my_complaints")
def my_complaints(request: Request):
    require_role(request, "student")
    username = request.session.get("user")
    docs = db.collection("complaints").where("student", "==", username).stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        result.append({
            "id": doc.id,
            "category": data.get("category"),
            "description": data.get("description"),
            "status": data.get("status"),
            "resolution_note": data.get("resolution_note"),
            "created": str(data.get("created", ""))
        })
    return result

@app.post("/api/complaints/{complaint_id}/resolve")
def resolve_complaint(complaint_id: str, request: Request, note: str = Form(...)):
    require_role(request, "warden")
    db.collection("complaints").document(complaint_id).update({
        "status": "resolved",
        "resolution_note": note,
        "resolved_by": request.session.get("user"),
        "resolved_at": datetime.utcnow()
    })
    return {"status": "resolved"}

# -------------------------
# VISITOR MANAGEMENT
# -------------------------

@app.post("/api/visitors")
def log_visitor(visitor: VisitorLog, request: Request):
    require_role(request, "security")
    user_doc = db.collection("users").document(visitor.student_username).get()
    if not user_doc.exists:
        raise HTTPException(status_code=404, detail="Student not found")
    user = user_doc.to_dict()
    db.collection("visitors").add({
        "visitor_name": visitor.visitor_name,
        "visitor_phone": visitor.visitor_phone,
        "student_username": visitor.student_username,
        "student_name": user.get("name"),
        "student_room": user.get("room"),
        "purpose": visitor.purpose,
        "check_in": datetime.utcnow(),
        "check_out": None,
        "logged_by": request.session.get("user")
    })
    return {"status": "visitor logged"}

@app.post("/api/visitors/{visitor_id}/checkout")
def visitor_checkout(visitor_id: str, request: Request):
    require_role(request, "security")
    db.collection("visitors").document(visitor_id).update({
        "check_out": datetime.utcnow()
    })
    return {"status": "visitor checked out"}

@app.get("/api/visitors")
def get_visitors(request: Request, date: str = Query(None)):
    require_any_role(request, ["warden", "security"])
    docs = db.collection("visitors").stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        result.append({
            "id": doc.id,
            "visitor_name": data.get("visitor_name"),
            "visitor_phone": data.get("visitor_phone"),
            "student_name": data.get("student_name"),
            "student_room": data.get("student_room"),
            "purpose": data.get("purpose"),
            "check_in": str(data.get("check_in", "")),
            "check_out": str(data.get("check_out", ""))
        })
    return result

# -------------------------
# ATTENDANCE
# -------------------------

@app.post("/api/attendance")
def mark_attendance(att: AttendanceRecord, request: Request):
    require_any_role(request, ["warden", "security"])
    db.collection("attendance").document(f"{att.student_username}_{att.date}").set({
        "student_username": att.student_username,
        "date": att.date,
        "present": att.present,
        "note": att.note,
        "marked_by": request.session.get("user"),
        "marked_at": datetime.utcnow()
    })
    return {"status": "attendance marked"}

@app.get("/api/attendance")
def get_attendance(request: Request, date: str = Query(None), student: str = Query(None)):
    require_any_role(request, ["warden", "security"])
    query = db.collection("attendance")
    if date:
        query = query.where("date", "==", date)
    if student:
        query = query.where("student_username", "==", student)
    docs = query.stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        user_doc = db.collection("users").document(data.get("student_username", "")).get()
        user = user_doc.to_dict() if user_doc.exists else {}
        result.append({
            "student_username": data.get("student_username"),
            "student_name": user.get("name"),
            "room": user.get("room"),
            "bed": user.get("bed"),
            "date": data.get("date"),
            "present": data.get("present"),
            "note": data.get("note")
        })
    return result

@app.get("/api/my_attendance")
def my_attendance(request: Request):
    require_role(request, "student")
    username = request.session.get("user")
    docs = db.collection("attendance").where("student_username", "==", username).stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        result.append({
            "date": data.get("date"),
            "present": data.get("present"),
            "note": data.get("note")
        })
    return sorted(result, key=lambda x: x["date"], reverse=True)

# -------------------------
# NOTICES
# -------------------------

@app.post("/api/notices")
def post_notice(notice: NoticeCreate, request: Request):
    require_role(request, "warden")
    db.collection("notices").add({
        "title": notice.title,
        "body": notice.body,
        "target_role": notice.target_role,
        "posted_by": request.session.get("user"),
        "created": datetime.utcnow(),
        "active": True
    })
    return {"status": "notice posted"}

@app.get("/api/notices")
def get_notices(request: Request):
    role = request.session.get("role")
    if not role:
        raise HTTPException(status_code=401)
    docs = db.collection("notices").where("active", "==", True).stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        target = data.get("target_role", "all")
        if target == "all" or target == role:
            result.append({
                "id": doc.id,
                "title": data.get("title"),
                "body": data.get("body"),
                "created": str(data.get("created", ""))
            })
    return sorted(result, key=lambda x: x["created"], reverse=True)

# -------------------------
# FEE MANAGEMENT
# -------------------------

@app.post("/api/fees")
def record_fee(fee: FeeRecord, request: Request):
    require_role(request, "warden")
    user_doc = db.collection("users").document(fee.student_username).get()
    if not user_doc.exists:
        raise HTTPException(status_code=404, detail="Student not found")
    user = user_doc.to_dict()
    db.collection("fees").add({
        "student_username": fee.student_username,
        "student_name": user.get("name"),
        "room": user.get("room"),
        "amount": fee.amount,
        "month": fee.month,
        "description": fee.description,
        "paid_at": datetime.utcnow(),
        "recorded_by": request.session.get("user")
    })
    return {"status": "fee recorded"}

@app.get("/api/fees")
def get_fees(request: Request, student: str = Query(None), month: str = Query(None)):
    require_role(request, "warden")
    query = db.collection("fees")
    if student:
        query = query.where("student_username", "==", student)
    if month:
        query = query.where("month", "==", month)
    docs = query.stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        result.append({
            "id": doc.id,
            "student_username": data.get("student_username"),
            "student_name": data.get("student_name"),
            "room": data.get("room"),
            "amount": data.get("amount"),
            "month": data.get("month"),
            "description": data.get("description"),
            "paid_at": str(data.get("paid_at", ""))
        })
    return result

@app.get("/api/my_fees")
def my_fees(request: Request):
    require_role(request, "student")
    username = request.session.get("user")
    docs = db.collection("fees").where("student_username", "==", username).stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        result.append({
            "month": data.get("month"),
            "amount": data.get("amount"),
            "description": data.get("description"),
            "paid_at": str(data.get("paid_at", ""))
        })
    return sorted(result, key=lambda x: x["month"], reverse=True)

# -------------------------
# DASHBOARD STATS (warden)
# -------------------------

@app.get("/api/dashboard/stats")
def dashboard_stats(request: Request):
    require_role(request, "warden")
    students = list(db.collection("users").where("role", "==", "student").stream())
    active_students = [s for s in students if s.to_dict().get("status", "active") == "active"]
    security_staff = list(db.collection("users").where("role", "==", "security").stream())
    rooms = list(db.collection("rooms").stream())
    pending_leaves = list(db.collection("leave_requests").where("status", "==", "pending").stream())
    approved_leaves = list(db.collection("leave_requests").where("status", "==", "approved").stream())
    open_complaints = list(db.collection("complaints").where("status", "==", "open").stream())
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    today_visitors = list(db.collection("visitors").stream())  # filtered below

    return {
        "total_students": len(students),
        "active_students": len(active_students),
        "total_security": len(security_staff),
        "total_rooms": len(rooms),
        "pending_leave_requests": len(pending_leaves),
        "approved_leave_requests": len(approved_leaves),
        "open_complaints": len(open_complaints),
        "today_visitors": len([v for v in today_visitors if today_str in str(v.to_dict().get("check_in", ""))])
    }

# -------------------------
# ACTIVITY LOG (warden audit)
# -------------------------

@app.get("/api/activity_logs")
def get_activity_logs(request: Request, limit: int = Query(50)):
    require_role(request, "warden")
    docs = db.collection("activity_logs").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit).stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        result.append({
            "action": data.get("action"),
            "performed_by": data.get("performed_by"),
            "target": data.get("target"),
            "details": data.get("details"),
            "timestamp": str(data.get("timestamp", ""))
        })
    return result

# -------------------------
# GATE LOG HISTORY
# -------------------------

@app.get("/api/gate_logs")
def get_gate_logs(request: Request, student: str = Query(None)):
    require_any_role(request, ["warden", "security"])
    query = db.collection("gate_logs")
    if student:
        query = query.where("student", "==", student)
    docs = query.order_by("timestamp", direction=firestore.Query.DESCENDING).limit(100).stream()
    result = []
    for doc in docs:
        data = doc.to_dict()
        user_doc = db.collection("users").document(data.get("student", "")).get()
        user = user_doc.to_dict() if user_doc.exists else {}
        result.append({
            "id": doc.id,
            "student": data.get("student"),
            "student_name": user.get("name"),
            "room": user.get("room"),
            "action": data.get("action"),
            "logged_by": data.get("logged_by"),
            "note": data.get("note"),
            "timestamp": str(data.get("timestamp", ""))
        })
    return result

# -------------------------
# SEARCH (warden global search)
# -------------------------

@app.get("/api/search")
def global_search(request: Request, q: str = Query(...)):
    require_role(request, "warden")
    results = {"students": [], "rooms": []}
    q_lower = q.lower().strip()

    # Search students by name, username, room, bed
    students = db.collection("users").where("role", "==", "student").stream()
    for doc in students:
        data = doc.to_dict()
        searchable = " ".join(filter(None, [
            data.get("name", ""), data.get("username", ""),
            data.get("room", ""), data.get("bed", ""),
            data.get("phone", ""), data.get("email", "")
        ])).lower()
        if q_lower in searchable:
            results["students"].append({
                "username": doc.id,
                "name": data.get("name"),
                "room": data.get("room"),
                "bed": data.get("bed"),
                "phone": data.get("phone"),
                "status": data.get("status", "active"),
                "photo": data.get("photo")
            })

    # Search rooms
    if q_lower:
        rooms = db.collection("rooms").stream()
        for doc in rooms:
            if q_lower in doc.id.lower():
                data = doc.to_dict()
                data["room"] = doc.id
                results["rooms"].append(data)

    return results
