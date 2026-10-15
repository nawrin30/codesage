import json
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from .config import settings
from .db import Base, engine, get_db
from .models import User, Review
from .schemas import AuthInput, TokenOut, UserOut, AnalyzeInput
from .auth import hash_password, verify_password, create_token, current_user
from .analyzer import analyze_python

Base.metadata.create_all(bind=engine)
app = FastAPI(title="CodeSage AI API", version="1.0.0", description="Python static code review API")
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.cors_origins.split(",")],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/api/health")
def health():
    return {"status": "ok", "analyzer": "static", "ai_configured": bool(settings.openai_api_key)}

@app.post("/api/auth/register", response_model=TokenOut, status_code=201)
def register(payload: AuthInput, db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "An account with this email already exists.")
    user = User(email=email, password_hash=hash_password(payload.password))
    db.add(user); db.commit(); db.refresh(user)
    return {"access_token": create_token(user.id), "user": {"id": user.id, "email": user.email}}

@app.post("/api/auth/login", response_model=TokenOut)
def login(payload: AuthInput, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == str(payload.email).lower()))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Email or password is incorrect.")
    return {"access_token": create_token(user.id), "user": {"id": user.id, "email": user.email}}

@app.get("/api/auth/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email}

def serialize_review(r: Review):
    return {"id": r.id, "title": r.title, "created_at": r.created_at.isoformat(),
            "findings": json.loads(r.findings_json), "code": r.source_code}

@app.post("/api/reviews")
def create_review(payload: AnalyzeInput, db: Session = Depends(get_db), user: User = Depends(current_user)):
    findings = analyze_python(payload.code)
    review = Review(user_id=user.id, title=payload.title.strip() or "Untitled review",
                    source_code=payload.code, findings_json=json.dumps(findings))
    db.add(review); db.commit(); db.refresh(review)
    return serialize_review(review)

@app.get("/api/reviews")
def list_reviews(q: str = "", limit: int = 50, offset: int = 0, db: Session = Depends(get_db), user: User = Depends(current_user)):
    limit = max(1, min(limit, 100)); offset = max(0, offset)
    query = select(Review).where(Review.user_id == user.id)
    if q.strip(): query = query.where(Review.title.ilike(f"%{q.strip()}%"))
    rows = db.scalars(query.order_by(Review.created_at.desc()).offset(offset).limit(limit)).all()
    return [{"id": r.id, "title": r.title, "created_at": r.created_at.isoformat(),
             "findings": json.loads(r.findings_json), "finding_count": len(json.loads(r.findings_json))} for r in rows]

@app.get("/api/reviews/{review_id}")
def get_review(review_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = db.get(Review, review_id)
    if not r or r.user_id != user.id: raise HTTPException(404, "Review not found.")
    return serialize_review(r)

@app.delete("/api/reviews/{review_id}", status_code=204)
def delete_review(review_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = db.get(Review, review_id)
    if not r or r.user_id != user.id: raise HTTPException(404, "Review not found.")
    db.delete(r); db.commit()
    return Response(status_code=204)

@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.scalars(select(Review).where(Review.user_id == user.id).order_by(Review.created_at.desc())).all()
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in rows:
        for f in json.loads(r.findings_json):
            if f.get("severity") in counts: counts[f["severity"]] += 1
    return {"total_reviews": len(rows), "severity_counts": counts,
            "recent_reviews": [{"id": r.id, "title": r.title, "created_at": r.created_at.isoformat(),
                                "finding_count": len(json.loads(r.findings_json))} for r in rows[:5]]}

@app.get("/api/reviews/{review_id}/export")
def export_review(review_id: int, format: str = "json", db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = db.get(Review, review_id)
    if not r or r.user_id != user.id: raise HTTPException(404, "Review not found.")
    findings = json.loads(r.findings_json)
    if format == "json":
        return {"title": r.title, "created_at": r.created_at.isoformat(), "findings": findings, "code": r.source_code}
    if format == "markdown":
        lines = [f"# {r.title}", "", f"Reviewed: {r.created_at.isoformat()}", "", f"Findings: {len(findings)}", ""]
        for f in findings:
            lines += [f"## [{f['severity']}] {f['title']}", "", f"- Rule: `{f['rule_id']}`",
                      f"- Line: {f['line']}", f"- Source: {f['source']}", "", f["explanation"], "",
                      f"**Suggested fix:** {f['suggested_fix']}", ""]
        return Response("\n".join(lines), media_type="text/markdown",
                        headers={"Content-Disposition": 'attachment; filename="codesage-review.md"'})
    raise HTTPException(400, "format must be json or markdown")
