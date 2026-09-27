from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional

from app.core.database import get_db
from app.core.security import verify_password, create_access_token
from app.models.models import User, UserRole
from app.schemas.schemas import LoginRequest, TokenResponse, UserResponse
from app.api.deps import get_current_user

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: LoginRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username o password errati",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Utente disabilitato"
        )
    
    user.last_login = datetime.utcnow()
    db.commit()
    
    access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
    
    # Set secure HttpOnly session cookie
    response.set_cookie(
        key="session_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=False,  # True in HTTPS production
        max_age=28800, # 8 hours
    )
    
    user_resp = UserResponse.from_orm(user)
    return TokenResponse(access_token=access_token, token_type="bearer", user=user_resp)


@router.post("/token", response_model=TokenResponse)
async def login_form(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    login_req = LoginRequest(username=form_data.username, password=form_data.password)
    return await login(login_req, response, db)


from fastapi.responses import RedirectResponse

@router.api_route("/logout", methods=["GET", "POST"])
async def logout(request: Request, response: Response):
    res = RedirectResponse(url="/login?logout=1", status_code=status.HTTP_303_SEE_OTHER)
    res.delete_cookie(key="session_token")
    return res


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return UserResponse.from_orm(current_user)


# User Administration Endpoints
from app.api.deps import require_role
from app.schemas.schemas import UserCreate, SourceRegistryCreate, SourceRegistryResponse
from app.models.models import SourceRegistry, SourceCategory
from app.core.security import hash_password
from typing import List


@router.get("/users", response_model=List[UserResponse], dependencies=[Depends(require_role([UserRole.ADMIN]))])
async def list_users(db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.id.asc()).all()
    return [UserResponse.from_orm(u) for u in users]


@router.post("/users", response_model=UserResponse, dependencies=[Depends(require_role([UserRole.ADMIN]))])
async def create_user_by_admin(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username o email già in uso")
    
    new_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role=user_in.role,
        is_active=user_in.is_active,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return UserResponse.from_orm(new_user)


@router.patch("/users/{user_id}/toggle-active", response_model=UserResponse, dependencies=[Depends(require_role([UserRole.ADMIN]))])
async def toggle_user_active(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    user.is_active = not user.is_active
    db.commit()
    db.refresh(user)
    return UserResponse.from_orm(user)


# Dynamic Source Registry Endpoints
@router.get("/sources", response_model=List[SourceRegistryResponse])
async def list_sources(category: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(SourceRegistry).filter(SourceRegistry.is_active == True)
    if category:
        query = query.filter(SourceRegistry.category == category)
    sources = query.order_by(SourceRegistry.name.asc()).all()
    return [SourceRegistryResponse.from_orm(s) for s in sources]


@router.post("/sources", response_model=SourceRegistryResponse, dependencies=[Depends(require_role([UserRole.ADMIN]))])
async def add_source(source_in: SourceRegistryCreate, db: Session = Depends(get_db)):
    existing = db.query(SourceRegistry).filter(SourceRegistry.code == source_in.code).first()
    if existing:
        raise HTTPException(status_code=400, detail="Codice fonte già esistente")
    
    cat_enum = SourceCategory.CVE
    if source_in.category.lower() == "feed":
        cat_enum = SourceCategory.FEED
    elif source_in.category.lower() == "ioc":
        cat_enum = SourceCategory.IOC

    new_source = SourceRegistry(
        code=source_in.code,
        name=source_in.name,
        category=cat_enum,
        base_url=source_in.base_url,
        description=source_in.description,
        is_active=True,
        is_builtin=False,
    )
    db.add(new_source)
    db.commit()
    db.refresh(new_source)
    return SourceRegistryResponse.from_orm(new_source)
