from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional

from app.core.database import get_db
from app.core.security import verify_password, create_access_token
from app.models.models import User
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


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="session_token")
    return {"message": "Logout effettuato con successo"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return UserResponse.from_orm(current_user)
