from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from typing import Optional, List, Callable

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.models import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


async def get_current_user_optional(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Retrieves current authenticated user if present (via Bearer token or session cookie)."""
    auth_token = token
    if not auth_token:
        auth_token = request.cookies.get("session_token")
    
    if not auth_token:
        return None
    
    payload = decode_access_token(auth_token)
    if not payload:
        return None
    
    username: str = payload.get("sub")
    if not username:
        return None
    
    user = db.query(User).filter(User.username == username).first()
    return user


async def get_current_user(
    request: Request,
    user: Optional[User] = Depends(get_current_user_optional)
) -> User:
    """Retrieves authenticated user or raises HTTP 401."""
    if not user or not user.is_active:
        if request.headers.get("hx-request"):
            response = HTMLResponse(status_code=status.HTTP_401_UNAUTHORIZED)
            response.headers["HX-Redirect"] = "/login"
            return response
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenziali di autenticazione non valide o non fornite",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


def require_role(allowed_roles: List[UserRole]) -> Callable:
    """Dependency factory enforcing RBAC roles."""
    async def role_checker(
        request: Request,
        current_user: Optional[User] = Depends(get_current_user_optional)
    ) -> User:
        if not current_user or not current_user.is_active:
            if request.headers.get("hx-request"):
                response = HTMLResponse(status_code=status.HTTP_401_UNAUTHORIZED)
                response.headers["HX-Redirect"] = "/login"
                return response
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenziali di autenticazione non valide o non fornite",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        if current_user.role not in allowed_roles:
            if request.headers.get("hx-request"):
                response = HTMLResponse("Accesso negato: permessi insufficienti", status_code=status.HTTP_403_FORBIDDEN)
                return response
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permessi insufficienti. Ruoli consentiti: {[r.value for r in allowed_roles]}"
            )
        return current_user
    
    return role_checker
