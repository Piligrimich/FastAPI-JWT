from http import HTTPStatus
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.api.usersDirectory.schemas import UserLogin, UserCreate, EditUser
from src.services import UserService, get_user_service

from src.services.auth import Auth


router = APIRouter()

auth_handler = Auth()
security = HTTPBearer()


@router.post(path="/signup", status_code=201, tags=['user'])
def signup(
        user_details: UserCreate, user_service: UserService = Depends(get_user_service)
) -> dict:
    user: dict = user_service.create_user(user=user_details)
    return {"msg": "User created.",
             "user": user
            }


@router.post(path="/login", tags=['user'])
def login(user: UserLogin, user_service: UserService = Depends(get_user_service)):
    user_task: Optional[dict] = user_service.login_user(username=user.username, password=user.password)
    return user_task


@router.post('/refresh', tags=['user'])
def refresh_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    refresh_token = credentials.credentials
    new_token = auth_handler.refresh_token(refresh_token)
    return new_token


@router.get('/users/me', tags=['user'])
def profile(
        user_service: UserService = Depends(get_user_service), credentials: HTTPAuthorizationCredentials = Security(security)
):
    token = credentials.credentials
    user_uuid = auth_handler.decode_token(token)
    if (user_uuid):
        user: dict = user_service.get_user_profile(user_uuid)
        return {'user': user}


@router.patch('/users/me', tags=['user'])
def profile(
        user_details: EditUser,
        user_service: UserService = Depends(get_user_service),
        credentials: HTTPAuthorizationCredentials = Security(security)
):
    token = credentials.credentials
    user_uuid = auth_handler.decode_token(token)
    if (user_uuid):
        user: dict = user_service.edit_profile(user_details, user_uuid)
        new_token = auth_handler.refresh_token_from_access_token(token)
        return {'msg': "Update is successful. Please use new access_token.",
                'user': user,
                'access_token': new_token
                }


@router.post('/logout', tags=['user'])
def logout(
    user_service: UserService = Depends(get_user_service),
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    token = credentials.credentials

    user_service.logout(token)
    return {
        "msg": "You have been logged out."
            }


@router.post('/logout_all', tags=['user'])
def logout_all(
    user_service: UserService = Depends(get_user_service),
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    token = credentials.credentials

    user_service.logout_all(token)
    return {
        "msg": "You have been logged out from all devices."
            }
