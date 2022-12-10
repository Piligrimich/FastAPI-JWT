import json
import uuid
from functools import lru_cache
from typing import Optional

import os
import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException
from sqlmodel import Session

from src.api.usersDirectory.schemas import UserCreate, UserLogin
from src.db import AbstractCache, get_cache, get_session
from src.models import User
from src.services import ServiceMixin

from src.db.db import active_refresh_tokens, blocked_access_tokens


__all__ = ("UserService", "get_user_service")


class Auth():
    hasher = CryptContext(schemes=['bcrypt'])
    secret = 'APP_SECRET_STRING'

    def encode_password(self, password):
        return self.hasher.hash(password)

    def verify_password(self, password, encoded_password):
        return self.hasher.verify(password, encoded_password)

    def encode_token(self, username, user_uuid, refresh_uuid):
        payload = {
            'exp': datetime.utcnow() + timedelta(days=0, minutes=30),
            'iat': datetime.utcnow(),
            'type': 'access_token',
            'sub': username,
            'jti': str(uuid.uuid4()),
            'user_uuid': user_uuid,
            'refresh_uuid': refresh_uuid
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            if (payload['type'] == 'access_token'):
                block_token = blocked_access_tokens.get(payload['jti'])
                if block_token:
                    raise HTTPException(status_code=403, detail='No access')
                return payload['user_uuid']
            raise HTTPException(status_code=401, detail='Type for the token is invalid')
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Token expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid token')

    def encode_refresh_token(self, username, user_uuid):
        payload = {
            'exp': datetime.utcnow() + timedelta(days=0, hours=10),
            'iat': datetime.utcnow(),
            'type': 'refresh_token',
            'sub': username,
            'jti': str(uuid.uuid4()),
            'user_uuid': user_uuid
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )

    def refresh_token(self, refresh_token):
        try:
            payload = jwt.decode(refresh_token, self.secret, algorithms=['HS256'])
            if (payload['type'] == 'refresh_token'):
                username = payload['sub']
                user_uuid = payload['user_uuid']
                list_refresh = active_refresh_tokens.lrange(user_uuid, 0, -1)
                if payload['jti'] in list_refresh:
                    new_refresh_token = self.encode_refresh_token(username, user_uuid)
                    for_refresh_id = jwt.decode(new_refresh_token, self.secret, algorithms=['HS256'])
                    new_access_token = self.encode_token(username, user_uuid, for_refresh_id['jti'])

                    list_refresh.remove(payload['jti'])
                    list_refresh.append(for_refresh_id['jti'])

                    active_refresh_tokens.delete(user_uuid)
                    active_refresh_tokens.lpush(user_uuid, *list_refresh)

                    return {'access_token': new_access_token, 'refresh_token': new_refresh_token}
                raise HTTPException(status_code=403, detail='No access')
            raise HTTPException(status_code=401, detail='Invalid type for token')
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Refresh token expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid refresh token')

    def refresh_token_from_access_token(self, access_token):
        try:
            payload = jwt.decode(access_token, self.secret, algorithms=['HS256'])
            if (payload['type'] == 'access_token'):
                username = payload['sub']
                user_uuid = payload['user_uuid']
                new_token = self.encode_token(username, user_uuid, payload['refresh_uuid'])
                blocked_access_tokens.set(payload['jti'], payload['jti'])
                return new_token
            raise HTTPException(status_code=401, detail='Invalid type for token')
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Access token expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid access token')


auth_handler = Auth()


class UserService(ServiceMixin):
    def login_user(self, username: str, password: str) -> dict:
        """Логин пользователя"""
        user = self.session.query(User).filter(User.username == username).first()
        if user is None:
            return HTTPException(status_code=401, detail='Invalid username')
        if not auth_handler.verify_password(password, user.password):
            return HTTPException(status_code=401, detail='Invalid password')

        refresh_token = auth_handler.encode_refresh_token(user.username, user.uuid)
        for_refresh_id = jwt.decode(refresh_token, auth_handler.secret, algorithms=['HS256'])
        access_token = auth_handler.encode_token(user.username, user.uuid, for_refresh_id['jti'])

        active_refresh_tokens.lpush(user.uuid, for_refresh_id['jti'])
        return {'access_token': access_token, 'refresh_token': refresh_token}

    def create_user(self, user: UserCreate) -> dict:
        """Создать пользователя."""
        if self.session.query(User).filter(User.username == user.username).first():
            raise HTTPException(status_code=401, detail='Username is already in use')
        hashed_password = auth_handler.encode_password(user.password)
        new_user = User(username=user.username, email=user.email, password=hashed_password, uuid=str(uuid.uuid4()))
        self.session.add(new_user)
        self.session.commit()
        self.session.refresh(new_user)
        new_user = new_user.dict()
        del new_user['password']
        del new_user['id']
        return new_user

    def get_user_profile(self, user_uuid) -> dict:
        """Возвращает конкретного пользователя"""
        user = self.session.query(User).filter(User.uuid == user_uuid).first()
        user = user.dict()
        del user['password']
        del user['id']
        del user['is_totp_enabled']
        del user['is_active']
        return user

    def edit_profile(self, user_detail, user_uuid) -> dict:
        """Изменение данных пользователя"""
        user = self.session.query(User).filter(User.uuid == user_uuid).first()
        if user_detail.username != None:
            user.username = user_detail.username
        if user_detail.email != None:
            user.email = user_detail.email
        if user_detail.password != None:
            user.password = user_detail.password
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        user = user.dict()
        del user['password']
        del user['id']
        return user

    def logout(self, access_token):
        """Выход из аккаунта на устройстве"""
        try:
            payload = jwt.decode(access_token, auth_handler.secret, algorithms=['HS256'])
            if not blocked_access_tokens.get(payload['jti']):
                if payload['type'] == 'access_token':
                    blocked_access_tokens.set(payload['jti'], payload['jti'])

                    list_refresh = active_refresh_tokens.lrange(payload['user_uuid'], 0, -1)
                    list_refresh.remove(payload['refresh_uuid'])

                    active_refresh_tokens.delete(payload['user_uuid'])
                    if len(list_refresh) > 0:
                        active_refresh_tokens.lpush(payload['user_uuid'], *list_refresh)
                    return True
            raise HTTPException(status_code=401, detail='Invalid type for token')
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Access token expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid access token')

    def logout_all(self, access_token):
        """Выход из всех устройств"""
        try:
            payload = jwt.decode(access_token, auth_handler.secret, algorithms=['HS256'])
            if not blocked_access_tokens.get(payload['jti']):
                if payload['type'] == 'access_token':
                    blocked_access_tokens.set(payload['jti'], payload['jti'])
                    active_refresh_tokens.delete(payload['user_uuid'])
                    return True

            raise HTTPException(status_code=401, detail='Invalid type for token')
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Access token expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid access token')


@lru_cache()
def get_user_service(
    cache: AbstractCache = Depends(get_cache),
    session: Session = Depends(get_session),
) -> UserService:
    return UserService(cache=cache, session=session)