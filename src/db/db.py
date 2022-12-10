from sqlmodel import Session, create_engine
import redis
from src.core import config

__all__ = ("get_session", "blocked_access_tokens", "active_refresh_tokens")


engine = create_engine(config.DATABASE_URL, echo=True)


def get_session():
    with Session(engine) as session:
        yield session


blocked_access_tokens = redis.Redis(
    host=config.REDIS_HOST, port=config.REDIS_PORT, db=1, decode_responses=True
)

active_refresh_tokens = redis.Redis(
    host=config.REDIS_HOST, port=config.REDIS_PORT, db=2, decode_responses=True
)
