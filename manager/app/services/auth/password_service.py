"""Argon2id password hashing and constant-time verification."""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# Precomputed dummy Argon2id digest to keep unknown-user timing comparable.
_DUMMY_HASH = _HASHER.hash("larp-dummy-timing-guard-value")


def validate_password_policy(password: str) -> None:
    if not isinstance(password, str) or len(password) < 8 or len(password) > 256:
        raise ValueError("Password must be between 8 and 256 characters")


def hash_password(password: str) -> str:
    validate_password_policy(password)
    return _HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    if not password_hash or not isinstance(password, str) or len(password) > 256:
        return False
    try:
        return bool(_HASHER.verify(password_hash, password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def dummy_verify(password: str) -> None:
    verify_password(_DUMMY_HASH, password or "")


def needs_rehash(password_hash: str) -> bool:
    try:
        return _HASHER.check_needs_rehash(password_hash)
    except InvalidHashError:
        return False

