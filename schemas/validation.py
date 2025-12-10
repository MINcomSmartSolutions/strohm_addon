from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT


def parse_iso8601_to_server_datetime(v: str) -> str:
    """
    Accept ISO8601 format and convert to DEFAULT_SERVER_DATETIME_FORMAT.
    Returns the converted string in DEFAULT_SERVER_DATETIME_FORMAT.
    """
    try:
        # Try parsing as ISO8601 format
        dt = datetime.fromisoformat(v.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        # If ISO8601 fails, try DEFAULT_SERVER_DATETIME_FORMAT
        try:
            dt = datetime.strptime(v, DEFAULT_SERVER_DATETIME_FORMAT)
        except ValueError:
            raise ValueError(f"Invalid datetime format. Expected ISO8601 or {DEFAULT_SERVER_DATETIME_FORMAT}")

    # Convert to DEFAULT_SERVER_DATETIME_FORMAT
    return dt.strftime(DEFAULT_SERVER_DATETIME_FORMAT)

class BaseRequest(BaseModel):
    """Base schema with common fields for authentication and validation"""
    timestamp: str = Field(..., max_length=40)
    salt: str = Field(..., max_length=30)
    hash: str

    @field_validator('timestamp', mode='before')
    def validate_timestamp_format(cls, v, info):
        return parse_iso8601_to_server_datetime(v)

    def parsed_timestamp(self) -> datetime:
        """Return the timestamp as a datetime object when needed"""
        return datetime.strptime(self.timestamp, DEFAULT_SERVER_DATETIME_FORMAT)


class UserCreate(BaseRequest):
    """Schema for user creation requests"""
    name: str = Field(..., min_length=3, max_length=100)
    email: EmailStr


class ApiKeyRotation(BaseRequest):
    """Schema for API key rotation requests"""
    user_id: int = Field(..., gt=0)
    key: str
    key_salt: str = Field(..., max_length=30)


class PaymentMethodCheck(BaseRequest):
    """Schema for payment method validation requests"""
    user_id: int = Field(..., gt=0)
    partner_id: int = Field(..., gt=0)
    key: str
    key_salt: str = Field(..., max_length=30)


class BillLineItem(BaseModel):
    """Schema for individual line items in a bill"""
    sku: str = Field(..., min_length=3, max_length=50)
    # Quantity and price must be non-negative
    quantity: float = Field(..., ge=0)
    price_unit: float = Field(..., ge=0)
    session_start: str = Field(..., max_length=30)
    session_end: str = Field(..., max_length=30)
    session_backend_ref: int = Field(..., gt=0)

    @field_validator('sku')
    def validate_sku(cls, v, info):
        # You can add specific SKU validation rules here
        if not v or len(v) < 3:
            raise ValueError("SKU must be at least 3 characters")
        return v

    @field_validator('session_start', 'session_end', mode='before')
    def validate_session_timestamps(cls, v, info):
        return parse_iso8601_to_server_datetime(v)

    @field_validator('session_end')
    def validate_session_end_after_start(cls, v, info):
        session_start = info.data.get('session_start')
        if session_start:
            start = datetime.strptime(session_start, DEFAULT_SERVER_DATETIME_FORMAT)
            end = datetime.strptime(v, DEFAULT_SERVER_DATETIME_FORMAT)
            if end <= start:
                raise ValueError("Session end must be after session start")
        return v

    def parsed_session_start(self) -> datetime:
        """Return session_start as datetime object"""
        return datetime.strptime(self.session_start, DEFAULT_SERVER_DATETIME_FORMAT)

    def parsed_session_end(self) -> datetime:
        """Return session_end as datetime object"""
        return datetime.strptime(self.session_end, DEFAULT_SERVER_DATETIME_FORMAT)

class BillCreate(BaseRequest):
    """Schema for bill creation requests"""
    lines_data: List[BillLineItem]
    key: str
    key_salt: str = Field(..., max_length=30)
    user_id: int = Field(..., gt=0)
    partner_id: int = Field(..., gt=0)
    due_date: Optional[str] = Field(None, max_length=30)
    invoice_date: Optional[str] = Field(None, max_length=30)

    @field_validator('due_date', mode='before')
    def validate_due_date_format(cls, v, info):
        if v is None:
            return v
        return parse_iso8601_to_server_datetime(v)

    @field_validator('invoice_date', mode='before')
    def validate_invoice_date_format(cls, v, info):
        if v is None:
            return v
        return parse_iso8601_to_server_datetime(v)

    def parsed_due_date(self) -> Optional[datetime]:
        """Return due_date as datetime object"""
        if not self.due_date:
            return None
        return datetime.strptime(self.due_date, DEFAULT_SERVER_DATETIME_FORMAT)

    def parsed_invoice_date(self) -> Optional[datetime]:
        """Return invoice_date as datetime object"""
        if not self.invoice_date:
            return None
        return datetime.strptime(self.invoice_date, DEFAULT_SERVER_DATETIME_FORMAT)

class PortalLogin(BaseRequest):
    """Schema for portal auto-login requests"""
    key: str
    key_salt: str = Field(..., max_length=30)
