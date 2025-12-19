"""
Centralized Backend Service
Handles all HTTP communication with the backend system to avoid code duplication.
"""
import datetime
import json
import logging
import os
from typing import Optional, Dict, Any, Tuple

import requests

_logger = logging.getLogger(__name__)


class BackendService:
    """
    Centralized service for all backend API communications.
    Provides consistent error handling, logging, and request/response management.
    """

    def __init__(self):
        """Initialize backend service with environment configuration."""
        self.internal_host = os.environ.get('BACKEND_HOST', '127.0.0.1')
        self.internal_port = os.environ.get('BACKEND_PORT', '3000')
        self.external_url = os.environ.get('BACKEND_EXTERNAL_URL')
        self.api_key = os.environ.get('WEBHOOK_API_KEY')
        self.default_timeout = 10  # seconds

    def _get_internal_url(self) -> str:
        """Get internal backend URL for server-to-server communication."""
        return f"http://{self.internal_host}:{self.internal_port}"

    def _get_external_url(self) -> Optional[str]:
        """Get external backend URL for client-facing operations."""
        if not self.external_url:
            _logger.error("BACKEND_EXTERNAL_URL not configured")
            return ""
        return self.external_url

    def _get_default_headers(self) -> Dict[str, str]:
        """Get default headers for API requests."""
        headers = {
            'Content-Type': 'application/json',
        }
        if self.api_key:
            headers['Authorization'] = self.api_key
        return headers

    def _make_json_serializable(self, data: Any) -> Any:
        """
        Convert data to JSON-serializable format.
        Handles Odoo records, datetime objects, bytes, etc.
        """
        if isinstance(data, dict):
            return {k: self._make_json_serializable(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._make_json_serializable(i) for i in data]
        elif isinstance(data, bytes):
            import base64
            return base64.urlsafe_b64encode(data).decode('utf-8')
        elif isinstance(data, bytearray):
            import base64
            return base64.urlsafe_b64encode(data).decode('utf-8')
        # Handle Odoo model records
        elif hasattr(data, '_name') and hasattr(data, 'id'):
            result = {'id': data.id, 'model': data._name}
            if hasattr(data, 'name') and data.name:
                result['name'] = data.name
            return result
        # Handle datetime objects
        elif hasattr(data, 'isoformat'):
            return data.isoformat()
        else:
            return data

    def post_internal(
        self,
        endpoint: str,
        data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Make POST request to internal backend API."""
        url = f"{self._get_internal_url()}{endpoint}"
        return self._execute_request('POST', url, data=data, headers=headers, timeout=timeout)

    def put_internal(
        self,
        endpoint: str,
        data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Make PUT request to internal backend API."""
        url = f"{self._get_internal_url()}{endpoint}"
        return self._execute_request('PUT', url, data=data, headers=headers, timeout=timeout)

    def patch_internal(
        self,
        endpoint: str,
        data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Make PATCH request to internal backend API."""
        url = f"{self._get_internal_url()}{endpoint}"
        return self._execute_request('PATCH', url, data=data, headers=headers, timeout=timeout)

    def delete_internal(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Make DELETE request to internal backend API."""
        url = f"{self._get_internal_url()}{endpoint}"
        return self._execute_request('DELETE', url, data=data, headers=headers, timeout=timeout)

    def post_external(
        self,
        endpoint: str,
        data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Make POST request to external backend API."""
        external_url = self._get_external_url()
        if not external_url:
            return (False, None, "BACKEND_EXTERNAL_URL not configured")

        url = f"{external_url}{endpoint}"
        return self._execute_request('POST', url, data=data, headers=headers, timeout=timeout)

    def get_external(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Make GET request to external backend API."""
        external_url = self._get_external_url()
        if not external_url:
            return (False, None, "BACKEND_EXTERNAL_URL not configured")

        url = f"{external_url}{endpoint}"
        return self._execute_request('GET', url, params=params, headers=headers, timeout=timeout)

    def get_internal(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Make GET request to internal backend API."""
        url = f"{self._get_internal_url()}{endpoint}"
        return self._execute_request('GET', url, params=params, headers=headers, timeout=timeout)

    def _execute_post(
        self,
        url: str,
        data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Deprecated: Use _execute_request instead."""
        return self._execute_request('POST', url, data=data, headers=headers, timeout=timeout)

    def _execute_get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Deprecated: Use _execute_request instead."""
        return self._execute_request('GET', url, params=params, headers=headers, timeout=timeout)

    def _execute_request(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Execute HTTP request with error handling and logging."""
        # Set timeout first
        request_timeout = timeout if timeout is not None else self.default_timeout

        try:
            # Merge headers
            request_headers = self._get_default_headers()
            if headers:
                request_headers.update(headers)

            _logger.info(f"{method} request to: {url}")
            
            serialized_data = None
            if data is not None:
                serialized_data = self._make_json_serializable(data)
                _logger.debug(f"Request payload: {serialized_data}")
            
            if params:
                _logger.debug(f"Query params: {params}")

            response = requests.request(
                method=method,
                url=url,
                headers=request_headers,
                data=json.dumps(serialized_data) if serialized_data is not None else None,
                params=params,
                timeout=request_timeout
            )

            _logger.info(f"Response status: {response.status_code}")

            # Handle successful responses
            if response.status_code in (200, 201, 202, 204):
                try:
                    if response.content:
                        response_data = response.json()
                        return (True, response_data, None)
                    return (True, None, None)
                except json.JSONDecodeError:
                    # Success but no JSON body
                    return (True, None, None)
            elif response.status_code == 404 and method == 'GET':
                # Treat 404 as valid response for existence checks on GET
                _logger.info(f"Resource not found (404): {url}")
                return (True, {'exists': False}, None)

            # Handle error responses
            error_msg = f"Backend returned status {response.status_code}: {response.text}"
            _logger.error(error_msg)
            return (False, None, error_msg)

        except requests.exceptions.Timeout:
            error_msg = f"Request timeout after {request_timeout}s: {url}"
            _logger.error(error_msg)
            return (False, None, error_msg)
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {str(e)}"
            _logger.error(error_msg)
            return (False, None, error_msg)
        except requests.exceptions.RequestException as e:
            error_msg = f"Request error: {str(e)}"
            _logger.error(error_msg)
            return (False, None, error_msg)
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            _logger.exception(error_msg)
            return (False, None, error_msg)

    def sync_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        user_id: Optional[int] = None,
        partner_id: Optional[int] = None
    ) -> bool:
        """
        Send sync event to backend (common pattern for user/partner sync).

        Args:
            event_type: Type of event (e.g., 'user_changed', 'user_deleted')
            data: Event data
            user_id: Optional user ID
            partner_id: Optional partner ID

        Returns:
            bool: True if successful, False otherwise
        """
        payload = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event': event_type,
            'user_id': user_id,
            'partner_id': partner_id,
            'data': data,
        }

        success, response, error = self.post_internal('/internal/user/sync', payload)

        if not success:
            _logger.error(f"Sync event failed: {error}")

        return success


# Singleton instance
_backend_service_instance = None


def get_backend_service() -> BackendService:
    """Get or create singleton instance of BackendService."""
    global _backend_service_instance
    if _backend_service_instance is None:
        _backend_service_instance = BackendService()
    return _backend_service_instance

