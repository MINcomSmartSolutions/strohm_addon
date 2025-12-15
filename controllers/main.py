import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime

import werkzeug.urls
import werkzeug.utils
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pydantic import ValidationError as PydanticValidationError

from odoo import http, fields
from odoo.exceptions import ValidationError, AccessDenied
from odoo.http import request, Controller
from ..schemas.validation import (
    UserCreate, ApiKeyRotation, PaymentMethodCheck,
    BillCreate, PortalLogin
)
from ..utils import strohm_init_parameters, ensure_standard_products

# import debugpy

_logger = logging.getLogger(__name__)


class StrohmAPI(Controller):
    def __init__(self):
        super().__init__()
        _logger.info("Initializing StrohmAPI")
        self.datetime_format = "%Y-%m-%dT%H:%M:%S"

        # debugpy.wait_for_client()

        if os.environ.get('ODOO_ENV') == 'dev':
            _logger.setLevel(logging.DEBUG)

        # Run shared initialization logic to ensure consistent configuration
        try:
            strohm_init_parameters(request.env)
        except Exception as e:
            _logger.warning(f"Failed to run strohm_init_parameters in controller: {str(e)}")

        # Initialize standard products during API startup
        self.standard_products = ensure_standard_products(request.env)

        # Use admin user for invoice operations (simplified approach)
        self.accounting_user_id = self._get_admin_user_id()

        self.API_SECRET = os.environ.get('ODOO_API_SECRET')
        if not self.API_SECRET:
            _logger.error("API secret not found in environment variables. Please set ODOO_API_SECRET")
            raise ValueError("API secret not found in environment variables. Please set ODOO_API_SECRET")

    def _get_admin_user_id(self):
        """Get admin user ID for invoice operations (simplified approach)"""
        try:
            _logger.info("Getting admin user for invoice operations")

            # Try to find admin user
            admin_user = request.env['res.users'].sudo().search([('login', '=', 'admin')], limit=1)
            if admin_user and admin_user.exists():
                _logger.info(f"Using admin user for accounting operations: {admin_user.name} (ID: {admin_user.id})")
                return admin_user.id

            # Fallback to first active user with accounting rights
            accounting_user = request.env['res.users'].sudo().search([
                ('active', '=', True),
                ('groups_id', 'in', [request.env.ref('account.group_account_user').id])
            ], limit=1)

            if accounting_user and accounting_user.exists():
                _logger.info(f"Using accounting user: {accounting_user.name} (ID: {accounting_user.id})")
                return accounting_user.id

            # Final fallback to superuser
            _logger.warning("No admin or accounting user found, falling back to superuser")
            return 1

        except Exception as e:
            _logger.error(f"Failed to get admin user: {str(e)}", exc_info=True)
            return 1  # Fallback to superuser

    def _get_accounting_user_id(self):
        """Get accounting user ID (simplified to use admin user)"""
        return self._get_admin_user_id()

    def _encrypt_api_key(self, api_key):
        """Encrypt API key using environment variable secret"""

        salt = self._generate_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            # See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
            iterations=600_000,
        )
        api_secret = self.API_SECRET
        key = base64.b64encode(kdf.derive(api_secret.encode()))
        f = Fernet(key)
        encrypted_key = f.encrypt(api_key.encode())

        # Verify encryption by decrypting and comparing
        try:
            decrypted = f.decrypt(encrypted_key).decode()
            if decrypted != api_key:
                _logger.error("Encryption verification failed: decrypted key doesn't match original")
                raise ValueError("Encryption verification failed")
        except Exception as e:
            _logger.error(f"Encryption verification failed: {str(e)}", exc_info=e, stack_info=True)
            raise ValidationError("Encryption verification failed")

        return {
            'key': base64.urlsafe_b64encode(encrypted_key).decode(),
            'key_salt': base64.urlsafe_b64encode(salt).decode()
        }

    def _decrypt_api_key(self, encoded_api_key, encoded_salt):
        """Decrypt API key using environment variable secret"""

        _logger.debug(" Decrypting API key")
        try:
            # Decode base64 inputs once
            encrypted_key = base64.urlsafe_b64decode(encoded_api_key)
            salt = base64.urlsafe_b64decode(encoded_salt)

            # Derive the same key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                # See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
                iterations=600_000,
            )
            api_secret = self.API_SECRET
            key = base64.b64encode(kdf.derive(api_secret.encode()))
            f = Fernet(key)

            decrypted_key = f.decrypt(encrypted_key).decode()
            _logger.debug(" API key decrypted successfully")
            return decrypted_key
        except InvalidToken:
            raise ValidationError("Invalid API or salt")
        except Exception as e:
            _logger.error(f"Decryption failed: {str(e)}", exc_info=e, stack_info=True)
            raise ValueError(f"Decryption failed: {str(e)}")

    def _validate_admin_token(self, headers):
        """Validate Bearer token from Authorization header

        Accepts either:
        1. ODOO_API_SECRET environment variable (simpler, no GUI needed)
        2. Valid Odoo API key (for more granular control)
        """

        auth_header = headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False

        token = auth_header.split(' ')[1]
        if not token:
            _logger.debug(" No token provided in Authorization header.")
            return False

        # First, check if token matches ODOO_API_SECRET (constant-time comparison)
        if secrets.compare_digest(token, self.API_SECRET):
            _logger.debug(" Admin authenticated with ODOO_API_SECRET")
            # Use admin user for this request
            admin_user = request.env['res.users'].sudo().search([
                ('login', '=', 'admin'),
                ('active', '=', True)
            ], limit=1)

            if not admin_user or not admin_user.exists():
                _logger.error(" Admin user not found or inactive - rejecting authentication")
                return False

            # Verify admin has system access (same security level as API key auth)
            if not admin_user.has_group('base.group_system'):
                _logger.error(" Admin user lacks system access - rejecting authentication")
                return False

            _logger.debug(" Admin has system access - authentication successful")
            request.update_env(user=admin_user)
            return True

        # If not API_SECRET, try validating as Odoo API key
        admin_id = request.env['res.users.apikeys'].sudo()._check_credentials(scope='rpc', key=token)
        if not admin_id:
            _logger.debug(" Token verification failed.")
            return False

        _logger.debug(" Token verification succeeded.")

        # Update request environment with the authenticated user
        admin = request.env['res.users'].sudo().browse(admin_id)
        if not admin.has_group('base.group_system'):
            _logger.debug(" Admin doesn't have system access - authentication successful")
            return False

        _logger.debug(" Admin has system access.")
        request.update_env(user=admin)
        return True

    def _generate_hash(self, message, secret=None):
        """
        Generate HMAC signature for authentication validation.

        Args:
            message (string): Message to be signed
            secret (bytes): Secret key used for generating the signature

        Returns:
            str: Hexadecimal digest of the HMAC signature
        """

        if secret is None:
            secret = self.API_SECRET.encode()

        if isinstance(message, str):
            message = message.encode('utf-8')

        return hmac.new(
            secret,
            message,
            hashlib.sha256
        ).hexdigest()

    def _generate_salt(self, decode=False):
        """Create a random salt for encryption"""
        salt = secrets.token_bytes(16)
        if decode:
            return base64.urlsafe_b64encode(salt).decode('utf-8')
        return salt

    def _validate_hash(self, hash, message, secret=None):
        """
        Validate HMAC signature for authentication validation.

        Args:
            hash (str): Hexadecimal digest of the HMAC signature
            message (str): Message used for generating the signature
            secret (bytes): Secret key used for generating the signature

        Returns:
            bool: True if the hash is valid, False otherwise
        """
        if secret is None:
            secret = self.API_SECRET.encode()

        expected_hash = self._generate_hash(message, secret)
        return secrets.compare_digest(hash, expected_hash)

    def _check_valid_payment_method(self, partner_id):
        """Check if user has a valid payment method"""
        if not partner_id:
            _logger.debug("No partner ID provided, cannot check payment method")
            return False

        _logger.debug(f"Checking if partner {partner_id} has a valid payment method")

        try:
            payment_token = request.env['payment.token'].sudo().search(
                [('partner_id', '=', partner_id), ('active', '=', True)], limit=1
            )
            return bool(payment_token and payment_token.exists())
        except Exception as e:
            _logger.error(f"Error checking payment method for partner {partner_id}: {str(e)}", exc_info=True)
            return False

    @http.route('/internal/test', type='http', auth='public', methods=['GET'], csrf=False)
    def test(self, **kw):
        """Test endpoint"""
        return request.make_json_response({'status': self._check_valid_payment_method(44)}, status=200)

    def _debug_accounting_user(self):
        """Internal method to verify accounting user setup for debugging"""
        try:
            accounting_user_id = self._get_accounting_user_id()
            accounting_user = request.env['res.users'].sudo().browse(accounting_user_id)

            if not accounting_user.exists():
                _logger.error(f"Accounting user not found, ID: {accounting_user_id}")
                return None

            # Test permissions
            can_create_moves = request.env['account.move'].with_user(accounting_user).sudo().check_access('create')

            debug_info = {
                'id': accounting_user.id,
                'name': accounting_user.name,
                'login': accounting_user.login,
                'active': accounting_user.active,
                'groups': [g.name for g in accounting_user.groups_id],
                'can_create_account_moves': can_create_moves
            }

            _logger.debug(f"Accounting user debug info: {debug_info}")
            return debug_info

        except Exception as e:
            _logger.error(f"Debug accounting user error: {str(e)}", exc_info=True, stack_info=True)
            return None

    @http.route('/internal/user/valid_pm', type='http', auth='public', methods=['POST'], csrf=False)
    def check_payment_method(self, **kw):
        try:
            # Parse and validate request data with Pydantic
            try:
                data = json.loads(request.httprequest.data)
                validated_data = PaymentMethodCheck(**data)
            except PydanticValidationError as e:
                errors = e.errors()
                error_msgs = [f"{err['loc'][0]}: {err['msg']}" for err in errors]
                return request.make_json_response({'error': error_msgs}, status=400)
            except json.JSONDecodeError:
                return request.make_json_response({'error': 'Invalid JSON'}, status=400)

            # Continue with validation using the validated data
            decrypted_key = self._decrypt_api_key(validated_data.key, validated_data.key_salt)

            # Continue with the existing validation logic
            user_id = request.env['res.users.apikeys'].sudo()._check_credentials(scope='rpc', key=decrypted_key)
            if not user_id == int(validated_data.user_id):
                raise ValidationError("Invalid API key")

            partner_id = request.env['res.users'].sudo().browse(validated_data.user_id).partner_id.id
            if not partner_id or not partner_id == int(validated_data.partner_id):
                raise ValidationError("Invalid partner ID")

            message = f"{validated_data.timestamp}{validated_data.user_id}{validated_data.partner_id}{validated_data.key}{validated_data.key_salt}{validated_data.salt}"
            if not (self._validate_hash(validated_data.hash, message)):
                return request.make_json_response({'error': 'Invalid signature'}, status=403)

            has_valid_payment_method = 1 if (self._check_valid_payment_method(partner_id)) else 0

            resp_timestamp = datetime.utcnow().strftime(self.datetime_format)
            _salt = self._generate_salt(decode=True)
            resp_message = f"{resp_timestamp}{has_valid_payment_method}{_salt}"
            _hash = self._generate_hash(resp_message)

            return request.make_json_response(
                {'timestamp': resp_timestamp, 'result': has_valid_payment_method, 'salt': _salt, 'hash': _hash},
                status=200)

        except ValidationError as ve:
            return request.make_json_response({'error': str(ve)}, status=400)
        except Exception as e:
            _logger.error(f"Valid payment method check error: {str(e)}", exc_info=True, stack_info=True)
            return request.make_json_response({'error': str(e)}, status=500)

    @http.route('/internal/rotate_api_key', type='http', auth='public', methods=['POST'], csrf=False)
    def rotate_api_key(self, **kw):
        """Rotate API key for a user"""
        try:
            # Validate admin token
            if not self._validate_admin_token(request.httprequest.headers):
                return request.make_json_response({'error': 'Invalid admin token'}, status=401)

            # Parse and validate request data with Pydantic
            try:
                data = json.loads(request.httprequest.data)
                validated_data = ApiKeyRotation(**data)
            except PydanticValidationError as e:
                errors = e.errors()
                error_msgs = [f"{err['loc'][0]}: {err['msg']}" for err in errors]
                return request.make_json_response({'error': error_msgs}, status=400)
            except json.JSONDecodeError:
                return request.make_json_response({'error': 'Invalid JSON'}, status=400)

            # Decrypt the API key
            decrypted_key = self._decrypt_api_key(validated_data.key, validated_data.key_salt)

            # Continue with the existing validation logic
            user_id = request.env['res.users.apikeys'].sudo()._check_credentials(scope='rpc', key=decrypted_key)
            if not user_id == validated_data.user_id:
                raise ValidationError("Invalid API key")

            message = f"{validated_data.timestamp}{validated_data.user_id}{validated_data.key}{validated_data.key_salt}{validated_data.salt}"
            if not (self._validate_hash(validated_data.hash, message)):
                return request.make_json_response({'error': 'Invalid signature'}, status=403)

            # Set the api keys expiration date to right now to invalidate it
            request.env['res.users.apikeys'].sudo().search([('user_id', '=', validated_data.user_id)]).write(
                {'expiration_date': fields.Datetime.now()})

            # Generate new API key
            new_api_key = request.env['res.users.apikeys'].sudo()._generate_for_user(
                user_id,
                'rpc',  # scope
                'Auto-generated User API key',  # name
                None  # TODO: Set a viable expiration_date
            )

            timestamp = datetime.utcnow().strftime(self.datetime_format)
            _salt = self._generate_salt(decode=True)
            new_encrypted_token_data = self._encrypt_api_key(new_api_key)

            _hash = self._generate_hash(
                f"{timestamp}{user_id}{new_encrypted_token_data['key']}{new_encrypted_token_data['key_salt']}{_salt}",
            )

            # Return the new encrypted API key
            return request.make_json_response({
                'success': True,
                'timestamp': timestamp,
                'user_id': user_id,
                'key': new_encrypted_token_data['key'],
                'key_salt': new_encrypted_token_data['key_salt'],
                'salt': _salt,
                'hash': _hash,
            }, status=200)


        except ValidationError as ve:
            return request.make_json_response({'error': str(ve)}, status=400)
        except Exception as e:
            _logger.error(f"API key rotation error: {str(e)}", exc_info=True, stack_info=True)
            return request.make_json_response({'error': str(e)}, status=500)

    @http.route('/internal/user/create', type='http', auth='public', methods=['POST'], csrf=False)
    def create_user(self, **kw):
        try:
            # Validate admin token
            if not self._validate_admin_token(request.httprequest.headers):
                return request.make_json_response({'error': 'Invalid admin token'}, status=401)

            # Parse and validate request data with Pydantic
            try:
                data = json.loads(request.httprequest.data)
                validated_data = UserCreate(**data)
            except PydanticValidationError as e:
                errors = e.errors()
                error_msgs = [f"{err['loc'][0]}: {err['msg']}" for err in errors]
                return request.make_json_response({'error': error_msgs}, status=400)
            except json.JSONDecodeError:
                return request.make_json_response({'error': 'Invalid JSON'}, status=400)

            # Check if partner with this email already exists
            existing_partner = request.env['res.partner'].sudo().search([('email', '=', validated_data.email)], limit=1)

            # Check if user with this email/login already exists
            existing_user = request.env['res.users'].sudo().search([('login', '=', validated_data.email)], limit=1)

            # If both partner and user exist, verify they match
            if existing_partner and existing_user:
                # Verify the user and partner are associated
                if existing_user.partner_id.id != existing_partner.id:
                    return request.make_json_response(
                        {'error': f'Data inconsistency: user and partner with email {validated_data.email} are not properly linked'},
                        status=500
                    )

                # If email and name match, regenerate and return new API credentials
                if existing_partner.name == validated_data.name:
                    _logger.info(f"Existing user {existing_user.id} re-registering, regenerating API key")

                    # Revoke old API keys by setting expiration date to now
                    request.env['res.users.apikeys'].sudo().search([('user_id', '=', existing_user.id)]).write(
                        {'expiration_date': fields.Datetime.now()}
                    )

                    # Generate new API key
                    new_api_key = request.env['res.users.apikeys'].sudo()._generate_for_user(
                        existing_user.id,
                        'rpc',  # scope
                        'Auto-generated User API key',  # name
                        None  # TODO: Set a viable expiration_date
                    )
                    _logger.info(f"Regenerated API key for existing user {existing_user.id}")

                    # Encrypt API key for transport
                    encrypted_token_data = self._encrypt_api_key(new_api_key)
                    _datetime = datetime.now().strftime(self.datetime_format)
                    _salt = self._generate_salt(decode=True)
                    _hash = self._generate_hash(
                        f"{_datetime}{existing_user.id}{existing_partner.id}{encrypted_token_data['key']}{encrypted_token_data['key_salt']}{_salt}",
                    )

                    return request.make_json_response({
                        'timestamp': _datetime,
                        'user_id': existing_user.id,
                        'partner_id': existing_partner.id,
                        'key': encrypted_token_data['key'],
                        'key_salt': encrypted_token_data['key_salt'],
                        'salt': _salt,
                        'hash': _hash,
                    }, status=200)
                else:
                    # Email matches but name doesn't - this is a conflict
                    return request.make_json_response(
                        {'error': f'A user with email {validated_data.email} already exists with a different name'},
                        status=409
                    )

            # If only partner exists (without user), that's a conflict
            elif existing_partner:
                return request.make_json_response(
                    {'error': f'A partner with email {validated_data.email} already exists'},
                    status=409
                )

            # If only user exists (without partner), that's also a conflict
            elif existing_user:
                return request.make_json_response(
                    {'error': f'A user with email {validated_data.email} already exists'},
                    status=409
                )

            # Create partner
            germany = request.env['res.country'].sudo().search([('code', '=', 'DE')], limit=1)
            partner_values = {
                'name': validated_data.name,
                'email': validated_data.email,
                'country_id': germany.id,
                'lang': 'de_DE',
                'tz': 'Europe/Berlin',
            }
            partner = request.env['res.partner'].sudo().create(
                {k: v for k, v in partner_values.items() if v}
            )

            portal_group = request.env.ref('base.group_portal')
            user_values = {
                'name': validated_data.name,
                'login': validated_data.email,
                'email': validated_data.email,
                'partner_id': partner.id,
                'lang': 'de_DE',
                'active': True,
                'groups_id': [(6, 0, [portal_group.id])],
            }


            user = request.env['res.users'].sudo().with_context(no_reset_password=True).create(user_values)

            # Generate and store API key for new user using the new method
            api_key = request.env['res.users.apikeys'].sudo()._generate_for_user(
                user.id,
                'rpc',  # scope
                'Auto-generated User API key',  # name
                None  # TODO: Set a viable expiration_date
            )
            _logger.info(f" Generated API key for user {user.id}: {api_key}")

            # Encrypt API key for transport, this encryption is done by us (independent of odoo framework)
            encrypted_token_data = self._encrypt_api_key(api_key)
            _datetime = datetime.now().strftime(self.datetime_format)
            _salt = self._generate_salt(decode=True)
            _hash = self._generate_hash(
                f"{_datetime}{user.id}{partner.id}{encrypted_token_data['key']}{encrypted_token_data['key_salt']}{_salt}",
            )

            return request.make_json_response({
                'timestamp': _datetime,
                'user_id': user.id,
                'partner_id': partner.id,
                'key': encrypted_token_data['key'],
                'key_salt': encrypted_token_data['key_salt'],
                'salt': _salt,
                'hash': _hash,
            }, status=201)


        except ValidationError as ve:
            return request.make_json_response({'error': str(ve)}, status=400)
        except Exception as e:
            _logger.error(f"User creation error: {str(e)}", exc_info=True, stack_info=True)
            return request.make_json_response({'error': str(e)}, status=500)

    @http.route('/portal_login', type='http', auth='public', methods=['GET'], csrf=False)
    def portal_auto_login(self, **kw):
        try:
            # Validate query parameters using Pydantic
            try:
                parameters = request.httprequest.args.to_dict()
                validated_data = PortalLogin(**kw)
            except PydanticValidationError as e:
                errors = e.errors()
                error_msgs = [f"{err['loc'][0]}: {err['msg']}" for err in errors]
                return request.make_json_response({'error': error_msgs}, status=400)

            # Verify timestamp isn't too old (5-minute window)
            timestamp_dt = validated_data.parsed_timestamp()
            timestamp_unix = int(timestamp_dt.timestamp())
            if int(time.time()) - timestamp_unix > 300:
                return request.make_json_response({'error': 'Expired'}, status=403)

            # Decrypt API key
            print(parameters)
            decrypted_key = self._decrypt_api_key(parameters['key'], parameters['key_salt']) # Directly from kw to avoid pydantic re-encoding issues
            _logger.debug(' User API key decrypted successfully')

            # Directly check the API key
            user_id = request.env['res.users.apikeys'].sudo()._check_credentials(scope='rpc', key=decrypted_key)
            if not user_id or not isinstance(user_id, int):
                _logger.debug(' Invalid API key during portal login')
                raise AccessDenied("Invalid API key")

            # Create the message that was used for the signature
            # One thing here to note is that user_id is parsed from api key and not send as parameter or data. This makes sures only backend knows the user id (odoo_user_id)
            message = f"{parameters['timestamp']}{user_id}{parameters['key']}{parameters['key_salt']}{parameters['salt']}" # Directly from kw to avoid pydantic re-encoding issues
            if not (self._validate_hash(parameters['hash'], message)):
                return request.make_json_response({'error': 'Invalid signature'}, status=403)

            _logger.debug(f" User ID: {user_id}, portal login")

            user = request.env['res.users'].sudo().browse(user_id)
            if not user or not user.exists() or not user.active:
                _logger.warning(f" User not found or inactive: ID {user_id}")
                return request.make_json_response({'error': 'User not found'}, status=404)

            # Disable 2FA for this user if it's enabled
            if user.totp_enabled:
                user.sudo().write({'totp_secret': False})
                # Also revoke all trusted devices
                user.totp_trusted_device_ids.unlink()
                _logger.info(f"Disabled 2FA for user {user.login} during portal login")

            # Set up environment for authentication
            request.httprequest.environ['wsgi.interactive'] = False

            try:
                # Direct session setup without using authenticate!
                # This bypasses the _check_credentials validation that requires type='password'
                request.session.uid = user.id
                request.session.login = user.login
                request.session.session_token = user._compute_session_token(request.session.sid)
                request.session.context = dict(request.session.context, uid=user.id)
                request.update_env(user=user)
                user = user.with_user(user)
                user._update_last_login()

                _logger.debug(' User session set up successfully')

                # Skip device registration for enhanced security tracking since we're bypassing 2FA
                if hasattr(request.env['res.users'], '_register_device'):
                    try:
                        request.env['res.users']._register_device()
                    except Exception as e:
                        _logger.warning(f"Failed to register device during portal login: {str(e)}")

                # Get the redirect path (default to portal home page)
                redirect_path = kw.get('redirect', '/my')

                # Redirect user directly to the portal page
                return werkzeug.utils.redirect(redirect_path)

            except AccessDenied as ade:
                _logger.warning(f"Access denied during portal login: {str(ade)}", exc_info=True, stack_info=True)
                return request.make_json_response({'error': str(ade)}, status=500)
            except Exception as e:
                _logger.error(f"Portal login error: {str(e)}", exc_info=True, stack_info=True)
                return request.make_json_response({'error': str(e)}, status=500)
        except ValidationError as ve:
            return request.make_json_response({'error': str(ve)}, status=400)
        except AccessDenied as ade:
            _logger.warning(f"Access denied, portal login: {str(ade)}", exc_info=True, stack_info=True)
            return request.make_json_response({'error': str(ade)}, status=401)
        except Exception as e:
            _logger.error(f"Portal login error: {str(e)}", exc_info=True, stack_info=True)
            return request.make_json_response({'error': str(e)}, status=500)

    @http.route('/internal/txn/process', type='http', auth='public', methods=['POST'], csrf=False)
    def process_txn(self, **kw):
        try:
            # Parse and validate request data with Pydantic
            try:
                data = json.loads(request.httprequest.data)
                validated_data = BillCreate(**data) # it is validated, not sanitized
            except PydanticValidationError as e:
                errors = e.errors()
                error_msgs = [f"{err['loc'][0]}: {err['msg']}" for err in errors]
                return request.make_json_response({'error': error_msgs}, status=400)
            except json.JSONDecodeError:
                return request.make_json_response({'error': 'Invalid JSON'}, status=400)

            timestamp_dt = validated_data.parsed_timestamp()
            # Verify timestamp isn't too old (5-minute window)
            timestamp_unix = int(timestamp_dt.timestamp())
            if int(time.time()) - timestamp_unix > 300:
                return request.make_json_response({'error': 'Expired'}, status=403)

            # Decrypt API key and authenticate user
            decrypted_key = self._decrypt_api_key(data['key'], data['key_salt'])

            # Directly check the API key
            user_id = request.env['res.users.apikeys'].sudo()._check_credentials(scope='rpc', key=decrypted_key)
            if not user_id or not isinstance(user_id, int):
                raise ValidationError("Invalid API key")

            # Get the authenticated user and update the request environment
            user = request.env['res.users'].sudo().browse(user_id)
            if not user or not user.exists() or not user.active:
                raise ValidationError("User not found")

            partner_id = user.partner_id.id
            if not partner_id or not isinstance(partner_id, int):
                raise ValidationError("User has no valid partner")

            # Create the message that was used for the signature
            message = f"{data['timestamp']}{user_id}{partner_id}{data['key']}{data['key_salt']}{data['salt']}"
            if not self._validate_hash(data['hash'], message):
                return request.make_json_response({'error': 'Invalid signature'}, status=403)

            # Now use the environment with the proper user context
            Partner = request.env['res.partner'].browse(partner_id)
            if not Partner or not Partner.exists():
                raise ValidationError("Invalid partner")

            # Update the request environment with the authenticated user
            request.update_env(user=user)

            # Generate the bill using the model method, using accounting user for privileged creation
            accounting_user_id = self._get_accounting_user_id()
            accounting_user = request.env['res.users'].sudo().browse(accounting_user_id)
            if not accounting_user.exists():
                _logger.error(f"Accounting user with ID {accounting_user_id} not found")
                raise ValidationError("Accounting user not available")

            _logger.debug(f"Using accounting user: {accounting_user.name} (ID: {accounting_user.id}) for bill creation")

            # sale order _ account move creation
            so_am = request.env['charging.session.invoice'].with_user(accounting_user).sudo().generate(
                Partner,
                validated_data.lines_data,
                validated_data.parsed_due_date(),
                validated_data.parsed_invoice_date()
            )

            return request.make_json_response({
                'success': True,
                'details': so_am,
                'message': "Bill created successfully"
            }, status=201)

        except ValidationError as verror:
            return request.make_json_response({'error': str(verror)}, status=400)
        except Exception as error:
            _logger.error(f"Bill creation error: {str(error)}", exc_info=True, stack_info=True)
            return request.make_json_response({'error': str(error)}, status=500)

    @http.route('/internal/admin/connection-check', type='http', auth='public', methods=['GET'], csrf=False)
    def admin_connection_check(self, **kw):
        """
        Simple endpoint to check admin connection validity.
        Returns success if admin token is valid, error otherwise.
        """
        try:
            # Validate admin token
            if not self._validate_admin_token(request.httprequest.headers):
                return request.make_json_response({
                    'success': False,
                    'error': 'Invalid or missing admin token'
                }, status=401)

            # If we get here, the admin token is valid
            return request.make_json_response({
                'success': True,
                'message': 'Admin connection is valid',
                'timestamp': datetime.utcnow().strftime(self.datetime_format)
            }, status=200)

        except Exception as e:
            _logger.error(f"Admin connection check error: {str(e)}", exc_info=True, stack_info=True)
            return request.make_json_response({
                'success': False,
                'error': 'Internal server error'
            }, status=500)
