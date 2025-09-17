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

# import debugpy

_logger = logging.getLogger(__name__)


class StrohmAPI(Controller):
    def __init__(self):
        super().__init__()
        _logger.info("Initializing StrohmAPI")
        self.datetime_format = "%Y-%m-%dT%H:%M:%S"

        # debugpy.wait_for_client()
        # debugpy.breakpoint()

        if os.environ.get('ODOO_ENV') == 'dev':
            _logger.setLevel(logging.DEBUG)

        # Check current company and its fiscal country
        company = request.env.company
        if not company:
            company = request.env['res.company'].sudo().search([], limit=1)
        _logger.info(f"Using company: {company.name} (id: {company.id})")
        if company.country_id.code != 'DE':
            _logger.warning(
                f"Company {company.name} does not have Germany set as fiscal country. Current: {company.country_id.name or 'Not set'}")
        else:
            _logger.info(f"Company {company.name} has correct fiscal country: {company.country_id.name}")

        # Check if de_DE is enabled
        lang = request.env['res.lang'].sudo().search([('code', '=', 'de_DE')], limit=1)
        if not lang:
            # If language doesn't exist in the database, install it
            _logger.warning("German language (de_DE) not found, please install it")
        elif not lang.active:
            # If language exists but is not active, activate it
            lang.sudo().write({'active': True})
            _logger.debug("German language (de_DE) activated")

        # Initialize standard products during API startup
        self._ensure_standard_products()

        # Initialize accounting user for invoice operations
        self.accounting_user_id = self._ensure_accounting_user()

        self.API_SECRET = os.environ.get('ODOO_API_SECRET')
        if not self.API_SECRET:
            _logger.error("API secret not found in environment variables. Please set ODOO_API_SECRET")
            raise ValueError("API secret not found in environment variables. Please set ODOO_API_SECRET")

    def _ensure_standard_products(self):
        """Pre-create standard products used by the charging system"""
        try:
            _logger.info("Ensuring standard charging products exist")

            # Use the ChargingSessionInvoice model to ensure products exist
            charging_model = request.env['charging.session.invoice'].sudo()
            self.standard_products = charging_model.ensure_standard_products()

        except Exception as e:
            _logger.error(f"Failed to initialize standard products: {str(e)}", exc_info=True)

    def _ensure_accounting_user(self):
        """Ensure an accounting user exists for invoice operations"""
        try:
            _logger.info("Ensuring accounting user exists for invoice operations")
            # TODO: In every init it tries to create a new accounting user, and it look like it goes through but it doesn't

            # Get current company
            company = request.env.company
            if not company:
                company = request.env['res.company'].sudo().search([], limit=1)

            # Create accounting user name based on company
            accounting_user_name = f"{company.name} Buchhaltung"
            accounting_user_login = f"accounting_{company.id}@{company.name.lower().replace(' ', '_')}.internal"

            # Check if accounting user already exists
            accounting_user = request.env['res.users'].sudo().search([
                ('login', '=', accounting_user_login)
            ], limit=1)

            if accounting_user:
                _logger.info(f"Accounting user already exists: {accounting_user.name} (ID: {accounting_user.id})")
                return accounting_user.id

            # Create partner for the accounting user
            partner_vals = {
                'name': accounting_user_name,
                'email': accounting_user_login,
                'is_company': False,
                'supplier_rank': 0,
                'customer_rank': 0,
                'company_id': company.id,
                'lang': 'de_DE',
                'tz': 'Europe/Berlin',
            }

            partner = request.env['res.partner'].sudo().create(partner_vals)
            _logger.info(f"Created accounting partner: {partner.name} (ID: {partner.id})")

            # Get required groups for accounting operations
            account_user_group = request.env.ref('account.group_account_user')
            account_invoice_group = request.env.ref('account.group_account_invoice')
            base_user_group = request.env.ref('base.group_user')

            # Verify groups exist
            if not account_user_group:
                _logger.error("account.group_account_user not found")
                raise ValidationError("Required accounting group not found")
            if not account_invoice_group:
                _logger.error("account.group_account_invoice not found")
                raise ValidationError("Required invoice group not found")
            if not base_user_group:
                _logger.error("base.group_user not found")
                raise ValidationError("Required base user group not found")

            # Create the accounting user
            user_vals = {
                'name': accounting_user_name,
                'login': accounting_user_login,
                'email': accounting_user_login,
                'partner_id': partner.id,
                'company_id': company.id,
                'company_ids': [(6, 0, [company.id])],
                'lang': 'de_DE',
                'tz': 'Europe/Berlin',
                'active': True,
                'groups_id': [(6, 0, [
                    base_user_group.id,
                    account_user_group.id,
                    account_invoice_group.id,
                ])],
            }

            accounting_user = request.env['res.users'].sudo().with_context(
                no_reset_password=True
            ).create(user_vals)

            _logger.info(f"Created accounting user: {accounting_user.name} (ID: {accounting_user.id})")
            _logger.info(f"Accounting user groups: {[g.name for g in accounting_user.groups_id]}")

            # Verify the user has the required permissions
            try:
                # Test if user can create account.move records
                test_env = request.env['account.move'].with_user(accounting_user).sudo()
                if not test_env.check_access('create'):
                    _logger.warning("Accounting user may not have sufficient permissions for account.move creation")
                else:
                    _logger.info("Accounting user has proper permissions for account.move creation")
            except Exception as e:
                _logger.warning(f"Could not verify accounting user permissions: {str(e)}")

            return accounting_user.id

        except Exception as e:
            _logger.error(f"Failed to ensure accounting user: {str(e)}", exc_info=True)
            # Fallback to admin user if creation fails
            admin_user = request.env['res.users'].sudo().search([('login', '=', 'admin')], limit=1)
            if admin_user:
                _logger.warning(f"Falling back to admin user for accounting operations: {admin_user.id}")
                return admin_user.id
            else:
                # Final fallback to superuser
                _logger.error("No admin user found, falling back to superuser (ID: 1)")
                return 1

    def _get_accounting_user_id(self):
        """Get accounting user ID, recreating if necessary"""
        try:
            # Check if current accounting user still exists
            if hasattr(self, 'accounting_user_id') and self.accounting_user_id:
                accounting_user = request.env['res.users'].sudo().browse(self.accounting_user_id)
                if accounting_user.exists() and accounting_user.active:
                    return self.accounting_user_id
                else:
                    _logger.warning(
                        f"Accounting user {self.accounting_user_id} no longer exists or is inactive, recreating...")

            # Recreate accounting user if it doesn't exist
            self.accounting_user_id = self._ensure_accounting_user()
            return self.accounting_user_id

        except Exception as e:
            _logger.error(f"Failed to get accounting user ID: {str(e)}", exc_info=True)
            return 1  # Fallback to superuser

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

        _logger.debug("🔑 Decrypting API key")
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
            _logger.debug("🔑 API key decrypted successfully")
            return decrypted_key
        except InvalidToken:
            raise ValidationError("Invalid API or salt")
        except Exception as e:
            _logger.error(f"Decryption failed: {str(e)}", exc_info=e, stack_info=True)
            raise ValueError(f"Decryption failed: {str(e)}")

    def _validate_admin_token(self, headers):
        """Validate Bearer token from Authorization header"""

        # TODO Even tough the uri is internal and not exposed to internet, admin token can be hijacked? Better hash it.

        auth_header = headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False

        token = auth_header.split(' ')[1]
        if not token:
            _logger.debug("❌ No token provided in Authorization header.")
            return False

        # Verify token using _check_credentials
        admin_id = request.env['res.users.apikeys'].sudo()._check_credentials(scope='rpc', key=token)
        if not admin_id:
            _logger.debug("❌ Token verification failed.")
            return False

        _logger.debug("✅ Token verification succeeded.")

        # Update request environment with the authenticated user
        admin = request.env['res.users'].sudo().browse(admin_id)
        if not admin.has_group('base.group_system'):
            _logger.debug("❌ Admin doesn't have system access.")
            return False

        _logger.debug("✅ Admin has system access.")
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
            if existing_partner:
                return request.make_json_response(
                    {'error': f'A partner with email {validated_data.email} already exists'}, status=409
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
                'name': data.get('name'),
                'login': data.get('email'),
                'email': data.get('email'),
                'partner_id': partner.id,
                'lang': 'de_DE',
                'active': True,
                'groups_id': [(6, 0, [portal_group.id])],
            }

            # Check if user with this login/email already exists
            existing_user = request.env['res.users'].sudo().search([('login', '=', data.get('email'))], limit=1)
            if existing_user:
                return request.make_json_response({'error': f'A user with email {data.get("email")} already exists'},
                                                  status=409)

            user = request.env['res.users'].sudo().with_context(no_reset_password=True).create(user_values)

            # Generate and store API key for new user using the new method
            api_key = request.env['res.users.apikeys'].sudo()._generate_for_user(
                user.id,
                'rpc',  # scope
                'Auto-generated User API key',  # name
                None  # TODO: Set a viable expiration_date
            )
            _logger.info(f"🔑 Generated API key for user {user.id}: {api_key}")

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
                validated_data = PortalLogin(**kw)
            except PydanticValidationError as e:
                errors = e.errors()
                error_msgs = [f"{err['loc'][0]}: {err['msg']}" for err in errors]
                return request.make_json_response({'error': error_msgs}, status=400)

            # Verify timestamp isn't too old (5-minute window)
            timestamp_unix = int(validated_data.parsed_timestamp().timestamp())
            if int(time.time()) - timestamp_unix > 300:
                return request.make_json_response({'error': 'Link expired'}, status=403)

            # Decrypt API key
            decrypted_key = self._decrypt_api_key(validated_data.key, validated_data.key_salt)
            _logger.debug('🔑 User API key decrypted successfully')

            # Directly check the API key
            user_id = request.env['res.users.apikeys'].sudo()._check_credentials(scope='rpc', key=decrypted_key)
            if not user_id:
                raise AccessDenied("Invalid API key")

            # Create the message that was used for the signature
            message = f"{validated_data.timestamp}{user_id}{validated_data.key}{validated_data.key_salt}{validated_data.salt}"
            if not (self._validate_hash(validated_data.hash, message)):
                return request.make_json_response({'error': 'Invalid signature'}, status=403)

            _logger.debug(f"🔑 User ID: {user_id}")

            user = request.env['res.users'].sudo().browse(user_id)
            if not user or not user.exists() or not user.active:
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

                _logger.debug('🔑 User session set up successfully')

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

    @http.route('/internal/bill/create', type='http', auth='public', methods=['POST'], csrf=False)
    def create_bill(self, **kw):
        try:
            # Parse and validate request data with Pydantic
            try:
                data = json.loads(request.httprequest.data)
                validated_data = BillCreate(**data)
            except PydanticValidationError as e:
                errors = e.errors()
                error_msgs = [f"{err['loc'][0]}: {err['msg']}" for err in errors]
                return request.make_json_response({'error': error_msgs}, status=400)
            except json.JSONDecodeError:
                return request.make_json_response({'error': 'Invalid JSON'}, status=400)

            # Create the message that was used for the signature
            message = f"{validated_data.timestamp}{validated_data.user_id}{validated_data.partner_id}{validated_data.session_start}{validated_data.session_end}{validated_data.key}{validated_data.key_salt}{validated_data.salt}"
            if not self._validate_hash(validated_data.hash, message):
                return request.make_json_response({'error': 'Invalid signature'}, status=403)

            # Parse timestamps to datetime objects
            session_start = datetime.strptime(validated_data.session_start, self.datetime_format)
            session_end = datetime.strptime(validated_data.session_end, self.datetime_format)
            timestamp_dt = datetime.strptime(validated_data.timestamp, self.datetime_format)

            # Verify timestamp isn't too old (5-minute window)
            timestamp_unix = int(timestamp_dt.timestamp())
            if int(time.time()) - timestamp_unix > 300:
                return request.make_json_response({'error': 'Expired'}, status=403)

            # Decrypt API key and authenticate user
            decrypted_key = self._decrypt_api_key(validated_data.key, validated_data.key_salt)
            _logger.debug('🔑 API key decrypted successfully')

            # Directly check the API key
            user_id = request.env['res.users.apikeys'].sudo()._check_credentials(scope='rpc', key=decrypted_key)
            if not user_id:
                raise ValidationError("Invalid API key")

            # Get the authenticated user and update the request environment
            user = request.env['res.users'].sudo().browse(user_id)
            if not user.exists():
                raise ValidationError("User not found")

            # Update the request environment with the authenticated user
            request.update_env(user=user)

            # Now use the environment with the proper user context
            Partner = request.env['res.partner'].browse(validated_data.partner_id)
            if not Partner.exists() or Partner.id != user.partner_id.id:
                raise ValidationError("Invalid partner")

            # Generate the bill using the model method, using accounting user for privileged creation
            accounting_user_id = self._get_accounting_user_id()
            accounting_user = request.env['res.users'].sudo().browse(accounting_user_id)
            if not accounting_user.exists():
                _logger.error(f"Accounting user with ID {accounting_user_id} not found")
                raise ValidationError("Accounting user not available")

            _logger.debug(f"Using accounting user: {accounting_user.name} (ID: {accounting_user.id}) for bill creation")

            bill = request.env['charging.session.invoice'].with_user(accounting_user).sudo().generate(
                session_start,
                session_end,
                Partner,
                validated_data.lines_data
            )

            return request.make_json_response({
                'success': True,
                'bill_id': bill.id,
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
