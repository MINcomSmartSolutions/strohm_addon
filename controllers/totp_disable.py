# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request
from odoo.addons.auth_totp.controllers.home import Home as TOTPHome
import logging

_logger = logging.getLogger(__name__)


class DisableTOTPController(TOTPHome):
    """Controller to disable all TOTP-related functionality"""

    @http.route('/web/login/totp', type='http', auth='public', methods=['GET', 'POST'], csrf=False)
    def totp_login(self, **kwargs):
        """Override TOTP login to redirect to normal login"""
        _logger.info("TOTP login bypassed - redirecting to normal login")
        return request.redirect('/web/login')

    @http.route('/web/login/totp/json', type='json', auth='public', methods=['POST'], csrf=False)
    def totp_login_json(self, **kwargs):
        """Override TOTP JSON login to return success"""
        _logger.info("TOTP JSON login bypassed")
        return {'success': True, 'redirect': '/web'}

    @http.route('/web/login/totp/disable', type='http', auth='user', methods=['POST'], csrf=False)
    def totp_disable(self, **kwargs):
        """Override TOTP disable to return success"""
        _logger.info("TOTP disable request bypassed")
        return request.redirect('/web')

    @http.route('/web/login/totp/enable', type='http', auth='user', methods=['POST'], csrf=False)
    def totp_enable(self, **kwargs):
        """Override TOTP enable to prevent activation"""
        _logger.info("TOTP enable request blocked")
        return request.redirect('/web')
