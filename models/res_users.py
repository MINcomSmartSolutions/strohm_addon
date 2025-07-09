# -*- coding: utf-8 -*-
from odoo import models, fields, api
import logging

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = 'res.users'

    def _mfa_type(self):
        """Override to completely disable 2FA"""
        return None

    def _mfa_url(self):
        """Override to disable 2FA URL redirection"""
        return None

    def _should_alert_new_device(self):
        """Override to disable new device alerts"""
        return False

    def _rpc_api_keys_only(self):
        """Override to allow password-based RPC even if 2FA was enabled"""
        return super(ResUsers, self)._rpc_api_keys_only()

    @api.model
    def _totp_check(self, code):
        """Override to disable TOTP validation"""
        _logger.info("2FA check: BYPASSED - 2FA is disabled")
        return True

    def _totp_try_setting(self, secret, code):
        """Override to prevent enabling 2FA"""
        _logger.info("2FA enable: BLOCKED - 2FA is disabled")
        return False

    def action_totp_disable(self):
        """Override to handle 2FA disable requests"""
        _logger.info("2FA disable: SUCCESS - 2FA is already disabled")
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'type': 'info',
                'message': 'Two-factor authentication is disabled',
                'next': {'type': 'ir.actions.act_window_close'},
            }
        }

    def action_totp_enable_wizard(self):
        """Override to prevent enabling 2FA"""
        _logger.info("2FA enable wizard: BLOCKED - 2FA is disabled")
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'type': 'warning',
                'message': 'Two-factor authentication is disabled on this system',
                'next': {'type': 'ir.actions.act_window_close'},
            }
        }

    @api.depends('totp_secret')
    def _compute_totp_enabled(self):
        """Override to always show 2FA as disabled"""
        for record in self:
            record.totp_enabled = False
