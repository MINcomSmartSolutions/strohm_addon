# -*- coding: utf-8 -*-
from odoo import models, api
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

    def unlink(self):
        """Override unlink to handle cascading deletion of partner when user is deleted"""
        # Skip partner deletion if this deletion was triggered by partner deletion (to avoid infinite recursion)
        if self.env.context.get('skip_partner_deletion'):
            return super().unlink()

        # Store partner information before deletion for sync
        partner_data_list = []

        for user in self:
            # Only handle portal users
            if not user.has_group('base.group_portal'):
                continue

            if user.partner_id:
                partner = user.partner_id

                # Check if this partner has other users (excluding the current one being deleted)
                other_users = partner.user_ids.filtered(lambda u: u.id != user.id)

                if not other_users:
                    # Partner will be orphaned, so we should delete it too
                    partner_data = {
                        'id': partner.id,
                        'name': partner.name,
                        'email': partner.email,
                        'user_ids': [user.id],
                        'has_portal_user': True,
                        'deletion_triggered_by': 'user_deletion'
                    }
                    partner_data_list.append((partner, partner_data))

                    _logger.info(f"User {user.id} deletion will trigger partner {partner.id} deletion")

        # Call the original unlink method first
        result = super().unlink()

        # After successful user deletion, delete orphaned partners and sync
        for partner, partner_data in partner_data_list:
            try:
                # Sync the partner deletion to backend
                self.env['strohm_addon.partner_sync'].sync_partner_deletion(partner_data)

                # Delete the partner (this will prevent triggering user deletion again)
                # We need to use sudo() and set a context flag to avoid infinite recursion
                partner.with_context(skip_user_deletion=True).sudo().unlink()

            except Exception as e:
                _logger.error(f"Failed to delete orphaned partner {partner.id} after user deletion: {str(e)}")

        return result
