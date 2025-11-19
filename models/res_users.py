# -*- coding: utf-8 -*-
from odoo import models, api
import logging

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = 'res.users'

    #TODO:NEEDS REVIEW - currently disabled to allow users to revoke devices

    # def action_revoke_all_devices(self):
    #     """
    #     Override to allow revoking all devices without password verification.
    #     Portal users authenticate via API keys (passwordless), so password check is not applicable.
    #
    #     This method revokes all trusted devices for TOTP/2FA except the current one.
    #     The current session will remain active.
    #     """
    #     _logger.info(f"Revoking all devices for user {self.id} (passwordless mode)")
    #
    #     # Get the current device cookie if it exists
    #     current_device_cookie = self.env.context.get('totp_device_cookie')
    #
    #     # Clear all trusted devices for this user except current one
    #     if current_device_cookie and self.totp_trusted_device_ids:
    #         # Keep only the current device
    #         current_device = self.totp_trusted_device_ids.filtered(
    #             lambda d: d.device_cookie == current_device_cookie
    #         )
    #         if current_device:
    #             # Remove all devices except current
    #             to_remove = self.totp_trusted_device_ids - current_device
    #             self.sudo().write({'totp_trusted_device_ids': [(3, d.id) for d in to_remove]})
    #         else:
    #             # No current device found, remove all
    #             self.sudo().write({'totp_trusted_device_ids': [(5, 0, 0)]})
    #     else:
    #         # No current device or no trusted devices, remove all
    #         self.sudo().write({'totp_trusted_device_ids': [(5, 0, 0)]})
    #
    #     _logger.info(f"Successfully revoked devices for user {self.id}")
    #     return True

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
                # Check if partner can be safely deleted
                can_delete = self._check_partner_can_be_deleted(partner)

                if can_delete:
                    # Sync the partner deletion to backend
                    self.env['strohm_addon.partner_sync'].sync_partner_deletion(partner_data)

                    # Delete the partner (this will prevent triggering user deletion again)
                    # We need to use sudo() and set a context flag to avoid infinite recursion
                    partner.with_context(skip_user_deletion=True).sudo().unlink()

                    _logger.info(f"Successfully deleted orphaned partner {partner.id} after user deletion")
                else:
                    # Partner has blocking records (invoices, etc.), so archive it instead
                    _logger.warning(f"Cannot delete partner {partner.id} due to related records (invoices, etc.). Archiving instead.")

                    # Sync the partner deletion to backend (business logic requires it)
                    self.env['strohm_addon.partner_sync'].sync_partner_deletion(partner_data)

                    # Archive the partner instead of deleting
                    partner.with_context(skip_user_deletion=True).sudo().write({'active': False})

                    _logger.info(f"Successfully archived orphaned partner {partner.id} after user deletion")

            except Exception as e:
                _logger.error(f"Failed to handle orphaned partner {partner.id} after user deletion: {str(e)}")

        return result

    def _check_partner_can_be_deleted(self, partner):
        """
        Check if a partner can be safely deleted.
        Returns True if safe to delete, False if partner has blocking records.

        Common blocking scenarios in Odoo:
        - Active or draft invoices (account.move)
        - Payment transactions
        - Sale orders
        - Purchase orders
        - Other related records with ondelete='restrict' or 'cascade'
        """
        try:
            # Check for invoices (including archived ones)
            invoices = self.env['account.move'].sudo().with_context(active_test=False).search([
                ('partner_id', '=', partner.id)
            ], limit=1)

            if invoices:
                _logger.info(f"Partner {partner.id} has related invoices, cannot delete")
                return False

            # Check for sale orders (including archived)
            if 'sale.order' in self.env:
                sale_orders = self.env['sale.order'].sudo().with_context(active_test=False).search([
                    ('partner_id', '=', partner.id)
                ], limit=1)

                if sale_orders:
                    _logger.info(f"Partner {partner.id} has related sale orders, cannot delete")
                    return False

            # Check for payment transactions
            if 'payment.transaction' in self.env:
                payment_transactions = self.env['payment.transaction'].sudo().with_context(active_test=False).search([
                    ('partner_id', '=', partner.id)
                ], limit=1)

                if payment_transactions:
                    _logger.info(f"Partner {partner.id} has related payment transactions, cannot delete")
                    return False

            # If we get here, partner should be safe to delete
            return True

        except Exception as e:
            # On any error, assume partner cannot be deleted to be safe
            _logger.error(f"Error checking if partner {partner.id} can be deleted: {str(e)}")
            return False

