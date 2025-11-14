import logging
import os

import werkzeug
from werkzeug import urls
from werkzeug.utils import redirect

from odoo import _
from odoo.addons.portal.controllers.portal import CustomerPortal, get_error
from odoo.http import request
from odoo.http import route

_logger = logging.getLogger(__name__)


class CustomCustomerPortal(CustomerPortal):
    """Extend the CustomerPortal class to add custom routes."""

    @route('/my/deactivate_account', type='http', auth='user', website=True, methods=['POST'])
    def deactivate_account(self, validation, **post):
        values = self._prepare_portal_layout_values()
        values['open_deactivate_modal'] = True
        values['get_error'] = get_error

        self.BACKEND_URL = os.environ.get('BACKEND_EXTERNAL_URL')

        if validation != request.env.user.login:
            values['error_message'] = _('The validation does not match your email.')
        else:
            # Check for open bills before allowing deactivation
            open_invoices = request.env['account.move'].sudo().search([
                ('partner_id', '=', request.env.user.partner_id.id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('payment_state', 'in', ['not_paid', 'partial'])
            ])

            if open_invoices:
                invoice_count = len(open_invoices)
                values['error_message'] = _('Das Konto kann nicht deaktiviert werden. Sie haben %s offene Rechnungen, die zuerst beglichen werden müssen.') % invoice_count
                _logger.warning(f"User {request.env.user.login} attempted to deactivate account with {invoice_count} open invoices")
            else:
                request.env.user.sudo()._deactivate_portal_user(**post)
                request.session.logout()

                return werkzeug.utils.redirect(
                    self.BACKEND_URL + '/logout?type=success&message=%s' % urls.url_quote(_('Konto gelöscht!')))

        return request.render('portal.portal_my_security', values, headers={
            'X-Frame-Options': 'SAMEORIGIN',
            'Content-Security-Policy': "frame-ancestors 'self'",
        })

    @route('/my/security/revoke_all_devices', type='http', auth='user', website=True, methods=['POST'])
    def portal_revoke_all_devices(self, **post):
        """
        Override revoke_all_devices to skip password verification.
        Portal users authenticate via passwordless methods (API keys), so password check is not applicable.
        """
        values = self._prepare_portal_layout_values()
        values['get_error'] = get_error

        # Skip password validation and directly revoke all devices
        try:
            request.env.user._revoke_all_devices()
            values['success_message'] = _('All devices have been revoked successfully.')
            _logger.info(f"User {request.env.user.login} revoked all devices (passwordless)")
        except Exception as e:
            values['error_message'] = _('An error occurred while revoking devices.')
            _logger.error(f"Error revoking devices for user {request.env.user.login}: {str(e)}")

        return request.render('portal.portal_my_security', values, headers={
            'X-Frame-Options': 'SAMEORIGIN',
            'Content-Security-Policy': "frame-ancestors 'self'",
        })

    # Append the has_active_payment field to the portal layout values to show a warning if the user has no active payment method/s
    # No use yet.
    def _prepare_portal_layout_values(self):
        portal_layout_values = super()._prepare_portal_layout_values()
        try:
            portal_layout_values['has_active_payment'] = request.env['payment.token'].sudo().search_count(
                [('partner_id', '=', request.env.user.partner_id.id), ('active', '=', True)]) > 0
        except Exception as e:
            _logger.error("Error checking active payment tokens: %s", e)
            portal_layout_values['has_active_payment'] = False
        return portal_layout_values
