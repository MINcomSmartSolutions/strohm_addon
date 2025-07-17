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

        backend_port = os.environ.get('BACKEND_PORT', '3000')
        self.BACKEND_URL = f"http://localhost:{backend_port}"

        if validation != request.env.user.login:
            values['error_message'] = _('The validation code does not match your login.')
        else:
            request.env.user.sudo()._deactivate_portal_user(**post)
            request.session.logout()

            return werkzeug.utils.redirect(
                self.BACKEND_URL + '/logout?message=%s' % urls.url_quote(_('Account deleted!')))

        return request.render('portal.portal_my_security', values, headers={
            'X-Frame-Options': 'SAMEORIGIN',
            'Content-Security-Policy': "frame-ancestors 'self'",
        })

    # Append the has_active_payment field to the portal layout values to show a warning if the user has no active payment method/s
    def _prepare_portal_layout_values(self):
        portal_layout_values = super()._prepare_portal_layout_values()
        try:
            portal_layout_values['has_active_payment'] = request.env['payment.token'].sudo().search_count(
                [('partner_id', '=', request.env.user.partner_id.id), ('active', '=', True)]) > 0
        except Exception as e:
            _logger.error("Error checking active payment tokens: %s", e)
            portal_layout_values['has_active_payment'] = False
        return portal_layout_values
