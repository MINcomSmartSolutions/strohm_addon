import logging
import os
from datetime import datetime

import werkzeug
from werkzeug import urls
from werkzeug.utils import redirect

from odoo import _
from odoo.addons.portal.controllers.portal import CustomerPortal, get_error, pager as portal_pager
from odoo.http import request
from odoo.http import route
from ..services.backend_service import get_backend_service

_logger = logging.getLogger(__name__)


class CustomCustomerPortal(CustomerPortal):
    """Extend the CustomerPortal class to add custom routes."""

    def _prepare_home_portal_values(self, counters):
        """Add session_count to portal home counters."""
        values = super()._prepare_home_portal_values(counters)
        # Always calculate session_count to ensure it appears in the portal
        if 'session_count' in counters:
            partner = request.env.user.partner_id
            SaleOrder = request.env['sale.order']
            AccountMove = request.env['account.move']
            
            so_count = SaleOrder.search_count([
                ('partner_id', '=', partner.id),
                ('session_start', '!=', False),
                ('session_end', '!=', False),
            ])
            
            # Count invoices that are NOT linked to sales (approximate for count)
            # We can't easily filter 'not linked' in search_count without a complex domain or join
            # For performance, we might just count all before the date, or accept a slight inaccuracy in the badge
            # But let's try to be accurate if possible.
            # Since we can't do a negative join in search_count easily, we'll fetch ids.
            am_domain = [
                ('partner_id', '=', partner.id),
                ('move_type', '=', 'out_invoice'),
                ('session_start', '!=', False),
                ('invoice_date', '<', '2025-12-09')
            ]
            invoices = AccountMove.search(am_domain)
            # Filter out invoices linked to sales
            invoices = invoices.filtered(lambda m: not m.invoice_line_ids.sale_line_ids)
            
            values['session_count'] = so_count + len(invoices)
        return values

    @route(['/my/sessions', '/my/sessions/page/<int:page>'], type='http', auth='user', website=True)
    def portal_my_sessions(self, page=1, date_begin=None, date_end=None, sortby=None, **kw):
        """
        Portal route to display charging sessions list.
        Sessions are sale.order records with session_start field set,
        AND account.move records (invoices) before 09.12.2025 with session_start set,
        excluding invoices that are already linked to sale orders.
        """
        values = self._prepare_portal_layout_values()
        SaleOrder = request.env['sale.order']
        AccountMove = request.env['account.move']
        partner = request.env.user.partner_id

        # Domains
        so_domain = [
            ('partner_id', '=', partner.id),
            ('session_start', '!=', False)
        ]
        
        am_domain = [
            ('partner_id', '=', partner.id),
            ('move_type', '=', 'out_invoice'),
            ('session_start', '!=', False),
            ('invoice_date', '<', '2025-12-18')
        ]

        searchbar_sortings = {
            'date': {'label': _('Charging Date'), 'order': 'date desc'},
            'session_start': {'label': _('Session Start'), 'order': 'session_start desc'},
            'session_end': {'label': _('Session End'), 'order': 'session_end desc'},
            'name': {'label': _('Reference'), 'order': 'name'},
        }
        if not sortby:
            sortby = 'session_start'
        
        # Date filtering
        if date_begin and date_end:
            so_domain += [('create_date', '>', date_begin), ('create_date', '<=', date_end)]
            am_domain += [('invoice_date', '>', date_begin), ('invoice_date', '<=', date_end)]

        # Fetch all records (needed for mixed sorting/pagination)
        orders = SaleOrder.search(so_domain)
        invoices = AccountMove.search(am_domain)
        
        # Filter out invoices that are linked to sale orders to avoid duplicates
        # We check if any invoice line is linked to a sale order line
        invoices = invoices.filtered(lambda m: not m.invoice_line_ids.sale_line_ids)
        
        sessions = list(orders) + list(invoices)
        
        # Sorting
        def get_sort_key(record):
            if sortby == 'date':
                val = record.date_order if record._name == 'sale.order' else record.invoice_date
                return str(val) if val else ''
            elif sortby == 'session_start':
                return str(record.session_start) if record.session_start else ''
            elif sortby == 'session_end':
                return str(record.session_end) if record.session_end else ''
            elif sortby == 'name':
                return record.name or ''
            return record.id

        reverse = 'desc' in searchbar_sortings[sortby]['order']
        sessions.sort(key=lambda x: get_sort_key(x), reverse=reverse)

        # Pager
        session_count = len(sessions)
        pager = portal_pager(
            url="/my/sessions",
            url_args={'date_begin': date_begin, 'date_end': date_end, 'sortby': sortby},
            total=session_count,
            page=page,
            step=self._items_per_page
        )

        # Slice for current page
        paginated_sessions = sessions[pager['offset']:pager['offset'] + self._items_per_page]
        
        values.update({
            'date': date_begin,
            'sessions': paginated_sessions,
            'page_name': 'session',
            'pager': pager,
            'default_url': '/my/sessions',
            'searchbar_sortings': searchbar_sortings,
            'sortby': sortby,
        })
        return request.render("strohm_addon.portal_my_sessions", values)

    def _check_active_charging_sessions(self, user_id, partner_id):
        """
        Check if user has active charging sessions via backend API.

        Args:
            user_id: Odoo user ID
            partner_id: Odoo partner ID

        Returns:
            tuple: (has_active_sessions: bool, error_message: str or None, session_data: dict or None)
        """
        if request.env.user.has_group('base.group_system'):
            return (False, None, None)

        backend_service = get_backend_service()

        # Make API call to backend to check for active charging sessions
        endpoint = f"/api/charging/session/active/{user_id}/{partner_id}"
        _logger.info(f"Checking active charging sessions via: {endpoint}")

        success, data, error = backend_service.get_internal(endpoint)
        if success and data:
            api_success = data.get('success', False)
            has_active = data.get('hasActiveSession', False)

            if not api_success:
                error_msg = data.get('error', 'Unknown error from backend API')
                _logger.error(f"Backend API error: {error_msg}")
                return (False, error_msg, None)

            session_data = data.get('session', None)

            _logger.info(f"Active charging sessions check: has_active={has_active}, session_data={session_data}")
            return (has_active, None, session_data)
        elif success and not data:
            # No active sessions found (404 was converted to exists=False)
            _logger.info(f"No active charging sessions found for user {user_id}")
            return (False, None, None)
        else:
            # Error occurred
            _logger.error(f"Error checking active sessions: {error}")
            return (False, error, None)

    def _get_electricity_price(self):
        """
        Get current electricity price from backend API.

        Returns:
            float or None: The electricity price in ct/kWh, or None if request fails
        """
        backend_service = get_backend_service()

        endpoint = "/api/electricity_price"
        _logger.info(f"Fetching electricity price via: {endpoint}")

        success, data, error = backend_service.get_internal(endpoint)
        if success and data:
            price = data.get('price_data').get('price_ct_kwh', None)
            valid_till = data.get('price_data').get('valid_till', None)
            _logger.info(f"Electricity price retrieved successfully: {price} ct/kWh")
            return price, valid_till
        else:
            _logger.error(f"Error fetching electricity price: {error}")
            return None

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
                ('state', 'in', ['posted', 'draft']),
                ('payment_state', 'in', ['not_paid', 'partial'])
            ])

            # Check for active charging sessions via backend API
            has_active_sessions, api_error, session_data = self._check_active_charging_sessions(
                request.env.user.id,
                request.env.user.partner_id.id
            )

            if open_invoices:
                invoice_count = len(open_invoices)
                values['error_message'] = _(
                    'The account cannot be deactivated. You have %s open invoice(s) that must be paid first.') % invoice_count
                _logger.warning(
                    f"User {request.env.user.login} attempted to deactivate account with {invoice_count} open invoices")
            elif has_active_sessions:
                values['error_message'] = _(
                    'The account cannot be deactivated. You have active charging session(s) that must be ended first.')
                _logger.warning(
                    f"User {request.env.user.login} attempted to deactivate account with active charging sessions")
            elif api_error:
                # If there was an API error, we should probably be cautious and not allow deactivation
                values['error_message'] = _(
                    'The account cannot be deactivated at this time. Please try again later.')
                _logger.error(
                    f"API error prevented account deactivation for user {request.env.user.login}: {api_error}")
            else:
                request.env.user.sudo()._deactivate_portal_user(**post)
                request.session.logout()

                return werkzeug.utils.redirect(
                    self.BACKEND_URL + '/logout?type=success&message=%s' % urls.url_quote(_('Account deleted!')))

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


    def _prepare_portal_layout_values(self):
        portal_layout_values = super()._prepare_portal_layout_values()
        try:
            price, valid_till = self._get_electricity_price() # To show the current price for info
            if price is not None:
                portal_layout_values['electricity_price_ct_kwh'] = price
            if valid_till is not None:
                # Format the datetime string to German format (dd.MM.yyyy HH:mm)
                try:
                    # Parse ISO format datetime string from API
                    dt = datetime.fromisoformat(valid_till.replace('Z', '+00:00'))
                    # Convert to user's timezone (assuming Europe/Berlin)
                    user_tz = request.env.user.tz or 'Europe/Berlin'
                    import pytz
                    dt_utc = dt.replace(tzinfo=pytz.UTC) if dt.tzinfo is None else dt
                    dt_local = dt_utc.astimezone(pytz.timezone(user_tz))
                    # Format as dd.MM.yyyy HH:mm
                    portal_layout_values['electricity_price_valid_till'] = dt_local.strftime('%d.%m.%Y %H:%M')
                except (ValueError, AttributeError) as e:
                    _logger.warning(f"Error formatting valid_till datetime: {e}")
                    portal_layout_values['electricity_price_valid_till'] = valid_till

            if request.env.user.partner_id.id and request.env.user.id:
                has_active_sessions, api_error, session_data = self._check_active_charging_sessions(
                    request.env.user.id,
                    request.env.user.partner_id.id
                )

                if api_error:
                    _logger.error("Error checking active charging sessions: %s", api_error)
                    portal_layout_values['has_active_charging_session'] = False
                else:
                    portal_layout_values['has_active_charging_session'] = has_active_sessions
                    portal_layout_values['active_charging_session_data'] = session_data


        except Exception as e:
            _logger.error("Error checking active payment tokens: %s", e)
            # portal_layout_values['has_active_payment'] = False
            portal_layout_values['has_active_charging_session'] = False
            portal_layout_values['electricity_price_ct_kwh'] = None
            portal_layout_values['active_charging_session_data'] = None
        return portal_layout_values
