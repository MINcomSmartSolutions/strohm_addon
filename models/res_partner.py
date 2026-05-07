# -*- coding: utf-8 -*-
import logging

from odoo import models, fields, api

_logger = logging.getLogger(__name__)


class ResPartner(models.Model):
    _inherit = 'res.partner'

    def _get_gravatar_image(self, email):
        return False

    billing_frequency = fields.Selection(
        selection=[
            ('session', 'Per Session'),
            ('monthly', 'Monthly'),
            ('quarterly', 'Quarterly'),
        ],
        string='Billing Frequency',
        default='quarterly',
        help='Determines how often invoices are generated for charging sessions. '
             'Per Session: Invoice immediately after each session. '
             'Monthly: Invoice on the 1st of each month. '
             'Quarterly: Invoice on the 1st of Jan, Apr, Jul, Oct.'
    )

    finance_handover = fields.Boolean(
        string='Finance Handover (Mahnstufe 3)',
        default=False,
        tracking=True,
        help='If True, the customer has reached Mahnstufe 3 and portal payments are blocked. '
             'Payment must be handled externally through Finance.'
    )

    highest_dunning_level = fields.Selection(
        selection=[
            ('0', 'No Dunning'),
            ('1', 'Mahnstufe 1'),
            ('2', 'Mahnstufe 2'),
            ('3', 'Mahnstufe 3'),
        ],
        string='Highest Dunning Level',
        compute='_compute_highest_dunning_level',
        store=True,
    )

    @api.depends('invoice_ids.dunning_level', 'invoice_ids.payment_state')
    def _compute_highest_dunning_level(self):
        for partner in self:
            unpaid_invoices = partner.invoice_ids.filtered(
                lambda inv: inv.move_type == 'out_invoice'
                and inv.state == 'posted'
                and inv.payment_state in ('not_paid', 'partial')
            )
            if unpaid_invoices:
                levels = unpaid_invoices.mapped('dunning_level')
                # Get the highest numeric dunning level
                max_level = max(int(l) for l in levels if l)
                partner.highest_dunning_level = str(max_level)
            else:
                partner.highest_dunning_level = '0'


    # FIXME: What if for somereason cannot suspend charging (block steve user)?
    def _suspend_charging_account(self):
        """Send request to backend for blocking the charging of user"""
        from ..services.backend_service import get_backend_service

        _logger.info(f"Suspending charging account for partner {self.name} (ID: {self.id})")

        backend_service = get_backend_service()
        success, response, error = backend_service.suspend_user(self.id, self.name)

        if success:
            _logger.info(f"Successfully suspended charging for partner {self.name}")
        else:
            _logger.error(f"Failed to suspend charging for partner {self.name}: {error}")

        return success

    # FIXME: What if for somereason cannot reactive charging (unblock steve user)?
    def _reactivate_charging_account(self):
        """Send request to backend for unblocking the charging of user"""
        from ..services.backend_service import get_backend_service

        _logger.info(f"Reactivating charging account for partner {self.name} (ID: {self.id})")

        backend_service = get_backend_service()
        success, response, error = backend_service.reactivate_user(self.id, self.name)

        if success:
            _logger.info(f"Successfully reactivated charging for partner {self.name}")
        else:
            _logger.error(f"Failed to reactivate charging for partner {self.name}: {error}")

        return success

    def _check_dunning_reactivation(self, previous_level):
        """
        Check if a partner should be reactivated after an invoice payment.
        Called when an invoice's dunning level is reset to 0.
        """
        remaining_m2_m3 = self.env['account.move'].search_count([
            ('partner_id', '=', self.id),
            ('move_type', '=', 'out_invoice'),
            ('state', '=', 'posted'),
            ('payment_state', 'in', ['not_paid', 'partial']),
            ('dunning_level', 'in', ['2', '3']),
        ])

        if remaining_m2_m3 == 0:
            # No more M2/M3 invoices - reactivate the account
            if previous_level in ('2', '3'):
                self._reactivate_charging_account()

            # Clear finance handover flag
            if self.finance_handover:
                self.sudo().write({'finance_handover': False})
                _logger.info(f"Finance handover cleared for partner {self.name}")

    def action_immediate_invoice(self):
        """
        Manually trigger invoicing for the selected partners, regardless of their billing frequency.
        """
        self.env['sale.order'].process_partners_invoicing(self)
