# -*- coding: utf-8 -*-
import logging

from odoo import models, fields

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

    def action_immediate_invoice(self):
        """
        Manually trigger invoicing for the selected partners, regardless of their billing frequency.
        """
        self.env['sale.order'].process_partners_invoicing(self)
