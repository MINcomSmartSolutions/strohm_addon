# -*- coding: utf-8 -*-
import logging
from datetime import date

from odoo import models, fields, api

_logger = logging.getLogger(__name__)


class SaleOrder(models.Model):
    _inherit = 'sale.order'

    @api.model
    def process_auto_invoicing(self):
        """
        Process auto invoicing for partners with monthly or quarterly billing.
        This method is called by a scheduled action (cron job).

        - Monthly: Invoices on the 1st of each month
        - Quarterly: Invoices on the 1st of Jan, Apr, Jul, Oct

        It finds all confirmed sale orders with pending invoicing for eligible
        partners and creates grouped invoices.
        """
        today = date.today()
        day = today.day
        month = today.month

        # Determine which billing frequencies to process today
        frequencies_to_process = []

        # Monthly: process on the 1st of every month
        if day == 1:
            frequencies_to_process.append('monthly')

        # Quarterly: process on the 1st of Jan(1), Apr(4), Jul(7), Oct(10)
        if day == 1 and month in (1, 4, 7, 10):
            frequencies_to_process.append('quarterly')

        if not frequencies_to_process:
            _logger.info("No billing frequencies to process today")
            return True

        _logger.info(f"Processing auto invoicing for frequencies: {frequencies_to_process}")

        # Find partners with the billing frequencies to process
        partners = self.env['res.partner'].sudo().search([
            ('billing_frequency', 'in', frequencies_to_process)
        ])

        if not partners:
            _logger.info("No partners found with billing frequencies to process")
            return True

        _logger.info(f"Found {len(partners)} partners to process for auto invoicing")

        invoices_created = 0

        for partner in partners:
            try:
                # Find confirmed sale orders with pending invoicing for this partner
                orders = self.sudo().search([
                    ('partner_id', '=', partner.id),
                    ('state', '=', 'sale'),  # Confirmed orders
                    ('invoice_status', '=', 'to invoice'),  # Not yet invoiced
                ])

                if not orders:
                    _logger.debug(f"No orders to invoice for partner {partner.name} (ID: {partner.id})")
                    continue

                _logger.info(f"Creating grouped invoice for partner {partner.name} with {len(orders)} orders")

                # Create grouped invoice for all orders of this partner
                invoices = orders._create_invoices(grouped=True)

                if invoices:
                    # Set invoice dates
                    invoices.write({
                        'invoice_date': fields.Date.today(),
                        'invoice_date_due': fields.Date.add(fields.Date.today(), months=1),
                    })
                    invoices_created += len(invoices)
                    _logger.info(f"Created invoice(s) {invoices.mapped('name')} for partner {partner.name}")

            except Exception as e:
                _logger.error(f"Error creating invoice for partner {partner.name} (ID: {partner.id}): {str(e)}", exc_info=True)
                continue

        _logger.info(f"Auto invoicing completed. Created {invoices_created} invoice(s)")
        return True
