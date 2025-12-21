# -*- coding: utf-8 -*-
import logging
from datetime import date

from odoo import models, fields, api

_logger = logging.getLogger(__name__)

# Maximum average power (kW) threshold for automatic invoice confirmation
# This is more of a simple check if the avg energy was delivered under the physical limits of the installed charging stations.
AUTO_CONFIRM_MAX_AVG_POWER_KW = 20.0


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
        if day == 1 and month in (4, 7, 10): # Add Jan(1) to the list after 01.01.26
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

        invoices_created = self.process_partners_invoicing(partners)
        _logger.info(f"Auto invoicing completed. Created {invoices_created} invoice(s)")
        return True

    @api.model
    def process_partners_invoicing(self, partners):
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

                # Filter orders to only include those with billable quantities (qty > 0)
                billable_orders = orders.filtered(
                    lambda o: any(
                        line.product_uom_qty > 0 or line.qty_delivered > 0 
                        for line in o.order_line
                    )
                )

                if not billable_orders:
                    _logger.debug(f"No billable orders (qty > 0) for partner {partner.name} (ID: {partner.id})")
                    continue

                _logger.info(f"Creating grouped invoice for partner {partner.name} with {len(billable_orders)} billable orders")

                # Create consolidated invoice for all billable orders of this partner
                # grouped=False means invoices are grouped by partner_id, currency_id (consolidated)
                # grouped=True would create one invoice per sale order (not consolidated)
                invoices = billable_orders._create_invoices(grouped=False)

                if invoices:
                    # Set invoice dates
                    invoices.write({
                        'invoice_date': fields.Date.today(),
                        'invoice_date_due': fields.Date.add(fields.Date.today(), months=1),
                    })
                    invoices_created += len(invoices)
                    _logger.info(f"Created invoice(s) {invoices.mapped('id')} for partner {partner.name}")

                    # Auto-confirm invoices where average power is under threshold
                    self._auto_confirm_low_power_invoices(invoices)

            except Exception as e:
                _logger.error(f"Error creating invoice for partner {partner.name} (ID: {partner.id}): {str(e)}", exc_info=True)
                continue

        return invoices_created

    @api.model
    def _calculate_invoice_average_power(self, invoice):
        """
        Calculate the average power (kW) for an invoice based on its lines.

        Average power is calculated as: total_kwh / duration_in_hours
        where duration is the time between session_start and session_end.

        Returns:
            float: Average power in kW, or None if calculation is not possible
                   (missing session times or zero duration)
        """
        if not invoice.session_start or not invoice.session_end:
            return None

        duration = invoice.session_end - invoice.session_start
        duration_hours = duration.total_seconds() / 3600.0

        if duration_hours <= 0:
            return None

        return invoice.total_kwh / duration_hours

    @api.model
    def _auto_confirm_low_power_invoices(self, invoices):
        """
        Automatically confirm (post) invoices where the average power is under the threshold.

        Average power = total_kwh / (session_end - session_start in hours)
        Invoices are only confirmed if the average power is under AUTO_CONFIRM_MAX_AVG_POWER_KW.

        Args:
            invoices: Recordset of account.move (invoices) to evaluate
        """
        for invoice in invoices:
            try:
                avg_power = self._calculate_invoice_average_power(invoice)

                if avg_power is None:
                    _logger.debug(
                        f"Cannot calculate average power for invoice {invoice.id}: "
                        f"missing session times or zero duration"
                    )
                    continue

                if avg_power < AUTO_CONFIRM_MAX_AVG_POWER_KW:
                    _logger.info(
                        f"Auto-confirming invoice {invoice.id} with average power "
                        f"{avg_power:.2f} kW (under {AUTO_CONFIRM_MAX_AVG_POWER_KW} kW threshold)"
                    )
                    invoice.action_post()
                else:
                    _logger.warning(
                        f"Invoice {invoice.id} NOT auto-confirmed: average power "
                        f"{avg_power:.2f} kW exceeds {AUTO_CONFIRM_MAX_AVG_POWER_KW} kW threshold"
                    )
            except Exception as e:
                _logger.error(
                    f"Error auto-confirming invoice {invoice.id}: {str(e)}",
                    exc_info=True
                )

