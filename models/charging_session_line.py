import logging

from odoo import models, fields, api

_logger = logging.getLogger(__name__)


class SaleOrderLine(models.Model):
    """
    Extend sale.order.line to add charging session fields.
    These fields store the session start/end times for each charging session line item.
    """
    _inherit = 'sale.order.line'

    session_start = fields.Datetime(
        string='Session Start',
        help='Start datetime of the charging session (UTC)'
    )
    session_end = fields.Datetime(
        string='Session End',
        help='End datetime of the charging session (UTC)'
    )
    session_backend_ref = fields.Integer(
        string='Session Backend Reference',
        help='Reference ID of the charging session in the backend system'
    )

    def _prepare_invoice_line(self, **optional_values):
        """
        Override to propagate session fields from sale.order.line to account.move.line.
        """
        res = super()._prepare_invoice_line(**optional_values)
        if self.session_start:
            res['session_start'] = self.session_start
        if self.session_end:
            res['session_end'] = self.session_end
        if self.session_backend_ref:
            res['session_backend_ref'] = self.session_backend_ref
        return res


class AccountMoveLine(models.Model):
    """
    Extend account.move.line to add charging session fields.
    These fields are populated from sale.order.line during invoicing.
    """
    _inherit = 'account.move.line'

    session_start = fields.Datetime(
        string='Session Start',
        help='Start datetime of the charging session (UTC)'
    )
    session_end = fields.Datetime(
        string='Session End',
        help='End datetime of the charging session (UTC)'
    )
    session_backend_ref = fields.Integer(
        string='Session Backend Reference',
        help='Reference ID of the charging session in the backend system'
    )


class SaleOrder(models.Model):
    """
    Extend sale.order to add computed fields for session summary.
    """
    _inherit = 'sale.order'

    session_start = fields.Datetime(
        string='Earliest Session Start',
        compute='_compute_session_times',
        store=True,
        help='Earliest session start time from all order lines'
    )
    session_end = fields.Datetime(
        string='Latest Session End',
        compute='_compute_session_times',
        store=True,
        help='Latest session end time from all order lines'
    )
    total_kwh = fields.Float(
        string='Total Charged Energy (kWh)',
        compute='_compute_total_kwh',
        store=True,
        help='Total energy charged in kWh from all order lines'
    )

    @api.depends('order_line.session_start', 'order_line.session_end')
    def _compute_session_times(self):
        for order in self:
            starts = order.order_line.filtered('session_start').mapped('session_start')
            ends = order.order_line.filtered('session_end').mapped('session_end')
            order.session_start = min(starts) if starts else False
            order.session_end = max(ends) if ends else False

    @api.depends('order_line.product_uom_qty', 'order_line.product_uom')
    def _compute_total_kwh(self):
        """Calculate total kWh from order lines with Energy unit of measure category"""
        energy_category = self.env.ref('strohm_addon.uom_categ_energy', raise_if_not_found=False)
        for order in self:
            total = 0.0
            for line in order.order_line:
                if line.product_uom and energy_category and line.product_uom.category_id == energy_category:
                    total += line.product_uom_qty
            order.total_kwh = total
