# -*- coding: utf-8 -*-
import logging

from odoo import models, fields, api

_logger = logging.getLogger(__name__)


class AccountMoveDunning(models.Model):
    _inherit = 'account.move'

    dunning_level = fields.Selection(
        selection=[
            ('0', 'No Dunning'),
            ('1', 'Mahnstufe 1 - Reminder Sent'),
            ('2', 'Mahnstufe 2 - Account Disconnected'),
            ('3', 'Mahnstufe 3 - Handed to Finance'),
        ],
        string='Dunning Level',
        default='0',
        tracking=True,
        copy=False,
        help='Tracks the dunning (Mahnwesen) stage of this invoice.'
    )

    dunning_level_date = fields.Date(
        string='Dunning Level Date',
        copy=False,
        help='Date when the current dunning level was set.'
    )

    def write(self, vals):
        """Override write to detect payment state changes and trigger reactivation."""
        res = super().write(vals)

        #FIXME: This is not advisable at all, query on every change of an account.move is bad
        #BUT for payment changes vals did not include that in the vals. So this is temp. here
        paid_invoices = self.filtered(
            lambda inv: inv.move_type == 'out_invoice' and inv.dunning_level != '0' and inv.payment_state == 'paid'
        )
        for invoice in paid_invoices:
            invoice._on_invoice_paid()

        return res

    def _on_invoice_paid(self):
        """Handle dunning reset when an invoice is paid."""
        previous_level = self.dunning_level
        self.sudo().write({
            'dunning_level': '0',
            'dunning_level_date': False,
        })
        _logger.info(
            f"Invoice {self.name} paid - dunning level reset from {previous_level} to 0 "
            f"(partner: {self.partner_id.name})"
        )

        # Check if partner should be reactivated
        partner = self.partner_id
        partner._check_dunning_reactivation(previous_level)

    @api.model
    def _cron_process_dunning(self):
        """
        Daily cron job to process dunning levels for overdue invoices.
        Transitions invoices through Mahnstufe 1 -> 2 -> 3 based on days overdue.
        """
        today = fields.Date.today()
        _logger.info("Starting dunning cron job...")

        # Find all posted, unpaid customer invoices with a due date
        overdue_invoices = self.search([
            ('move_type', '=', 'out_invoice'),
            ('state', '=', 'posted'),
            ('payment_state', 'in', ['not_paid', 'partial']),
            ('invoice_date_due', '!=', False),
            ('invoice_date_due', '<', today),
        ])

        m1_count = 0
        m2_count = 0
        m3_count = 0

        for invoice in overdue_invoices:
            days_overdue = (today - invoice.invoice_date_due).days

            if days_overdue >= 90 and invoice.dunning_level == '2':
                invoice._transition_to_m3()
                m3_count += 1

            elif days_overdue >= 60 and invoice.dunning_level == '1':
                invoice._transition_to_m2()
                m2_count += 1

            elif days_overdue >= 30 and invoice.dunning_level == '0':
                invoice._transition_to_m1()
                m1_count += 1

        if m3_count > 0:
            # TODO: Remove or add the functionality
            self._notify_finance_m3()

        _logger.info(
            f"Dunning cron completed: M1={m1_count}, M2={m2_count}, M3={m3_count}"
        )

    def _transition_to_m1(self):
        """Transition invoice to Mahnstufe 1: Send friendly reminder."""
        self.sudo().write({
            'dunning_level': '1',
            'dunning_level_date': fields.Date.today(),
        })
        _logger.info(f"Invoice {self.name} -> Mahnstufe 1 (partner: {self.partner_id.name})")

        # Send reminder email
        template = self.env.ref(
            'strohm_addon.email_template_dunning_m1', raise_if_not_found=False
        )
        if template:
            template.send_mail(self.id, force_send=True)

    def _transition_to_m2(self):
        """Transition invoice to Mahnstufe 2: Send disconnect notice and suspend user."""
        self.sudo().write({
            'dunning_level': '2',
            'dunning_level_date': fields.Date.today(),
        })
        _logger.info(f"Invoice {self.name} -> Mahnstufe 2 (partner: {self.partner_id.name})")

        # Send disconnect email
        template = self.env.ref(
            'strohm_addon.email_template_dunning_m2', raise_if_not_found=False
        )
        if template:
            template.send_mail(self.id, force_send=True)

        # Suspend user in Steve/Backend
        self.partner_id._suspend_charging_account()

    def _transition_to_m3(self):
        """Transition invoice to Mahnstufe 3: Hand over to HM Finance, block portal payments."""
        self.sudo().write({
            'dunning_level': '3',
            'dunning_level_date': fields.Date.today(),
        })
        self.partner_id.sudo().write({'finance_handover': True})
        _logger.info(f"Invoice {self.name} -> Mahnstufe 3 (partner: {self.partner_id.name})")

        # Send final notice email
        template = self.env.ref(
            'strohm_addon.email_template_dunning_m3', raise_if_not_found=False
        )
        if template:
            template.send_mail(self.id, force_send=True)

    def _notify_finance_m3(self):
        """Send internal notification with list of M3 customers."""
        m3_invoices = self.search([
            ('move_type', '=', 'out_invoice'),
            ('state', '=', 'posted'),
            ('payment_state', 'in', ['not_paid', 'partial']),
            ('dunning_level', '=', '3'),
            ('dunning_level_date', '=', fields.Date.today()),
        ])

        if not m3_invoices:
            return

        partner_names = ', '.join(m3_invoices.mapped('partner_id.name'))
        invoice_refs = ', '.join(m3_invoices.mapped('name'))

        _logger.warning(
            f"FINANCE HANDOVER: {len(m3_invoices)} invoice(s) reached Mahnstufe 3 today. "
            f"Partners: {partner_names}. Invoices: {invoice_refs}"
        )

        # Send internal email notification to finance
        template = self.env.ref(
            'strohm_addon.email_template_dunning_m3_finance_notification',
            raise_if_not_found=False
        )
        if template:
            template.send_mail(self.env.company.id, force_send=True)
