# -*- coding: utf-8 -*-
import logging

from odoo import models, api
from ..services.backend_service import get_backend_service

_logger = logging.getLogger(__name__)


class InvoiceSync(models.Model):
    _name = 'strohm_addon.invoice_sync'
    _description = 'Invoice Sync with Backend'

    @api.model
    def sync_invoice_create(self, invoice_ids):
        """
        Sync new invoices to backend system.
        Called when invoice is created.
        """
        return self._sync_invoices(invoice_ids, method='POST')

    @api.model
    def sync_invoice_update(self, invoice_ids):
        """
        Sync invoice updates to backend system.
        Called when invoice state changes.
        """
        return self._sync_invoices(invoice_ids, method='PUT')

    @api.model
    def sync_invoice_delete(self, invoice_data):
        """
        Sync invoice deletion to backend system.
        Called when invoice is deleted.
        """
        try:
            _logger.info(f"Syncing invoice deletion for invoice {invoice_data.get('id')}")
            
            backend_service = get_backend_service()
            success, response, error = backend_service.delete_internal(
                f"/internal/invoice/{invoice_data.get('id')}",
                data=invoice_data
            )

            if success:
                _logger.info(f"Successfully synced invoice deletion to backend")
            else:
                _logger.error(f"Failed to sync invoice deletion to backend: {error}")
                
        except Exception as e:
            _logger.error(f"Error syncing invoice deletion: {str(e)}", exc_info=True)
            return False
            
        return True

    def _sync_invoices(self, invoice_ids, method='POST'):
        """Helper to sync invoices with specified HTTP method."""
        if not invoice_ids:
            return False

        invoices = self.env['account.move'].sudo().browse(invoice_ids)

        for invoice in invoices:
            try:
                # Only sync customer invoices (out_invoice, out_refund)
                if invoice.move_type not in ('out_invoice', 'out_refund'):
                    continue

                invoice_data = self._prepare_invoice_data(invoice)
                
                _logger.info(f"Syncing invoice {invoice.id} ({method}): {invoice.name} -> {invoice.state}")

                backend_service = get_backend_service()
                
                if method == 'POST':
                    success, response, error = backend_service.post_internal('/internal/invoice', invoice_data)
                elif method == 'PUT':
                    success, response, error = backend_service.put_internal(f"/internal/invoice/{invoice.id}", invoice_data)
                else:
                    _logger.error(f"Unsupported sync method: {method}")
                    continue

                if success:
                    _logger.info(f"Successfully synced invoice {invoice.name} to backend")
                else:
                    _logger.error(f"Failed to sync invoice {invoice.name} to backend: {error}")

            except Exception as e:
                _logger.error(f"Error syncing invoice {invoice.id}: {str(e)}", exc_info=True)
                continue

        return True

    def _prepare_invoice_data(self, invoice):
        """Prepare invoice data for backend sync."""
        # Get related sale orders
        sale_order_names = []
        sale_order_ids = []
        for line in invoice.invoice_line_ids:
            for sale_line in line.sale_line_ids:
                if sale_line.order_id.id not in sale_order_ids:
                    sale_order_ids.append(sale_line.order_id.id)
                    sale_order_names.append(sale_line.order_id.name)

        # Get session backend refs from invoice lines
        session_backend_refs = []
        for line in invoice.invoice_line_ids:
            if hasattr(line, 'session_backend_ref') and line.session_backend_ref:
                session_backend_refs.append(line.session_backend_ref)

        return {
            'invoice': {
                'id': invoice.id,
                'name': invoice.name,
                'state': invoice.state,
                'move_type': invoice.move_type,
                'partner_id': invoice.partner_id.id,
                'partner_name': invoice.partner_id.name,
                'amount_total': invoice.amount_total,
                'amount_untaxed': invoice.amount_untaxed,
                'amount_tax': invoice.amount_tax,
                'amount_residual': invoice.amount_residual,
                'currency_id': invoice.currency_id.id,
                'currency_name': invoice.currency_id.name,
                'invoice_date': invoice.invoice_date.isoformat() if invoice.invoice_date else None,
                'invoice_date_due': invoice.invoice_date_due.isoformat() if invoice.invoice_date_due else None,
                'payment_state': invoice.payment_state,
                'sale_order_ids': sale_order_ids,
                'sale_order_names': sale_order_names,
                'session_backend_refs': session_backend_refs,
            }
        }
