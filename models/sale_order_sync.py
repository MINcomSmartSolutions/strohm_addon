# -*- coding: utf-8 -*-
import logging

from odoo import models, api
from ..services.backend_service import get_backend_service

_logger = logging.getLogger(__name__)


class SaleOrderSync(models.Model):
    _name = 'strohm_addon.sale_order_sync'
    _description = 'Sale Order Sync with Backend'

    @api.model
    def sync_sale_order_create(self, order_ids):
        """
        Sync new sale orders to backend system.
        Called when sale order is created.
        """
        return self._sync_orders(order_ids, method='POST')

    @api.model
    def sync_sale_order_update(self, order_ids):
        """
        Sync sale order updates to backend system.
        Called when sale order state changes.
        """
        return self._sync_orders(order_ids, method='PUT')

    @api.model
    def sync_sale_order_delete(self, order_data):
        """
        Sync sale order deletion to backend system.
        Called when sale order is deleted.
        """
        if not order_data or not order_data.get('id') or not isinstance(order_data.get('id'), int):
            _logger.error("Invalid order data provided for deletion sync")
            return False

        order_state = order_data.get('state')
        order_id = order_data.get('id')

        if order_state and order_state not in ('draft', 'cancel'):
            _logger.info(f"Skipping sync for sale order deletion with state {order_state}. It should be canceled first.")
            return False

        try:
            _logger.info(f"Syncing sale order deletion for order {order_id}")
            
            backend_service = get_backend_service()
            success, response, error = backend_service.delete_internal(
                f"/internal/sale/{order_id}",
                data=order_data
            )

            if success:
                _logger.info(f"Successfully synced sale order deletion to backend")
            else:
                _logger.error(f"Failed to sync sale order deletion to backend: {error}")
                
        except Exception as e:
            _logger.error(f"Error syncing sale order deletion: {str(e)}", exc_info=True)
            return False
            
        return True

    def _sync_orders(self, order_ids, method='POST'):
        """Helper to sync sale orders with specified HTTP method."""
        if not order_ids:
            return False

        orders = self.env['sale.order'].sudo().browse(order_ids)

        for order in orders:
            try:
                order_data = self._prepare_order_data(order)
                
                _logger.info(f"Syncing sale order {order.id} ({method}): {order.name} -> {order.state}")

                backend_service = get_backend_service()
                
                if method == 'POST':
                    success, response, error = backend_service.post_internal('/internal/sale', order_data)
                elif method == 'PUT':
                    success, response, error = backend_service.put_internal(f"/internal/sale/{order.id}", order_data)
                else:
                    _logger.error(f"Unsupported sync method: {method}")
                    continue

                if success:
                    _logger.info(f"Successfully synced sale order {order.name} to backend")
                else:
                    _logger.error(f"Failed to sync sale order {order.name} to backend: {error}")

            except Exception as e:
                _logger.error(f"Error syncing sale order {order.id}: {str(e)}", exc_info=True)
                continue

        return True

    def _prepare_order_data(self, order):
        """Prepare sale order data for backend sync."""
        # Get session backend refs from order lines
        session_backend_refs = []
        for line in order.order_line:
            if hasattr(line, 'session_backend_ref') and line.session_backend_ref:
                session_backend_refs.append(line.session_backend_ref)

        # Get related invoices
        invoice_ids = []
        invoice_names = []
        for invoice in order.invoice_ids:
            invoice_ids.append(invoice.id)
            invoice_names.append(invoice.name)

        return {
            'sale_order': {
                'id': order.id,
                'name': order.name,
                'state': order.state,
                'invoice_status': order.invoice_status,
                'partner_id': order.partner_id.id,
                'partner_name': order.partner_id.name,
                'amount_total': order.amount_total,
                'amount_untaxed': order.amount_untaxed,
                'amount_tax': order.amount_tax,
                'currency_id': order.currency_id.id,
                'currency_name': order.currency_id.name,
                'date_order': order.date_order.isoformat() if order.date_order else None,
                'invoice_ids': invoice_ids,
                'invoice_names': invoice_names,
                'session_backend_refs': session_backend_refs,
            }
        }
