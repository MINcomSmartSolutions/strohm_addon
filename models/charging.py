import logging

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError

_logger = logging.getLogger(__name__)


class ChargingSessionInvoice(models.TransientModel):
    _name = 'charging.session.invoice'
    _description = 'Charging Session Invoicing'

    @api.model
    def generate(self, partner, lines_data, invoice_due_date=None, invoice_date=None):
        """
        Generate a Sale Order with charging session lines and create a draft invoice.

        This method creates a Sale Order, confirms it, and generates a draft invoice.
        Session start/end times are stored on each line item, allowing multiple sessions per invoice.
        The invoice is left in draft state for review before posting.
        For now every order should only have 1 charging session line.

        Args:
            session_start (Datetime): Session start datetime UTC
            session_end (Datetime): Session end datetime UTC
            partner (res.partner): The partner for whom the invoice is created.
            lines_data (BillLineItem): List of objects containing line item data for the invoice.
                - sku (str): Internal reference for product.
                - quantity (float): Consumed quantity (e.g., 150, in kWh).
                - price_unit (float): Actual invoice price per unit (e.g., 0.38).
            invoice_due_date (Datetime): Optional invoice due date.
            invoice_date (Datetime): Optional invoice date.
        Returns:
            recordset: The created draft `account.move` (invoice) record.
        """
        SaleOrder = self.env['sale.order']
        Partner = self.env['res.partner'].browse(partner.id)
        if not Partner or not Partner.exists():
            raise ValidationError('Partner not found for the user. Please ensure the user has a valid partner record.')

        # Build order lines with session data
        order_lines = []
        if not lines_data:
            raise ValidationError('No line items provided for invoicing.')

        for line_item in lines_data:
            # Find product (but don't create or modify it)
            product = self.sudo()._get_or_create_product(line_item)

            # Build the sale order line vals
            qty = line_item.quantity
            order_lines.append((0, 0, {
                'product_id': product.id,
                'product_uom_qty': qty,
                'qty_delivered': qty,
                'price_unit': line_item.price_unit,
                'session_start': line_item.session_start,
                'session_end': line_item.session_end,
                'session_backend_ref': line_item.session_backend_ref,
                'tax_id': [(6, 0, product.taxes_id.ids)],
            }))

        # Create the Sale Order
        order_vals = {
            'partner_id': Partner.id,
            'order_line': order_lines,
            'date_order': invoice_date or fields.Datetime.now(),
            'payment_term_id': self.env.ref('account.account_payment_term_30days').id or False,
        }

        sale_order = SaleOrder.create(order_vals)
        _logger.info(f"Created Sale Order {sale_order.name} for partner {Partner.name}")

        # Confirm the Sale Order
        sale_order.action_confirm()
        _logger.info(f"Confirmed Sale Order {sale_order.name}")
        details = {}

        details.update({
            "sale_order": {
                'id': sale_order.id,
                'name': sale_order.name,
                'confirmed': True,
                'total_amount': sale_order.amount_total,
                'qty': sum(line.product_uom_qty for line in sale_order.order_line),
                'line_count': len(sale_order.order_line),
            },
        })

        # Create the invoice from the Sale Order if any line items' qty is more than zero
        if (not sale_order.order_line or
                all((line.product_uom_qty <= 0 and line.qty_delivered <= 0) for line in sale_order.order_line)):
            _logger.warning(f"Sale Order {sale_order} has no deliverable quantities, skipping invoice creation.")
        else:
            invoice = self._create_invoice_from_sale_order(sale_order, invoice_date, invoice_due_date)
            details.update({
                "invoice": {
                    'id': invoice.id,
                    'name': invoice.name,
                    'state': invoice.state,
                    'total_amount': invoice.amount_total,
                },
            })
        print(details)
        return details


    @api.model
    def _create_invoice_from_sale_order(self, sale_order, invoice_date=None, invoice_due_date=None):
        """
        Create a draft invoice from a confirmed Sa le Order.

        Args:
            sale_order: The confirmed sale.order record
            invoice_date: Optional invoice date, comes parsed
            invoice_due_date: Optional invoice due date, comes parsed

        Returns:
            recordset: The created draft account.move record
        """
        # Use Odoo's standard invoicing mechanism
        # This will automatically call _prepare_invoice_line which propagates session fields
        invoice = sale_order._create_invoices()

        # Update invoice dates if provided
        invoice_vals = {}
        if invoice_date:
            invoice_vals['invoice_date'] = invoice_date
        if invoice_due_date:
            invoice_vals['invoice_date_due'] = invoice_due_date
        else:
            # Default: due in 1 month
            invoice_vals['invoice_date_due'] = fields.Date.add(fields.Date.today(), months=1)

        if invoice_vals:
            invoice_vals['show_delivery_date'] = False
            invoice_vals['delivery_date'] = False
            invoice.write(invoice_vals)

        _logger.info(f"Created draft invoice {invoice.id} from Sale Order {sale_order.name}")

        return invoice

    @api.model
    def migrate_invoice_sessions_to_lines(self):
        """
        Migrate existing invoices with header-level session_start/session_end
        to line-level fields.

        This method finds all account.move records with session data on the header
        and copies that data to each invoice line.

        Returns:
            dict: Summary of migration results
        """
        AccountMove = self.env['account.move']

        # Find invoices with session data on header (using the old fields)
        invoices_with_sessions = AccountMove.search([
            ('move_type', '=', 'out_invoice'),
            '|',
            ('session_start', '!=', False),
            ('session_end', '!=', False),
        ])

        migrated_count = 0
        line_count = 0

        # Get energy category
        energy_category = self.env.ref('strohm_addon.uom_categ_energy', raise_if_not_found=False)

        for invoice in invoices_with_sessions:
            session_start = invoice.session_start
            session_end = invoice.session_end

            if not session_start and not session_end:
                continue

            # Filter lines that are products
            product_lines = invoice.invoice_line_ids.filtered(lambda l: l.display_type == 'product')

            # Check if there is exactly one energy line
            energy_lines = product_lines
            if energy_category:
                energy_lines = product_lines.filtered(lambda l: l.product_uom_id.category_id == energy_category)

            # Only proceed if we have exactly one energy line (or one product line if category not found)
            # This prevents ambiguity if an invoice has multiple charging sessions mixed together
            if len(energy_lines) != 1:
                _logger.warning(
                    f"Skipping migration for invoice {invoice.name}: Found {len(energy_lines)} energy lines, expected exactly 1.")
                continue

            # Update the single energy line with the session data
            # We use SQL to avoid triggering the compute method on account.move which might wipe the header data
            # before the line data is persisted.
            line = energy_lines[0]

            # Check if already migrated (skip if data exists)
            if line.session_start or line.session_end:
                continue

            try:
                self.env.cr.execute("""
                                    UPDATE account_move_line
                                    SET session_start = %s,
                                        session_end   = %s
                                    WHERE id = %s
                                    """, (session_start or None, session_end or None, line.id))

                # Force commit to ensure changes are persisted immediately
                self.env.cr.commit()

                # Invalidate cache for these fields on this line so Odoo sees the new values
                line.invalidate_recordset(['session_start', 'session_end'])

                line_count += 1
                migrated_count += 1
                _logger.info(f"Migrated session data for invoice {invoice.name} (Line ID: {line.id}): "
                             f"start={session_start}, end={session_end}")
            except Exception as e:
                _logger.error(f"Failed to migrate invoice {invoice.name}: {e}")
                # Rollback transaction on error to prevent partial updates or database locks
                self.env.cr.rollback()

        _logger.info(f"Migration complete: {migrated_count} invoices migrated, {line_count} lines updated")

        return {
            'success': True,
            'invoices_migrated': migrated_count,
            'lines_updated': line_count,
        }

    @api.model
    def ensure_standard_products(self):
        """
        Ensure all standard products exist in the database.
        Will fail if Fiscal Localization is not set to Germany.

        Returns:
            dict: Dictionary mapping product SKUs to product records
        """
        products = {}

        # Define standard product here
        product_definitions = [
            {
                'name': 'Ladesitzung',
                'sku': 'standard_charging',
                'uom_name': 'kWh',
                'base_price': 0.35,
                # list_price is set to base_price by default and can be set changed with price_unit when creating invoice
            },
        ]

        for data in product_definitions:
            sku = data.get('sku')
            _logger.info(f"Looking up product with SKU: {sku}")

            product = self.env['product.product'].with_context(active_test=False).search(
                [('default_code', '=', sku)], limit=1
            )

            if not product:
                _logger.info(f"Product with SKU {sku} not found, creating new product")

                # Create UoM if needed
                uom_name = data.get('uom_name', 'kWh')
                uom = self.env['uom.uom'].search([('name', '=', uom_name)], limit=1)
                if not uom:
                    _logger.info(f"UOM {uom_name} not found, creating new UOM")
                    category = self.env.ref('uom.uom_categ_energy', raise_if_not_found=False)
                    uom = self.env['uom.uom'].create({
                        'name': uom_name,
                        'category_id': category.id,
                        'rounding': 0.01,
                        'factor_inv': 1.0,
                    })
                    self.env.cr.commit()  # Commit UOM creation

                # Create product
                _logger.info(f"Creating product with SKU: {sku}, name: {data.get('name', sku)}")

                # Fix: Proper way to get the German country
                country = self.env.ref('base.de', raise_if_not_found=False)
                if not country:
                    country = self.env['res.country'].search([('code', '=', 'DE')], limit=1)

                if not country:
                    raise UserError(_("Could not find country Germany (DE) in the database."))

                # Try to find the German 19% VAT tax.
                # First try with xmlid reference
                tax = self.env.ref('l10n_de.tax_ust_19_skr04', raise_if_not_found=False)

                # If that fails, search more broadly
                if not tax:
                    tax = self.env['account.tax'].search([
                        ('amount', '=', 19),
                        ('type_tax_use', '=', 'sale'),
                        ('country_id', '=', country.id),
                    ], limit=1)

                # If still not found, try without country filter?
                # Skeptical about this, but let's keep it for now
                if not tax:
                    tax = self.env['account.tax'].search([
                        ('amount', '=', 19),
                        ('type_tax_use', '=', 'sale'),
                    ], limit=1)

                if not tax:
                    raise UserError(
                        _("No tax found for Germany with 19% VAT. Make sure the Settings --> Invoice --> Fiscal Localization is set to Germany."))

                product = self.env['product.product'].create({
                    'name': data.get('name') or sku,
                    'default_code': sku,
                    'type': 'consu',
                    'uom_id': uom.id,
                    'uom_po_id': uom.id,
                    'list_price': data.get('base_price', 0.35),
                    'invoice_policy': 'delivery',
                    # In Odoo, the tuple `(6, 0, ids)` is a special command used in many2many and one2many fields to set the field's value. Here:
                    #
                    # - `6` is the command to replace all existing records with the provided list.
                    # - `0` is ignored (kept for compatibility).
                    # - `tax.ids` is the list of IDs to set.
                    #
                    # So, `[(6, 0, tax.ids)]` means: replace all current tax records with the ones in `tax.ids`.
                    'taxes_id': [(6, 0, tax.ids)],
                })

                self.env.cr.commit()  # Commit product creation
                _logger.info(f"Created product with ID: {product.id}")

            products[sku] = product

        return products

    def _get_or_create_product(self, data):
        """
        Finds a product by SKU without modifying its base price.
        """
        # Use direct attribute access instead of .get()
        sku = data.sku

        # Try to get product from API cache if available
        api = self.env.context.get('strohm_api')
        if api and hasattr(api, 'standard_products') and sku in api.standard_products:
            return api.standard_products[sku]

        # Fall back to database lookup if not cached
        product = self.env['product.product'].with_context(active_test=False).search(
            [('default_code', '=', sku)], limit=1
        )

        if not product:
            # Instead of creating a product on-the-fly, raise an error
            raise ValueError(
                f"Product with SKU '{sku}' not found. Products must be pre-created in system initialization.")

        return product


class AccountMove(models.Model):
    """
    Extend account.move to add computed session fields based on invoice lines.
    This provides backward compatibility for reports and templates that reference
    session_start/session_end on the invoice header.
    """
    _inherit = 'account.move'

    session_start = fields.Datetime(
        string='Session Start',
        compute='_compute_session_times',
        store=True,
        help='Earliest session start time from invoice lines'
    )
    session_end = fields.Datetime(
        string='Session End',
        compute='_compute_session_times',
        store=True,
        help='Latest session end time from invoice lines'
    )
    total_kwh = fields.Float(
        string='Total Charged Energy (kWh)',
        compute='_compute_total_kwh',
        store=True,
        help='Total energy charged in kWh'
    )

    @api.depends('invoice_line_ids.session_start', 'invoice_line_ids.session_end')
    def _compute_session_times(self):
        """Compute session times from invoice lines (earliest start, latest end)"""
        for record in self:
            starts = record.invoice_line_ids.filtered('session_start').mapped('session_start')
            ends = record.invoice_line_ids.filtered('session_end').mapped('session_end')
            record.session_start = min(starts) if starts else False
            record.session_end = max(ends) if ends else False

    @api.depends('invoice_line_ids.quantity', 'invoice_line_ids.product_uom_id')
    def _compute_total_kwh(self):
        """Calculate total kWh from invoice lines with Energy unit of measure category"""
        energy_category = self.env.ref('strohm_addon.uom_categ_energy', raise_if_not_found=False)
        for record in self:
            total = 0.0
            for line in record.invoice_line_ids:
                if line.product_uom_id and energy_category and line.product_uom_id.category_id == energy_category:
                    total += line.quantity
            record.total_kwh = total
