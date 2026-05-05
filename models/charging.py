import logging

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError

_logger = logging.getLogger(__name__)

_UOM_ENERGY_CATEG = 'uom.product_uom_categ_energy'
_UOM_KWH = 'uom.product_uom_kwh'


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

        tax_cache = {}
        for line_item in lines_data:
            # Find product (but don't create or modify it)
            product = self.sudo()._get_or_create_product(line_item)

            # Resolve tax: use per-line override if provided, otherwise fall back to product default
            if line_item.tax_rate is not None:
                tax = self._resolve_tax(line_item.tax_rate, bool(line_item.tax_included), tax_cache)
                tax_ids = [(6, 0, [tax.id])]
            else:
                tax_ids = [(6, 0, product.taxes_id.ids)]

            # Build the sale order line vals
            qty = line_item.quantity
            uom = self.env.ref(_UOM_KWH)
            order_lines.append((0, 0, {
                'product_id': product.id,
                'product_uom_qty': qty,
                'product_uom': uom.id,
                'qty_delivered': qty,
                'price_unit': line_item.price_unit,
                'session_start': line_item.session_start,
                'session_end': line_item.session_end,
                'session_backend_ref': line_item.session_backend_ref,
                'tax_id': tax_ids,
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

        # Confirm the Sale Order without sending emails
        sale_order.with_context(mail_notrack=True, mail_create_nosubscribe=True).action_confirm()
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

        # Check partner's billing frequency to determine if we should invoice immediately
        billing_frequency = Partner.billing_frequency or 'quarterly'

        # Create the invoice from the Sale Order if any line items' qty is more than zero
        if (not sale_order.order_line or
                all((line.product_uom_qty <= 0 and line.qty_delivered <= 0) for line in sale_order.order_line)):
            _logger.warning(f"Sale Order {sale_order} has no deliverable quantities, skipping invoice creation.")
        elif billing_frequency != 'session':
            # For monthly/quarterly billing, skip immediate invoice creation
            # The invoice will be created by the auto billing cron job
            _logger.info(f"Partner {Partner.name} has {billing_frequency} billing, skipping immediate invoice creation for Sale Order {sale_order.name}")
        else:
            # Per-session billing: create invoice immediately
            invoice = self._create_invoice_from_sale_order(sale_order, invoice_date, invoice_due_date)
            details.update({
                "invoice": {
                    'id': invoice.id,
                    'name': invoice.name,
                    'state': invoice.state,
                    'total_amount': invoice.amount_total,
                },
            })
        return details


    @api.model
    def _create_invoice_from_sale_order(self, sale_order, invoice_date=None, invoice_due_date=None):
        """
        Create a draft invoice from a confirmed Sale Order.

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
        energy_category = self.env.ref(_UOM_ENERGY_CATEG, raise_if_not_found=False)

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

            # Update the single energy line with the session data
            # We use SQL to avoid triggering the compute method on account.move which might wipe the header data
            # before the line data is persisted.
            line = energy_lines[0]

            # Check if already migrated (skip if data exists)
            if line.session_start or line.session_end: #TODO: 'or' or 'and'?
                continue

            # Only proceed if we have exactly one energy line (or one product line if category not found)
            # This prevents ambiguity if an invoice has multiple charging sessions mixed together
            if len(energy_lines) != 1:
                _logger.warning(
                    f"Skipping migration for invoice {invoice.name}: Found {len(energy_lines)} energy lines, expected exactly 1.")
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
                self.env.cr.rollback()

        if (migrated_count > 0):
            _logger.info(f"Migration complete: {migrated_count} invoices migrated, {line_count} lines updated")
        else:
            _logger.info("No invoices required migration.")


        return {
            'success': True,
            'invoices_migrated': migrated_count,
            'lines_updated': line_count,
        }

    @api.model
    def migrate_uom_to_official(self):
        """
        One-time migration: reassign all sale order lines, invoice lines, and products
        from any custom strohm_addon kWh UoM to the official Odoo 18 one
        (uom.product_uom_kwh), then delete the orphaned custom records.

        Handles both xmlid-registered and programmatically-created duplicate UoMs.
        Safe to call multiple times — skips steps that are already done.
        """
        cr = self.env.cr
        result = {'products_fixed': 0, 'so_lines_fixed': 0, 'inv_lines_fixed': 0, 'cleaned_up': []}

        official_uom = self.env.ref('uom.product_uom_kwh', raise_if_not_found=False)
        official_categ = self.env.ref('uom.product_uom_categ_energy', raise_if_not_found=False)

        if not official_uom or not official_categ:
            msg = 'Official Odoo 18 energy UoM not found — is the uom module installed?'
            _logger.error(msg)
            result['error'] = msg
            return result

        _logger.info(f"Official kWh UoM id={official_uom.id}, official Energy category id={official_categ.id}")

        # Step 1: Find ALL kWh UoMs that are NOT the official one (by name match, case-insensitive)
        # name is jsonb in Odoo 18, so check all language values
        cr.execute(
            "SELECT id, category_id FROM uom_uom "
            "WHERE id != %s AND EXISTS ("
            "  SELECT 1 FROM jsonb_each_text(name) AS kv WHERE LOWER(kv.value) = 'kwh'"
            ")",
            (official_uom.id,),
        )
        duplicate_uom_rows = cr.fetchall()
        duplicate_uom_ids = [r[0] for r in duplicate_uom_rows]

        # Also find custom UoM ids registered via ir_model_data (in case name differs)
        custom_xmlid_names = [
            'product_uom_kwh', 'str_product_uom_kwh',
            'uom_categ_energy', 'str_uom_categ_energy',
        ]
        cr.execute(
            "SELECT name, res_id, model FROM ir_model_data "
            "WHERE module = 'strohm_addon' AND name = ANY(%s)",
            (custom_xmlid_names,),
        )
        xmlid_rows = cr.fetchall()
        xmlid_uom_ids = [r[1] for r in xmlid_rows if r[2] == 'uom.uom' and r[1] != official_uom.id]
        xmlid_categ_ids = [r[1] for r in xmlid_rows if r[2] == 'uom.category' and r[1] != official_categ.id]

        # Merge: all non-official kWh UoM ids (from name search + xmlid search)
        all_custom_uom_ids = list(set(duplicate_uom_ids + xmlid_uom_ids))

        # Also find duplicate Energy categories by name (case-insensitive)
        # name is jsonb in Odoo 18
        cr.execute(
            "SELECT id FROM uom_category "
            "WHERE id != %s AND EXISTS ("
            "  SELECT 1 FROM jsonb_each_text(name) AS kv WHERE LOWER(kv.value) = 'energy'"
            ")",
            (official_categ.id,),
        )
        duplicate_categ_ids = [r[0] for r in cr.fetchall()]
        all_custom_categ_ids = list(set(duplicate_categ_ids + xmlid_categ_ids))

        _logger.info(f"Found custom UoM ids to migrate: {all_custom_uom_ids}")
        _logger.info(f"Found custom category ids to migrate: {all_custom_categ_ids}")

        # Step 2: Reassign all FKs from custom UoMs → official
        if all_custom_uom_ids:
            updates = [
                ('product_template', 'uom_id'),
                ('product_template', 'uom_po_id'),
                ('sale_order_line', 'product_uom'),
                ('account_move_line', 'product_uom_id'),
            ]
            for table, column in updates:
                cr.execute(
                    f'UPDATE "{table}" SET "{column}" = %s WHERE "{column}" = ANY(%s)',
                    (official_uom.id, all_custom_uom_ids),
                )
                if cr.rowcount:
                    _logger.info(f"Reassigned {cr.rowcount} rows in {table}.{column} → official kWh (id={official_uom.id})")
                    if 'product' in table:
                        result['products_fixed'] += cr.rowcount
                    elif 'sale' in table:
                        result['so_lines_fixed'] += cr.rowcount
                    elif 'account' in table:
                        result['inv_lines_fixed'] += cr.rowcount

            cr.commit()
            _logger.info("Committed FK reassignment")

        # Step 3: Reassign any UoMs still in custom categories to official category
        if all_custom_categ_ids:
            cr.execute(
                'UPDATE uom_uom SET category_id = %s WHERE category_id = ANY(%s)',
                (official_categ.id, all_custom_categ_ids),
            )
            if cr.rowcount:
                _logger.info(f"Reassigned {cr.rowcount} UoMs to official energy category")
            cr.commit()

        # Step 4: Delete orphaned custom UoM records
        if all_custom_uom_ids:
            cr.execute('DELETE FROM uom_uom WHERE id = ANY(%s)', (all_custom_uom_ids,))
            if cr.rowcount:
                _logger.info(f"Deleted {cr.rowcount} custom UoM records")
                result['cleaned_up'].append(f'{cr.rowcount} uom.uom')
            cr.commit()

        # Step 5: Delete orphaned custom category records
        if all_custom_categ_ids:
            cr.execute('DELETE FROM uom_category WHERE id = ANY(%s)', (all_custom_categ_ids,))
            if cr.rowcount:
                _logger.info(f"Deleted {cr.rowcount} custom UoM category records")
                result['cleaned_up'].append(f'{cr.rowcount} uom.category')
            cr.commit()

        # Step 6: Clean up ir_model_data entries
        if xmlid_rows:
            cr.execute(
                "DELETE FROM ir_model_data WHERE module = 'strohm_addon' AND name = ANY(%s)",
                (custom_xmlid_names,),
            )
            if cr.rowcount:
                _logger.info(f"Cleaned up {cr.rowcount} ir_model_data entries")
                result['cleaned_up'].append(f'{cr.rowcount} ir_model_data')
            cr.commit()

        _logger.info(f"UoM migration to official complete: {result}")
        return result

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
                'base_price': 0.30,
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

                # Use our custom kWh UoM defined in data/uom_data.xml
                uom = self.env.ref(_UOM_KWH)

                _logger.info(f"Creating product with SKU: {sku}, name: {data.get('name', sku)}")

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
                    'list_price': data.get('base_price', 0.30),
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

    def _resolve_tax(self, amount, price_include: bool, cache):
        """Find or create an account.tax by amount and price_include flag.

        Results are cached by (amount, price_include) for the duration of the call.
        """
        key = (amount, price_include)
        if key in cache:
            return cache[key]

        Tax = self.env['account.tax'].sudo()

        if amount == 0:
            tax = Tax.search([
                ('name', '=', '0% C EXEMPT'),
                ('type_tax_use', '=', 'sale'),
                ('amount', '=', 0),
                ('price_include', '=', price_include),
            ], limit=1)
            if not tax:
                tax = Tax.create({
                    'name': '0% C EXEMPT',
                    'amount': 0,
                    'amount_type': 'percent',
                    'type_tax_use': 'sale',
                    'price_include': price_include,
                })
                _logger.info(f"Created tax id={tax.id} name={tax.name}")
            cache[key] = tax
            return tax

        tax = Tax.search([
            ('amount', '=', amount),
            ('price_include', '=', price_include),
            ('type_tax_use', '=', 'sale'),
        ], limit=1)

        if not tax:
            incl_label = 'inkl.' if price_include else 'exkl.'
            tax = Tax.create({
                'name': f'{amount}% USt ({incl_label})',
                'amount': amount,
                'amount_type': 'percent',
                'type_tax_use': 'sale',
                'price_include': price_include,
            })
            _logger.info(f"Created tax id={tax.id} name={tax.name}")

        cache[key] = tax
        return tax

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
        energy_category = self.env.ref(_UOM_ENERGY_CATEG, raise_if_not_found=True)
        for record in self:
            total = 0.0
            for line in record.invoice_line_ids:
                if line.product_uom_id and energy_category and line.product_uom_id.category_id == energy_category:
                    total += line.quantity
            record.total_kwh = total
