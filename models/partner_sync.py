import logging

from odoo import models, api
from ..services.backend_service import get_backend_service

_logger = logging.getLogger(__name__)

class PartnerSync(models.Model):
    _name = 'strohm_addon.partner_sync'
    _description = 'Partner Sync with Backend'

    # DISCLAIMER: THE MODEL IS ERROR PRONE AND SHOULD NOT BE USED IN PRODUCTION
    # THIS MODEL IS USED TO SYNC PARTNER/USER CHANGES TO THE BACKEND SYSTEM
    #
    # THE PROBLEM WITH THE ODOO CHANGE TRACKING IS THAT IT IS BROAD AND REQUIERE UNENECESSARY DEVELOPMENT TIME
    # ALL CHANGES SHOULD BE TRACKED BY THE ODOO INTERFACE UNTIL IT ISN'T

    @api.model
    def sync_partner_changes(self, partner_ids, old_values=None):
        """Send partner changes to backend system"""
        if not partner_ids:
            return False

        partners = self.env['res.partner'].sudo().browse(partner_ids)

        for partner in partners:
            try:
                # Check if partner is associated with portal users
                if not partner.user_ids or not any(user.has_group('base.group_portal') for user in partner.user_ids):
                    continue

                # Prepare old values if available
                old_data = {}
                if old_values and partner.id in old_values:
                    old_data = old_values[partner.id]

                _logger.info(f"Syncing partner changes for partner {partner.id}: {partner.name}")
                _logger.info(f"Old data: {old_data}")

                # Check if this is a creation (most old_data fields are null/None)
                is_creation = not old_data or self._is_partner_creation(old_data)

                if is_creation:
                    # For creation, send all current data as new_data with empty old_data
                    changed_values = {
                        'id': partner.id,
                        'name': partner.name,
                        'email': partner.email,
                        'active': partner.active,
                        'phone': partner.phone,
                        'mobile': partner.mobile,
                        'street': partner.street,
                        'street2': partner.street2,
                        'city': partner.city,
                        'zip': partner.zip,
                        'country_id': partner.country_id.id if partner.country_id else False,
                        'state_id': partner.state_id.id if partner.state_id else False,
                        'user_ids': partner.user_ids.ids,
                        'peppol_endpoint': getattr(partner, 'peppol_endpoint', False),
                        'vat': partner.vat,
                        'company_name': partner.company_name,
                        'invoice_sending_method': getattr(partner, 'invoice_sending_method', False),
                    }
                    normalized_old_data = {}
                else:
                    # For updates, get current values and normalize old_data
                    current_values = {
                        'id': partner.id,
                        'name': partner.name,
                        'email': partner.email,
                        'active': partner.active,
                        'phone': partner.phone,
                        'mobile': partner.mobile,
                        'street': partner.street,
                        'street2': partner.street2,
                        'city': partner.city,
                        'zip': partner.zip,
                        'country_id': partner.country_id.id if partner.country_id else False,
                        'state_id': partner.state_id.id if partner.state_id else False,
                        'user_ids': partner.user_ids.ids,
                        'peppol_endpoint': getattr(partner, 'peppol_endpoint', False),
                        'vat': partner.vat,
                        'company_name': partner.company_name,
                        'invoice_sending_method': getattr(partner, 'invoice_sending_method', False),
                    }

                    # Normalize old_data to match current_values format
                    normalized_old_data = self._normalize_partner_data(old_data, current_values.keys())

                    # Only send changed values
                    changed_values = {}
                    for key, new_val in current_values.items():
                        old_val = normalized_old_data.get(key)
                        if self._is_value_changed(old_val, new_val):
                            changed_values[key] = new_val

                # If no changes detected, skip
                if not changed_values:
                    _logger.info(f"No changes detected for partner {partner.id}, skipping sync")
                    continue

                # Get user_id if available
                user_id = partner.user_ids[0].id if partner.user_ids else None

                # Send to backend with consistent format
                event_type = 'partner_changed'
                data = {
                    'record_id': partner.id,
                    'old_data': normalized_old_data,
                    'new_data': changed_values
                }

                backend_service = get_backend_service()
                backend_service.sync_event(
                    event_type=event_type,
                    data=data,
                    user_id=user_id,
                    partner_id=partner.id
                )

            except Exception as e:
                _logger.error(f"Failed to sync partner changes for partner {partner.id}: {str(e)}")

        return True

    def _normalize_partner_data(self, old_data, expected_keys):
        """Normalize old_data to match the format of current_values"""
        normalized = {}

        for key in expected_keys:
            if key in old_data:
                value = old_data[key]

                # Handle relational fields that come as dicts from old_data
                if key in ['country_id', 'state_id'] and isinstance(value, dict):
                    # Extract the ID from the dict, handle False/None cases
                    normalized[key] = value.get('id') if value.get('id') is not False else False
                elif key == 'user_ids' and isinstance(value, list):
                    # Ensure user_ids is a list of integers
                    normalized[key] = [uid if isinstance(uid, int) else uid.get('id', uid) for uid in value if uid]
                else:
                    # For all other fields, use the value as-is
                    normalized[key] = value
            else:
                # If the key is not in old_data, set it to a default based on field type
                if key == 'user_ids':
                    normalized[key] = []
                elif key in ['country_id', 'state_id', 'mobile', 'peppol_endpoint', 'invoice_sending_method']:
                    normalized[key] = False
                else:
                    normalized[key] = None

        return normalized

    @api.model
    def sync_partner_deletion(self, partner_data):
        """Send partner deletion to backend system"""
        try:
            if not partner_data.get('has_portal_user', False):
                return True

            # Get user_id if available (from the partner_data)
            user_id = partner_data.get('user_ids', [None])[0]
            partner_id = partner_data.get('id')

            # Format data consistently with other operations
            event_type = 'partner_deleted'
            data = {
                'record_id': partner_id,
                'old_data': partner_data,
                'new_data': {}
            }

            backend_service = get_backend_service()
            success = backend_service.sync_event(
                event_type=event_type,
                data=data,
                user_id=user_id,
                partner_id=partner_id
            )
            return success
        except Exception as e:
            _logger.error(f"Failed to sync partner deletion: {str(e)}")
            return False

    def _is_partner_creation(self, old_data):
        """Check if this looks like a partner creation based on old_data"""
        # A real creation would have most/all essential fields as null/None
        # But if we have meaningful old values (like name and email), it's an update
        essential_fields = ['name', 'email']

        # If we have actual values for essential fields, this is definitely an update
        has_essential_values = any(
            old_data.get(field) not in (None, False, '')
            for field in essential_fields
        )

        if has_essential_values:
            return False

        # Only consider it a creation if we have no meaningful data at all
        # (most fields are missing or null)
        total_fields_with_data = sum(
            1 for value in old_data.values()
            if value not in (None, False, '', [])
        )

        return total_fields_with_data <= 2  # Very few fields have actual data

    def _is_value_changed(self, old_val, new_val):
        """Check if a value has actually changed, handling null/False equivalence"""
        # Handle None/null vs False equivalence for some fields
        if old_val is None and new_val is False:
            return False
        if old_val is False and new_val is None:
            return False
        # Handle empty string vs None equivalence
        if old_val in ('', None) and new_val in ('', None):
            return False
        # Handle empty list vs None equivalence
        if old_val in ([], None) and new_val in ([], None):
            return False

        return old_val != new_val
