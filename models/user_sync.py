import logging

from odoo import models, api, _
from odoo.exceptions import ValidationError
from ..services.backend_service import get_backend_service

_logger = logging.getLogger(__name__)


class UserSync(models.Model):
    _name = 'strohm_addon.user_sync'
    _description = 'User Sync with Backend'

    # DISCLAIMER: THE MODEL IS ERROR PRONE AND SHOULD NOT BE USED IN PRODUCTION
    # THIS MODEL IS USED TO SYNC PARTNER/USER CHANGES TO THE BACKEND SYSTEM
    #
    # THE PROBLEM WITH THE ODOO CHANGE TRACKING IS THAT IT IS BROAD AND REQUIERE UNENECESSARY DEVELOPMENT TIME
    # ALL CHANGES SHOULD BE TRACKED BY THE ODOO INTERFACE UNTIL IT ISN'T

    @api.model
    def sync_user_changes(self, user_ids, old_values=None):
        """Send user changes to backend system"""
        if not user_ids:
            return False

        users = self.env['res.users'].sudo().browse(user_ids)
        for user in users:
            try:
                # Validate that user has a properly set up partner
                if not user.partner_id:
                    raise ValidationError(
                        _("User %s (ID: %s) doesn't have an associated partner record. This is required for synchronization.") % (
                            user.name, user.id))

                # Validate partner has essential information
                if not user.partner_id.name or not user.partner_id.email:
                    raise ValidationError(
                        _("Partner for user %s (ID: %s) is missing essential information (name or email).") % (
                            user.name, user.id))

                # Check if this is a portal user deletion (deactivation)
                old_data = {}
                if old_values and user.id in old_values:
                    old_data = old_values[user.id]

                _logger.info(f"Syncing user changes for user {user.id}: {user.name}")
                _logger.info(f"Old data: {old_data}")

                # Detect portal user deletion: more flexible detection
                # Check if login changed to __deleted_user_* pattern OR user became inactive
                is_portal_deletion = (
                    (user.login.startswith('__deleted_user_') and
                     old_data.get('login') and
                     not old_data.get('login').startswith('__deleted_user_')) or
                    (old_data.get('active') == True and user.active == False)
                )

                if is_portal_deletion:
                    # Handle as user deletion instead of change
                    user_deletion_data = {
                        'id': user.id,
                        'login': old_data.get('login', user.login),
                        'name': old_data.get('name', user.name),
                        'email': old_data.get('email', user.email),
                        'partner_id': user.partner_id.id,
                        'deletion_type': 'portal_self_deletion/archived',
                    }
                    self.sync_user_deletion(user_deletion_data)
                    continue

                # Get current user data
                current_values = {
                    'id': user.id,
                    'login': user.login,
                    'name': user.name,
                    'email': user.email,
                    'active': user.active,
                    'partner_id': user.partner_id.id if user.partner_id else False,
                }

                # Only send changed values
                changed_values = {}
                for key, new_val in current_values.items():
                    old_val = old_data.get(key)
                    if old_val != new_val:
                        changed_values[key] = new_val

                # If no changes detected, skip
                if not changed_values:
                    _logger.info(f"No changes detected for user {user.id}, skipping sync")
                    continue

                # Send to backend with consistent format
                event_type = 'user_changed'
                data = {
                    'record_id': user.id,
                    'old_data': old_data,
                    'new_data': changed_values,
                    'user_id': user.id,
                    'partner_id': user.partner_id.id,
                }

                backend_service = get_backend_service()
                success = backend_service.sync_event(
                    event_type=event_type,
                    data=data,
                    user_id=user.id,
                    partner_id=user.partner_id.id
                )

                if not success:
                    raise ValidationError(_("Failed to sync user changes to backend"))

            except ValidationError as ve:
                # Re-raise validation errors to be shown to the user
                raise
            except Exception as e:
                _logger.error(f"Failed to sync user changes for user {user.id}: {str(e)}")
                raise ValidationError(_("Failed to sync user changes for user %s: %s") % (user.name, str(e)))

        return True

    @api.model
    def sync_user_deletion(self, user_data):
        """Send user deletion to backend system"""
        try:
            # Make sure partner_id is included if it was in the original data
            partner_id = user_data.get('partner_id')
            user_id = user_data.get('id')

            if not partner_id and user_id:
                # Try to find the partner ID if we have the user ID
                user = self.env['res.users'].sudo().browse(user_id)
                if user.exists() and user.partner_id:
                    partner_id = user.partner_id.id
                    user_data['partner_id'] = partner_id

            # Format data consistently with other operations
            event_type = 'user_deleted'
            data = {
                'record_id': user_id,
                'old_data': user_data,
                'new_data': {},
                'user_id': user_id,
                'partner_id': partner_id,
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
            _logger.error(f"Failed to sync user deletion: {str(e)}")
            return False


