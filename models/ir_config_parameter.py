import logging

from odoo import api, models

_logger = logging.getLogger(__name__)

# Protected parameters with their enforced values
# These values will be re-applied if any addon tries to change them
PROTECTED_PARAMETERS = {
    'portal.allow_api_keys': 'False',
    'digest.default_digest_emails': 'False',
    'digest.default_digest_id': '0',
    'sale.auto_send_order_confirmation': 'False',
    'sale.async_emails' : 'False',
    'auth_signup.reset_password' : 'False',
}


class IrConfigParameterProtected(models.Model):
    _inherit = 'ir.config_parameter'

    @api.model
    def set_param(self, key, value):
        """
        Override set_param to intercept and enforce protected parameter values.
        If a protected parameter is being set to a non-allowed value, log a warning
        and enforce the protected value instead.
        """
        if key in PROTECTED_PARAMETERS:
            protected_value = PROTECTED_PARAMETERS[key]
            if str(value) != protected_value:
                _logger.warning(
                    "Attempted to change protected parameter '%s' from '%s' to '%s'. "
                    "Enforcing protected value: '%s'",
                    key, self.get_param(key), value, protected_value
                )
                value = protected_value
        return super().set_param(key, value)

    def write(self, vals):
        """
        Override write to intercept direct record modifications.
        This catches cases where the parameter is modified directly on the record
        rather than through set_param.
        """
        if 'value' in vals:
            for record in self:
                if record.key in PROTECTED_PARAMETERS:
                    protected_value = PROTECTED_PARAMETERS[record.key]
                    if str(vals['value']) != protected_value:
                        _logger.warning(
                            "Attempted to change protected parameter '%s' from '%s' to '%s'. "
                            "Enforcing protected value: '%s'",
                            record.key, record.value, vals['value'], protected_value
                        )
                        vals = dict(vals, value=protected_value)
        return super().write(vals)
