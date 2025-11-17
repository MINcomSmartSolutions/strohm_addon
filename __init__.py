from . import controllers
from . import models
from . import services
from .utils import strohm_init_parameters
import logging

_logger = logging.getLogger(__name__)


def _set_parameters_init_hook(env):
    """Code to execute when the module is installed"""
    _logger.info("Running Strohm module initialization hook")
    strohm_init_parameters(env)
    _logger.info("Strohm module initialization hook completed")
