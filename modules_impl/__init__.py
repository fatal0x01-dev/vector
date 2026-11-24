"""
Importing this package registers every concrete Module implementation
with core.registry.MODULE_IMPLEMENTATIONS via the @register_implementation
decorator on each module. main.py (or anything using the Controller)
must import modules_impl before running the Controller.
"""

from . import nmap_module          # noqa: F401
from . import whatweb_module       # noqa: F401
from . import ssh_banner_module    # noqa: F401
from . import feroxbuster_module   # noqa: F401
from . import nuclei_module        # noqa: F401
from . import enum4linux_module    # noqa: F401
from . import smbclient_module     # noqa: F401
from . import ftp_anon_module      # noqa: F401
from . import cve_lookup_module    # noqa: F401
from . import nse_probe_module     # noqa: F401
from . import tls_audit_module     # noqa: F401
from . import default_creds_module # noqa: F401
