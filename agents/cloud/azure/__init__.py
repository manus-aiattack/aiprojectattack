"""Azure Cloud Attack Agents"""

# Import all Azure agents
try:
    from .ad_enumeration_agent import *
except ImportError:
    pass

try:
    from .ad_privesc_agent import *
except ImportError:
    pass

try:
    from .blob_storage_agent import *
except ImportError:
    pass

try:
    from .keyvault_agent import *
except ImportError:
    pass

try:
    from .vm_exploit_agent import *
except ImportError:
    pass
