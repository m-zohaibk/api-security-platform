import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.discovery import EndpointDiscovery
from tests.targeted_main_scan import targeted_discover

for target in sys.argv[1:]:
    d = EndpointDiscovery(target, timeout=30)
    result = targeted_discover(d)
    print(target)
    for item in result:
        print(item)
