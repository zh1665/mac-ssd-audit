import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mac_ssd_audit.py"
SPEC = importlib.util.spec_from_file_location("mac_ssd_audit", SCRIPT)
mod = importlib.util.module_from_spec(SPEC)
sys.modules["mac_ssd_audit"] = mod
SPEC.loader.exec_module(mod)


def test_parse_smartctl_host_writes():
    text = """
Model Number:                       APPLE SSD AP0256Z
SMART overall-health self-assessment test result: PASSED
Temperature:                        33 Celsius
Available Spare:                    100%
Percentage Used:                    0%
Data Units Written:                 2,608,592 [1.33 TB]
Power On Hours:                     36
Media and Data Integrity Errors:    0
"""
    parsed = mod.parse_smartctl(text)
    assert parsed["model"] == "APPLE SSD AP0256Z"
    assert parsed["health"] == "PASSED"
    assert parsed["temperature_c"] == 33
    assert parsed["available_spare_percent"] == 100
    assert parsed["power_on_hours"] == 36
    assert parsed["media_errors"] == 0
    assert parsed["host_writes_bytes"] == 2_608_592 * 512_000


def test_growth_top20():
    prev = {"path_sizes": [{"path": "/a", "size_bytes": 10}, {"path": "/b", "size_bytes": 100}], "top_candidates": []}
    current = [{"path": "/a", "size_bytes": 40}, {"path": "/b", "size_bytes": 110}]
    growth = mod.compare_path_growth(current, prev)
    assert growth[0]["path"] == "/a"
    assert growth[0]["delta_bytes"] == 30
    assert growth[1]["path"] == "/b"


if __name__ == "__main__":
    test_parse_smartctl_host_writes()
    test_growth_top20()
    print("ok")
