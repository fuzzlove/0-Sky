"""0-Sky core foundation."""
from .capabilities import Capability, CapabilityMatrix, CapabilityState
from .database import EventStore, SCHEMA_VERSION
from .health import CircuitBreaker, SensorState
from .ipc import (IPCRequest, IPCValidationError, PROTOCOL_VERSION,
                  READ_OPERATIONS, WRITE_OPERATIONS, response, validate_request)
from .logging import StructuredLogger
from .paths import RootlessPaths
from .runtime import CoreRuntime
from .snapshots import SnapshotCoordinator, SnapshotError
from .automation import (AutomationEngine, FreezeCoordinator, PolicyError,
                         ProfileEngine, builtin_profiles, validate_profile,
                         validate_rule)
from .intelligence import NotificationSensor, PermissionTimeoutCoordinator
from .storage import StorageScanner
from .sensors import (BatterySensor, DeviceHealthSensor, ProcessSensor,
                      SensorResult, TelemetryCoordinator, ThermalSensor,
                      LibprocBackend, NetworkSensor, PrivacySensor,
                      ConflictSensor, CrashSensor, PackageInventory, PACKAGE_ID,
                      parse_elapsed, parse_socket_buffer)

__all__ = [
    "Capability", "CapabilityMatrix", "CapabilityState", "CircuitBreaker",
    "CoreRuntime", "EventStore", "IPCRequest", "IPCValidationError",
    "PROTOCOL_VERSION", "READ_OPERATIONS", "RootlessPaths", "SCHEMA_VERSION",
    "BatterySensor", "DeviceHealthSensor", "ProcessSensor", "SensorResult",
    "TelemetryCoordinator", "ThermalSensor", "parse_elapsed",
    "LibprocBackend", "NetworkSensor", "PrivacySensor", "parse_socket_buffer",
    "ConflictSensor", "CrashSensor", "PackageInventory", "PACKAGE_ID",
    "SnapshotCoordinator", "SnapshotError",
    "AutomationEngine", "FreezeCoordinator", "PolicyError", "ProfileEngine",
    "builtin_profiles", "validate_profile", "validate_rule",
    "NotificationSensor", "PermissionTimeoutCoordinator", "StorageScanner",
    "SensorState", "StructuredLogger", "WRITE_OPERATIONS", "response",
    "validate_request",
]
