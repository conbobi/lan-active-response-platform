from app.services.risk_rules.base import RiskRule
from app.services.risk_rules.registry import RiskRuleRegistry
from app.services.risk_rules.cpu_spike_rule import CpuSpikeRule
from app.services.risk_rules.suspicious_process_rule import SuspiciousProcessRule
from app.services.risk_rules.network_connection_rule import NetworkConnectionRule
from app.services.risk_rules.file_changes_rule import FileChangesRule
from app.services.risk_rules.process_chain_rule import ProcessChainRule
from app.services.risk_rules.injection_rule import InjectionRule
from app.services.risk_rules.living_off_land_rule import LivingOffLandRule
from app.services.risk_rules.registry_rule import RegistryRule
from app.services.risk_rules.credential_dumping_rule import CredentialDumpingRule
from app.services.risk_rules.shadow_copy_rule import ShadowCopyRule
from app.services.risk_rules.c2_communication_rule import C2CommunicationRule
from app.services.risk_rules.lateral_movement_rule import LateralMovementRule
from app.services.risk_rules.mass_file_modification_rule import MassFileModificationRule


def create_default_registry() -> RiskRuleRegistry:
    """Instantiate a RiskRuleRegistry populated with all 13 default risk rules."""
    registry = RiskRuleRegistry()
    registry.register(CpuSpikeRule())
    registry.register(SuspiciousProcessRule())
    registry.register(NetworkConnectionRule())
    registry.register(FileChangesRule())
    registry.register(ProcessChainRule())
    registry.register(InjectionRule())
    registry.register(LivingOffLandRule())
    registry.register(RegistryRule())
    registry.register(CredentialDumpingRule())
    registry.register(ShadowCopyRule())
    registry.register(C2CommunicationRule())
    registry.register(LateralMovementRule())
    registry.register(MassFileModificationRule())
    return registry


__all__ = [
    "RiskRule",
    "RiskRuleRegistry",
    "create_default_registry",
    "CpuSpikeRule",
    "SuspiciousProcessRule",
    "NetworkConnectionRule",
    "FileChangesRule",
    "ProcessChainRule",
    "InjectionRule",
    "LivingOffLandRule",
    "RegistryRule",
    "CredentialDumpingRule",
    "ShadowCopyRule",
    "C2CommunicationRule",
    "LateralMovementRule",
    "MassFileModificationRule",
]
