#!/usr/bin/env bash
# ==============================================================================
# Master Test Runner cho 13 Detection Rules của LARP Agent
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "======================================================================"
echo "      LARP AGENT DETECTION RULE SIMULATION TEST SUITE (13 RULES)"
echo "======================================================================"
echo "Danh sách 13 test scripts sẵn có trong $SCRIPT_DIR:"
echo " 1. test_cpu_spike.sh              -> CpuSpikeRule"
echo " 2. test_suspicious_process.sh     -> SuspiciousProcessRule"
echo " 3. test_network_connection.sh     -> NetworkConnectionRule"
echo " 4. test_file_changes.sh           -> FileChangesRule"
echo " 5. test_process_chain.sh          -> ProcessChainRule"
echo " 6. test_injection.sh              -> InjectionRule"
echo " 7. test_living_off_land.sh        -> LivingOffLandRule"
echo " 8. test_registry.sh               -> RegistryRule"
echo " 9. test_credential_dumping.sh     -> CredentialDumpingRule"
echo "10. test_shadow_copy.sh            -> ShadowCopyRule"
echo "11. test_c2_communication.sh       -> C2CommunicationRule"
echo "12. test_lateral_movement.sh       -> LateralMovementRule"
echo "13. test_mass_file_modification.sh -> MassFileModificationRule"
echo "======================================================================"
echo "Chạy từng script đơn lẻ: ./scripts/test_<rule_name>.sh"
echo "Hoặc chạy script bằng: bash ./scripts/test_<rule_name>.sh"
echo "======================================================================"
