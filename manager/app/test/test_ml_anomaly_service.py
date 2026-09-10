from app.services.ml_anomaly_service import MLAnomalyService


def test_feature_extraction():
    telemetry = {
        "cpu_usage": 45.5,
        "ram_usage": 60.2,
        "disk_usage": 15.0,
        "process_list": [{"pid": 1}, {"pid": 2}],
        "network_connections": [{"port": 80}],
        "file_changes_count": 3
    }
    vec = MLAnomalyService.extract_features(telemetry)
    assert len(vec) == 2
    assert vec[0] == 45.5
    assert vec[1] == 60.2


def test_isolation_forest_pipeline():
    service = MLAnomalyService(None)
    # Generate 50 normal sample points
    normal_data = []
    for i in range(50):
        normal_data.append([10.0 + (i % 3), 30.0 + (i % 4)])

    model_bytes, mean_dict, std_dict = service._train_isolation_forest(normal_data)
    assert len(model_bytes) > 0
    assert "cpu_usage" in mean_dict

    import io
    import joblib
    model = joblib.load(io.BytesIO(model_bytes))

    # Test normal point
    is_ano, score, risk, _ = service._predict_model(
        model,
        [10.5, 31.0],
        mean_dict,
        std_dict
    )
    assert not is_ano

    # Test huge anomaly point (extreme CPU spike + extreme RAM spike)
    is_ano_bad, score_bad, risk_bad, reasons = service._predict_model(
        model,
        [99.0, 95.0],
        mean_dict,
        std_dict
    )
    assert is_ano_bad
    assert 5.0 <= risk_bad <= 15.0
    assert len(reasons) >= 1


def test_zero_variance_idle_agent_not_anomaly():
    """Verify idle agents with tiny fluctuations (e.g. CPU 0.04% -> 0.52%) do not trigger anomaly."""
    service = MLAnomalyService(None)
    # Idle training data around 0.04% CPU, 1.0% RAM with very low std
    idle_data = [[0.04 + 0.005 * (i % 3), 1.0 + 0.01 * (i % 2)] for i in range(50)]
    model_bytes, mean_dict, std_dict = service._train_isolation_forest(idle_data)

    import io
    import joblib
    model = joblib.load(io.BytesIO(model_bytes))

    # Even if CPU increases tenfold (from 0.04% to 0.52%), it is below ABSOLUTE_FLOOR (15%) and protected by MIN_STD
    is_ano, score, risk, reasons = service._predict_model(
        model,
        [0.52, 1.37],
        mean_dict,
        std_dict
    )
    assert not is_ano
    assert risk == 0.0
    assert len(reasons) == 0

