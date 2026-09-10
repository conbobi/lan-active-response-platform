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
    assert len(vec) == 6
    assert vec[0] == 45.5
    assert vec[3] == 2.0  # process_count
    assert vec[4] == 1.0  # conn_count
    assert vec[5] == 3.0  # file_changes


def test_isolation_forest_pipeline():
    service = MLAnomalyService(None)
    # Generate 50 normal sample points
    normal_data = []
    for i in range(50):
        normal_data.append([10.0 + (i % 3), 30.0 + (i % 4), 20.0, 15.0, 5.0, 0.0])

    model_bytes, mean_dict, std_dict = service._train_isolation_forest(normal_data)
    assert len(model_bytes) > 0
    assert "cpu_usage" in mean_dict

    import io
    import joblib
    model = joblib.load(io.BytesIO(model_bytes))

    # Test normal point
    is_ano, score, risk, _ = service._predict_model(
        model,
        [10.5, 31.0, 20.0, 15.0, 5.0, 0.0],
        mean_dict,
        std_dict
    )
    assert not is_ano

    # Test huge anomaly point (extreme CPU spike + thousands of file changes + socket explosion)
    is_ano_bad, score_bad, risk_bad, reasons = service._predict_model(
        model,
        [99.0, 95.0, 80.0, 300.0, 200.0, 500.0],
        mean_dict,
        std_dict
    )
    assert is_ano_bad
    assert risk_bad >= 25.0
    assert len(reasons) > 0
