from uwcn.evaluation.attacks import replay_test
from uwcn.evaluation.metrics import communication_bits, detect_anomalies
from uwcn.models.message import MessageRecord


def test_replay_test_blocks_stale_timestamp():
    assert replay_test(verbose=False) is False


def test_detect_anomalies_flags_outlier():
    delays = [0.10, 0.11, 0.09, 0.10, 0.12, 2.5]
    anomalies = detect_anomalies(delays, threshold=1.5)
    assert 5 in anomalies


def test_communication_bits_falls_back_to_reference_when_empty():
    assert communication_bits([]) == 296


def test_communication_bits_sums_observed_records():
    records = [
        MessageRecord("M1", 1, "U1", "S1", ["a"], ciphertext_bytes=10, delay_s=0.1),
        MessageRecord("M2", 2, "S1", "U1", ["b"], ciphertext_bytes=12, delay_s=0.1),
    ]
    assert communication_bits(records) == (10 + 12) * 8
