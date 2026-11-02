import pytest

from app.grafana.promql_inject import inject_cluster_label


def test_bare_metric_name_gets_cluster_label():
    assert inject_cluster_label("up", "abc") == 'up{cluster_id="abc"}'


def test_metric_with_existing_labels_gets_cluster_label():
    assert inject_cluster_label('http_requests{method="GET"}', "abc") == (
        'http_requests{method="GET",cluster_id="abc"}'
    )


def test_existing_cluster_id_is_overridden():
    assert inject_cluster_label('up{cluster_id="evil"}', "abc") == 'up{cluster_id="abc"}'


def test_binary_expression_injects_all_metric_selectors():
    assert inject_cluster_label("up + http_requests", "abc") == (
        'up{cluster_id="abc"} + http_requests{cluster_id="abc"}'
    )


def test_rate_subquery_injects_inner_metric_selector():
    assert inject_cluster_label("rate(http_requests[5m])", "abc") == (
        'rate(http_requests{cluster_id="abc"}[5m])'
    )


def test_empty_query_raises_value_error():
    with pytest.raises(ValueError):
        inject_cluster_label("", "abc")
