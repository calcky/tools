use std::process::Command;

use jsonschema::Validator;
use netlens::model::Report;
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/report-evidence-v5.json")).unwrap()
}

fn validator() -> Validator {
    let schema: Value =
        serde_json::from_str(include_str!("../docs/schema/report-v5.schema.json")).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn fixture_v4() -> Value {
    serde_json::from_str(include_str!("fixtures/report-evidence-v4.json")).unwrap()
}

fn validator_v4() -> Validator {
    validator_for(include_str!("../docs/schema/report-v4.schema.json"))
}

fn validator_for(schema: &str) -> Validator {
    let schema: Value = serde_json::from_str(schema).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn schema_accepts(value: &Value) -> bool {
    validator().is_valid(value)
}

fn schema_v4_accepts(value: &Value) -> bool {
    validator_v4().is_valid(value)
}

fn rust_accepts(value: Value) -> bool {
    serde_json::from_value::<Report>(value)
        .and_then(|report| {
            report
                .validate()
                .map_err(|error| serde_json::Error::io(std::io::Error::other(error)))?;
            Ok(report)
        })
        .is_ok()
}

fn assert_rejected_by_both(value: Value) {
    assert!(
        !schema_accepts(&value),
        "Schema unexpectedly accepted {value:#}"
    );
    assert!(
        !rust_accepts(value),
        "Rust unexpectedly accepted invalid report"
    );
}

fn assert_semantically_rejected(value: Value) {
    assert!(
        schema_accepts(&value),
        "semantic fixture must remain structurally valid"
    );
    assert!(
        !rust_accepts(value),
        "Report::validate accepted invalid report"
    );
}

fn assert_v4_rejected_by_both(value: Value) {
    assert!(
        !schema_v4_accepts(&value),
        "report-v4 Schema unexpectedly accepted {value:#}"
    );
    assert!(
        !rust_accepts(value),
        "Report::validate unexpectedly accepted invalid report v4"
    );
}

fn assert_rust_validation_error_contains(value: &Value, expected: &str) {
    let report = serde_json::from_value::<Report>(value.clone())
        .expect("targeted semantic fixture must deserialize");
    let error = report
        .validate()
        .expect_err("targeted semantic fixture must fail validation")
        .to_string();
    assert!(
        error.contains(expected),
        "expected validation error containing {expected:?}, got {error:?}"
    );
}

fn set_all_totals_to_exact_zero(value: &mut Value) {
    for total in value["telemetry"]["totals"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        *total = json!({"value": 0, "bound": "exact"});
    }
}

fn set_observation_bound(value: &mut Value, bound: &str) {
    value["observations"][0]["meta"]["descriptor"]["measurement"]["bound"] = json!(bound);
    let observation_id = value["observations"][0]["meta"]["id"].clone();
    let finding = value["findings"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|finding| finding["evidence"][0]["id"] == observation_id)
        .unwrap();
    finding["descriptor"]["measurement"]["bound"] = json!(bound);
}

fn stage_coverage_for_provider_mut<'a>(value: &'a mut Value, provider: &str) -> &'a mut Value {
    value["capabilities"]["stageCoverage"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|coverage| coverage["provider"] == provider)
        .unwrap()
}

fn make_first_subject_a_hop(value: &mut Value, ordinal: Option<u64>) {
    let subject = &mut value["subjects"][0];
    subject["kind"] = json!("hop");
    if let Some(ordinal) = ordinal {
        subject["attributes"]["nwdiag.path.hop_ordinal"] = json!({
            "type": "unsigned",
            "value": ordinal
        });
    }
}

fn set_first_metric_transition(value: &mut Value, transition: &str) {
    let metric_id = value["metrics"][0]["meta"]["id"].clone();
    value["metrics"][0]["meta"]["transition"] = json!(transition);
    let finding = value["findings"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|finding| finding["evidence"][0]["id"] == metric_id)
        .unwrap();
    finding["transition"] = json!(transition);
}

fn socket_diag_report() -> Value {
    let requested = json!({
        "layers": ["socket"],
        "networkNamespace": {"identity": "net:[4026531840]"},
        "interfacePath": null,
        "direction": null,
        "flow": {
            "protocol": null,
            "sourceAddress": null,
            "destinationAddress": null,
            "sourcePort": null,
            "destinationPort": null
        }
    });
    let descriptor = json!({
        "stage": null,
        "hook": null,
        "direction": null,
        "pathRole": null,
        "context": {
            "networkNamespace": null,
            "ingressIfindex": null,
            "egressIfindex": null,
            "queueId": null,
            "cpu": null,
            "protocol": null
        },
        "outcome": {"disposition": null, "signal": null},
        "form": "counter_delta",
        "role": "context",
        "measurement": {
            "unit": "source_units",
            "domain": null,
            "scope": "socket",
            "bound": "lower_bound"
        }
    });
    json!({
        "schemaVersion": 5,
        "window": {"startedAtUnixMs": 1000, "durationMs": 1000},
        "scope": {
            "requested": requested.clone(),
            "providers": [{
                "provider": "linux.sock_diag.skmeminfo",
                "requested": requested,
                "effective": {
                    "layers": ["socket"],
                    "networkNamespace": {
                        "extent": "current",
                        "identity": "net:[4026531840]"
                    },
                    "interfaceScope": {"extent": "all_visible"},
                    "direction": null,
                    "flow": {
                        "protocol": null,
                        "sourceAddress": null,
                        "destinationAddress": null,
                        "sourcePort": null,
                        "destinationPort": null
                    }
                },
                "filterSupport": {
                    "layers": "userspace_exact",
                    "networkNamespace": "kernel_exact",
                    "interfacePath": "broader_only",
                    "direction": "broader_only",
                    "protocol": "broader_only",
                    "sourceAddress": "broader_only",
                    "destinationAddress": "broader_only",
                    "sourcePort": "broader_only",
                    "destinationPort": "broader_only"
                }
            }]
        },
        "capabilities": {
            "schemaVersion": 5,
            "kernelRelease": "fixture",
            "hasKernelBtf": false,
            "tracefsPath": null,
            "kfreeSkb": {
                "available": false,
                "hasDropReason": false,
                "layout": null,
                "formatPath": null
            },
            "selectedBpfMode": "counter_only",
            "providers": [{
                "name": "linux.sock_diag.skmeminfo",
                "state": "available",
                "detail": "all four query pairs completed"
            }],
            "coverage": [{
                "layer": "socket",
                "availability": "active",
                "visibility": "partial",
                "forms": ["counter_delta"],
                "filterSupport": "broader_only",
                "integrity": "complete",
                "sources": ["linux.sock_diag.skmeminfo"],
                "limitations": []
            }],
            "stageCoverage": []
        },
        "subjects": [{
            "id": "s_11111111111111111111111111111111_1",
            "provider": "linux.sock_diag.skmeminfo",
            "kind": "socket",
            "attributes": {}
        }],
        "metrics": [{
            "meta": {
                "id": "e_11111111111111111111111111111111_1",
                "provider": "linux.sock_diag.skmeminfo",
                "layer": null,
                "executionDomain": "linux.kernel",
                "transition": null,
                "descriptor": descriptor.clone(),
                "subjects": [{
                    "role": "primary",
                    "id": "s_11111111111111111111111111111111_1"
                }]
            },
            "metricType": "linux.sock_diag.skmeminfo_drops",
            "values": {"start": 2, "end": 5, "delta": 3, "reset": false},
            "attributes": {}
        }],
        "observations": [],
        "findings": [],
        "telemetry": {
            "totals": {
                "bpfEventsSeen": {"value": 0, "bound": "exact"},
                "bpfOutputLost": {"value": 0, "bound": "exact"},
                "transportEventsReceived": {"value": 0, "bound": "exact"},
                "transportEventsLost": {"value": 0, "bound": "exact"},
                "userEventsDropped": {"value": 0, "bound": "exact"},
                "netlinkLossEvents": {"value": 0, "bound": "exact"},
                "netlinkDumpInterruptions": {"value": 0, "bound": "exact"},
                "parseErrors": {"value": 0, "bound": "exact"}
            },
            "providers": [{
                "provider": "linux.sock_diag.skmeminfo",
                "counters": {
                    "bpfEventsSeen": {"status": "not_applicable"},
                    "bpfOutputLost": {"status": "not_applicable"},
                    "transportEventsReceived": {"status": "not_applicable"},
                    "transportEventsLost": {"status": "not_applicable"},
                    "userEventsDropped": {"status": "not_applicable"},
                    "netlinkLossEvents": {"status": "measured", "value": 0},
                    "netlinkDumpInterruptions": {"status": "measured", "value": 0},
                    "parseErrors": {"status": "measured", "value": 0}
                },
                "sampling": {"mode": "none"}
            }],
            "collectionErrors": [],
            "sampling": {"mode": "none"}
        }
    })
}

fn socket_diag_report_v4() -> Value {
    let mut value = socket_diag_report();
    value["schemaVersion"] = json!(4);
    value["capabilities"]["schemaVersion"] = json!(4);
    value["capabilities"]["effectiveUid"] = json!(0);

    let descriptor = &mut value["metrics"][0]["meta"]["descriptor"];
    descriptor["stage"] = json!("socket.receive_queue");
    descriptor["direction"] = json!("ingress");
    descriptor["pathRole"] = json!("local_input");
    descriptor["outcome"] = json!({"disposition": "dropped", "signal": null});
    descriptor["role"] = json!("causal");
    descriptor["measurement"]["unit"] = json!("occurrences");
    descriptor["measurement"]["domain"] = json!("skb");
    value["metrics"][0]["meta"]["layer"] = json!("socket");

    value["capabilities"]["stageCoverage"] = json!([{
        "provider": "linux.sock_diag.skmeminfo",
        "layer": "socket",
        "stage": "socket.receive_queue",
        "executionDomain": "linux.kernel",
        "availability": "active",
        "visibility": "partial",
        "forms": ["counter_delta"],
        "filterSupport": "broader_only",
        "integrity": "complete",
        "limitations": ["frozen report-v4 compatibility profile"]
    }]);

    let metric = &value["metrics"][0];
    value["findings"] = json!([{
        "id": "socket.receive_queue_drop",
        "layer": metric["meta"]["layer"].clone(),
        "executionDomain": metric["meta"]["executionDomain"].clone(),
        "transition": metric["meta"]["transition"].clone(),
        "descriptor": metric["meta"]["descriptor"].clone(),
        "severity": "warning",
        "confidence": "direct",
        "title": "Socket receive queue drop",
        "summary": "The socket drop counter increased during the capture window.",
        "count": metric["values"]["delta"].clone(),
        "evidence": [{
            "kind": "metric",
            "id": metric["meta"]["id"].clone()
        }]
    }]);
    value
}

fn observation_for_provider_and_cause_mut<'a>(
    value: &'a mut Value,
    provider: &str,
    cause: Option<&str>,
) -> &'a mut Value {
    value["observations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|observation| {
            observation["meta"]["provider"] == provider
                && match cause {
                    Some(expected) => {
                        observation["attributes"]["linux.udp.receive_admission_failure.cause"]
                            ["value"]
                            .as_str()
                            == Some(expected)
                    }
                    None => true,
                }
        })
        .unwrap()
}

fn set_event_bound(value: &mut Value, provider: &str, cause: Option<&str>, bound: &str) {
    let evidence_id = {
        let observation = observation_for_provider_and_cause_mut(value, provider, cause);
        observation["meta"]["descriptor"]["measurement"]["bound"] = json!(bound);
        observation["meta"]["id"].clone()
    };
    let finding = value["findings"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|finding| {
            finding["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .any(|evidence| evidence["id"] == evidence_id)
        })
        .unwrap();
    finding["descriptor"]["measurement"]["bound"] = json!(bound);
}

fn causal_finding_mut<'a>(
    value: &'a mut Value,
    provider: &str,
    cause: Option<&str>,
) -> &'a mut Value {
    let evidence_id =
        observation_for_provider_and_cause_mut(value, provider, cause)["meta"]["id"].clone();
    value["findings"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|finding| {
            finding["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .any(|evidence| evidence["id"] == evidence_id)
        })
        .unwrap()
}

#[test]
fn checked_in_fixture_passes_both_contract_boundaries() {
    let value = fixture();

    assert!(schema_accepts(&value));
    assert!(rust_accepts(value));
}

#[test]
fn sock_diag_generic_context_metric_passes_both_contract_boundaries() {
    let value = socket_diag_report();

    assert!(value["findings"].as_array().unwrap().is_empty());
    assert!(value["capabilities"]["stageCoverage"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(schema_accepts(&value));
    assert!(rust_accepts(value));
}

#[test]
fn sock_diag_generic_context_descriptor_is_exact() {
    for (pointer, replacement) in [
        ("/metrics/0/meta/layer", json!("socket")),
        ("/metrics/0/meta/executionDomain", json!("linux.userspace")),
        (
            "/metrics/0/meta/transition",
            json!("nwdiag.transition.fixture"),
        ),
        (
            "/metrics/0/meta/descriptor/stage",
            json!("socket.receive_queue"),
        ),
        (
            "/metrics/0/meta/descriptor/hook",
            json!({"family": "socket", "name": "receive"}),
        ),
        ("/metrics/0/meta/descriptor/direction", json!("ingress")),
        ("/metrics/0/meta/descriptor/pathRole", json!("local_input")),
        ("/metrics/0/meta/descriptor/context/protocol", json!(17)),
        (
            "/metrics/0/meta/descriptor/outcome/disposition",
            json!("dropped"),
        ),
        (
            "/metrics/0/meta/descriptor/outcome/signal",
            json!("pressure"),
        ),
        ("/metrics/0/meta/descriptor/role", json!("causal")),
        (
            "/metrics/0/meta/descriptor/measurement/unit",
            json!("occurrences"),
        ),
        (
            "/metrics/0/meta/descriptor/measurement/domain",
            json!("skb"),
        ),
        (
            "/metrics/0/meta/descriptor/measurement/scope",
            json!("host"),
        ),
    ] {
        let mut value = socket_diag_report();
        *value.pointer_mut(pointer).unwrap() = replacement;

        assert_rejected_by_both(value);
    }
}

#[test]
fn frozen_v4_sock_diag_profile_rejects_each_false_attribution_mutation() {
    let baseline = socket_diag_report_v4();
    assert!(schema_v4_accepts(&baseline));
    assert!(rust_accepts(baseline));

    for (metric_pointer, finding_pointer, replacement) in [
        ("/meta/layer", "/layer", json!("netdevice")),
        (
            "/meta/descriptor/stage",
            "/descriptor/stage",
            json!("socket.unspecified"),
        ),
        (
            "/meta/descriptor/direction",
            "/descriptor/direction",
            json!("egress"),
        ),
        (
            "/meta/descriptor/pathRole",
            "/descriptor/pathRole",
            json!("local_output"),
        ),
        (
            "/meta/descriptor/outcome",
            "/descriptor/outcome",
            json!({"disposition": null, "signal": null}),
        ),
        (
            "/meta/descriptor/role",
            "/descriptor/role",
            json!("context"),
        ),
        (
            "/meta/descriptor/measurement/unit",
            "/descriptor/measurement/unit",
            json!("bytes"),
        ),
        (
            "/meta/descriptor/measurement/domain",
            "/descriptor/measurement/domain",
            json!("datagram"),
        ),
    ] {
        let mut value = socket_diag_report_v4();
        let evidence_id = {
            let metric = value["metrics"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|metric| metric["meta"]["provider"] == "linux.sock_diag.skmeminfo")
                .unwrap();
            *metric.pointer_mut(metric_pointer).unwrap() = replacement.clone();
            metric["meta"]["id"].clone()
        };
        let finding = value["findings"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|finding| {
                finding["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|evidence| evidence["id"] == evidence_id)
            })
            .unwrap();
        *finding.pointer_mut(finding_pointer).unwrap() = replacement;

        assert_v4_rejected_by_both(value);
    }
}

#[test]
fn sock_diag_contract_rejects_private_attributes_and_wide_values() {
    let mut private = socket_diag_report();
    private["subjects"][0]["attributes"]["linux.socket.cookie"] =
        json!({"type": "unsigned", "value": 42});
    assert_rejected_by_both(private);

    let mut wide = socket_diag_report();
    wide["metrics"][0]["values"]["end"] = json!(4_294_967_296_u64);
    wide["metrics"][0]["values"]["delta"] = json!(4_294_967_294_u64);
    assert_rejected_by_both(wide);
}

#[test]
fn sock_diag_metric_requires_one_primary_opaque_socket_subject() {
    let mut missing = socket_diag_report();
    missing["metrics"][0]["meta"]["subjects"] = json!([]);
    assert_rejected_by_both(missing);

    let mut duplicate = socket_diag_report();
    duplicate["metrics"][0]["meta"]["subjects"] = json!([
        {"role": "primary", "id": "s_11111111111111111111111111111111_1"},
        {"role": "primary", "id": "s_11111111111111111111111111111111_1"}
    ]);
    assert_rejected_by_both(duplicate);

    let mut wrong_role = socket_diag_report();
    wrong_role["metrics"][0]["meta"]["subjects"][0]["role"] = json!("owner");
    assert_rejected_by_both(wrong_role);

    let mut wrong_owner = socket_diag_report();
    wrong_owner["subjects"][0]["provider"] = json!("nwdiag.core");
    assert_semantically_rejected(wrong_owner);
}

#[test]
fn every_v5_sock_diag_metric_requires_a_fresh_socket_subject() {
    let mut reused = socket_diag_report();
    let mut second_metric = reused["metrics"][0].clone();
    second_metric["meta"]["id"] = json!("e_11111111111111111111111111111111_2");
    second_metric["values"] = json!({
        "start": 10,
        "end": 11,
        "delta": 1,
        "reset": false
    });
    reused["metrics"]
        .as_array_mut()
        .unwrap()
        .push(second_metric);
    assert_semantically_rejected(reused);

    let mut distinct = socket_diag_report();
    let mut second_subject = distinct["subjects"][0].clone();
    second_subject["id"] = json!("s_11111111111111111111111111111111_2");
    distinct["subjects"]
        .as_array_mut()
        .unwrap()
        .push(second_subject);
    let mut second_metric = distinct["metrics"][0].clone();
    second_metric["meta"]["id"] = json!("e_11111111111111111111111111111111_2");
    second_metric["meta"]["subjects"][0]["id"] = json!("s_11111111111111111111111111111111_2");
    second_metric["values"] = json!({
        "start": 10,
        "end": 11,
        "delta": 1,
        "reset": false
    });
    distinct["metrics"]
        .as_array_mut()
        .unwrap()
        .push(second_metric);
    assert!(schema_accepts(&distinct));
    assert!(rust_accepts(distinct));
}

#[test]
fn sock_diag_positive_delta_cannot_claim_an_exact_bound() {
    let mut value = socket_diag_report();
    value["metrics"][0]["meta"]["descriptor"]["measurement"]["bound"] = json!("exact");

    assert_rejected_by_both(value);
}

#[test]
fn sock_diag_positive_delta_requires_a_lower_bound() {
    let mut value = socket_diag_report();
    value["metrics"][0]["meta"]["descriptor"]["measurement"]["bound"] = Value::Null;

    assert_rejected_by_both(value);
}

#[test]
fn sock_diag_reset_cannot_claim_a_measurement_bound() {
    let mut value = socket_diag_report();
    value["metrics"][0]["values"] = json!({"start": 5, "end": 2, "delta": null, "reset": true});

    assert_rejected_by_both(value);
}

#[test]
fn sock_diag_metric_requires_both_counter_endpoints() {
    for missing in ["start", "end"] {
        let mut value = socket_diag_report();
        value["metrics"][0]["values"][missing] = Value::Null;
        value["metrics"][0]["values"]["delta"] = Value::Null;
        value["metrics"][0]["meta"]["descriptor"]["measurement"]["bound"] = Value::Null;

        assert_rejected_by_both(value);
    }
}

#[test]
fn sock_diag_metric_rejects_an_unchanged_counter_row() {
    let mut value = socket_diag_report();
    value["metrics"][0]["values"] = json!({"start": 2, "end": 2, "delta": 0, "reset": false});

    assert_rejected_by_both(value);
}

#[test]
fn sock_diag_generic_context_cannot_back_a_finding() {
    let mut value = socket_diag_report();
    let mut descriptor = value["metrics"][0]["meta"]["descriptor"].clone();
    descriptor["measurement"]["unit"] = json!("occurrences");
    value["findings"] = json!([{
        "id": "socket.drop_counter_increase",
        "layer": null,
        "executionDomain": "linux.kernel",
        "transition": null,
        "descriptor": descriptor,
        "severity": "info",
        "confidence": "direct",
        "title": "Per-socket kernel drop counter increased",
        "summary": "The generic source counter increased.",
        "count": 3,
        "evidence": [{
            "kind": "metric",
            "id": "e_11111111111111111111111111111111_1"
        }]
    }]);

    assert_semantically_rejected(value);
}

#[test]
fn sock_diag_reset_metric_remains_reportable_without_a_finding() {
    let mut value = socket_diag_report();
    value["metrics"][0]["values"] = json!({"start": 5, "end": 2, "delta": null, "reset": true});
    value["metrics"][0]["meta"]["descriptor"]["measurement"]["bound"] = Value::Null;

    assert!(schema_accepts(&value));
    assert!(rust_accepts(value));
}

#[test]
fn partial_sock_diag_failure_retains_lower_bound_evidence_and_loss_state() {
    let mut value = socket_diag_report();
    value["capabilities"]["providers"][0]["state"] = json!("degraded");
    value["capabilities"]["providers"][0]["detail"] =
        json!("3/4 start/end sock_diag query pairs completed; 1 query error");
    value["capabilities"]["coverage"][0]["availability"] = json!("degraded");
    value["capabilities"]["coverage"][0]["integrity"] = json!("loss_detected");
    value["capabilities"]["coverage"][0]["limitations"] =
        json!(["one sock_diag query pair was incomplete"]);
    value["telemetry"]["totals"]["netlinkLossEvents"] = json!({"value": 1, "bound": "exact"});
    value["telemetry"]["providers"][0]["counters"]["netlinkLossEvents"] =
        json!({"status": "measured", "value": 1});
    value["telemetry"]["collectionErrors"] = json!([{
        "provider": "linux.sock_diag.skmeminfo",
        "message": "end snapshot: IPv6 UDP dump was interrupted"
    }]);

    assert!(schema_accepts(&value));
    assert!(rust_accepts(value));
}

#[test]
fn source_units_is_confined_to_sock_diag_metrics_and_never_findings() {
    let mut other_metric = fixture();
    other_metric["metrics"][0]["meta"]["descriptor"]["measurement"]["unit"] = json!("source_units");
    assert_rejected_by_both(other_metric);

    let mut observation = fixture();
    observation["observations"][0]["meta"]["descriptor"]["measurement"]["unit"] =
        json!("source_units");
    assert_rejected_by_both(observation);

    let mut finding = fixture();
    finding["findings"][0]["descriptor"]["measurement"]["unit"] = json!("source_units");
    assert_rejected_by_both(finding);
}

#[test]
fn udp_receive_admission_accepts_both_closed_cause_profiles() {
    for (cause, stage) in [
        ("receive_buffer", "socket.receive_queue"),
        ("protocol_memory", "socket.protocol_memory"),
    ] {
        let mut value = fixture();
        let evidence_id = {
            let observation = observation_for_provider_and_cause_mut(
                &mut value,
                "linux.tracepoint.udp_fail_queue_rcv_skb",
                Some(cause),
            );
            assert_eq!(
                observation["eventType"],
                "linux.udp.receive_admission_failure"
            );
            assert_eq!(observation["meta"]["descriptor"]["stage"], stage);
            observation["meta"]["id"].clone()
        };
        value["observations"]
            .as_array_mut()
            .unwrap()
            .retain(|observation| observation["meta"]["id"] == evidence_id);
        value["findings"]
            .as_array_mut()
            .unwrap()
            .retain(|finding| finding["evidence"][0]["id"] == evidence_id);

        assert!(schema_accepts(&value));
        assert!(rust_accepts(value));
    }
}

#[test]
fn udp_receive_admission_cause_and_stage_must_match() {
    for (cause, wrong_stage) in [
        ("receive_buffer", "socket.protocol_memory"),
        ("protocol_memory", "socket.receive_queue"),
    ] {
        let mut value = fixture();
        observation_for_provider_and_cause_mut(
            &mut value,
            "linux.tracepoint.udp_fail_queue_rcv_skb",
            Some(cause),
        )["meta"]["descriptor"]["stage"] = json!(wrong_stage);

        assert_rejected_by_both(value);
    }
}

#[test]
fn causal_socket_events_accept_exact_and_lower_bound_counts() {
    for (provider, cause) in [
        (
            "linux.tracepoint.udp_fail_queue_rcv_skb",
            Some("receive_buffer"),
        ),
        (
            "linux.tracepoint.udp_fail_queue_rcv_skb",
            Some("protocol_memory"),
        ),
        ("linux.tracepoint.sock_rcvqueue_full", None),
    ] {
        let mut value = fixture();
        set_event_bound(&mut value, provider, cause, "lower_bound");

        assert!(schema_accepts(&value));
        assert!(rust_accepts(value));
    }
}

#[test]
fn socket_receive_queue_full_requires_bounded_gauge_attributes() {
    const PROVIDER: &str = "linux.tracepoint.sock_rcvqueue_full";
    for attribute in [
        "linux.socket.receive_memory_allocated_bytes",
        "linux.skb.true_size_bytes",
        "linux.socket.receive_buffer_limit_bytes",
    ] {
        let mut value = fixture();
        observation_for_provider_and_cause_mut(&mut value, PROVIDER, None)["attributes"]
            .as_object_mut()
            .unwrap()
            .remove(attribute);
        assert_rejected_by_both(value);
    }

    let mut maximums = fixture();
    let attributes =
        &mut observation_for_provider_and_cause_mut(&mut maximums, PROVIDER, None)["attributes"];
    attributes["linux.socket.receive_memory_allocated_bytes"]["value"] = json!(i32::MAX as u64);
    attributes["linux.skb.true_size_bytes"]["value"] = json!(u32::MAX as u64);
    attributes["linux.socket.receive_buffer_limit_bytes"]["value"] = json!(i32::MAX as u64);
    assert!(schema_accepts(&maximums));
    assert!(rust_accepts(maximums));

    for (attribute, oversized) in [
        (
            "linux.socket.receive_memory_allocated_bytes",
            i32::MAX as u64 + 1,
        ),
        ("linux.skb.true_size_bytes", u32::MAX as u64 + 1),
        (
            "linux.socket.receive_buffer_limit_bytes",
            i32::MAX as u64 + 1,
        ),
    ] {
        let mut value = fixture();
        observation_for_provider_and_cause_mut(&mut value, PROVIDER, None)["attributes"]
            [attribute]["value"] = json!(oversized);
        assert_rejected_by_both(value);
    }
}

#[test]
fn socket_receive_queue_full_event_profile_is_exact() {
    const PROVIDER: &str = "linux.tracepoint.sock_rcvqueue_full";
    for (pointer, replacement) in [
        (
            "/meta/provider",
            json!("linux.tracepoint.udp_fail_queue_rcv_skb"),
        ),
        ("/eventType", json!("linux.udp.receive_admission_failure")),
        ("/meta/layer", json!("netdevice")),
        ("/meta/executionDomain", json!("linux.userspace")),
        ("/meta/transition", json!("nwdiag.transition.fixture")),
        ("/meta/descriptor/stage", json!("socket.protocol_memory")),
        (
            "/meta/descriptor/hook",
            json!({"family": "socket", "name": "receive"}),
        ),
        ("/meta/descriptor/direction", json!("egress")),
        ("/meta/descriptor/pathRole", json!("local_output")),
        ("/meta/descriptor/context/protocol", json!(17)),
        ("/meta/descriptor/outcome/disposition", json!("dropped")),
        ("/meta/descriptor/outcome/signal", json!("pressure")),
        ("/meta/descriptor/role", json!("context")),
        ("/meta/descriptor/measurement/unit", json!("bytes")),
        ("/meta/descriptor/measurement/domain", json!("datagram")),
        ("/meta/descriptor/measurement/scope", json!("socket")),
        ("/meta/descriptor/measurement/bound", json!("estimate")),
        (
            "/meta/subjects",
            json!([{
                "role": "primary",
                "id": "s_00000000000000000000000000000000_2"
            }]),
        ),
    ] {
        let mut value = fixture();
        let observation = observation_for_provider_and_cause_mut(&mut value, PROVIDER, None);
        *observation.pointer_mut(pointer).unwrap() = replacement;

        assert_rejected_by_both(value);
    }

    let mut private = fixture();
    observation_for_provider_and_cause_mut(&mut private, PROVIDER, None)["attributes"]
        ["linux.socket.cookie"] = json!({"type": "unsigned", "value": 42});

    assert_rejected_by_both(private);
}

#[test]
fn causal_socket_event_contracts_reject_private_identity_canaries() {
    for (provider, cause) in [
        (
            "linux.tracepoint.udp_fail_queue_rcv_skb",
            Some("receive_buffer"),
        ),
        (
            "linux.tracepoint.udp_fail_queue_rcv_skb",
            Some("protocol_memory"),
        ),
        ("linux.tracepoint.sock_rcvqueue_full", None),
    ] {
        for (attribute, value) in [
            (
                "linux.socket.source_address",
                json!({"type": "string", "value": "198.51.100.77"}),
            ),
            (
                "linux.socket.destination_address",
                json!({"type": "string", "value": "2001:db8::77"}),
            ),
            (
                "linux.socket.source_port",
                json!({"type": "unsigned", "value": 61_001}),
            ),
            (
                "linux.socket.destination_port",
                json!({"type": "unsigned", "value": 61_002}),
            ),
            (
                "linux.socket.pointer",
                json!({"type": "unsigned", "value": 0xfeed_cafe_u64}),
            ),
            (
                "linux.skb.pointer",
                json!({"type": "unsigned", "value": 0xdead_beef_u64}),
            ),
            (
                "linux.socket.cookie",
                json!({"type": "unsigned", "value": 0x1122_3344_u64}),
            ),
            (
                "linux.socket.inode",
                json!({"type": "unsigned", "value": 4_242_424}),
            ),
            (
                "linux.socket.uid",
                json!({"type": "unsigned", "value": 424_242}),
            ),
            (
                "linux.queue.private_id",
                json!({"type": "unsigned", "value": 515_151}),
            ),
        ] {
            let mut report = fixture();
            observation_for_provider_and_cause_mut(&mut report, provider, cause)["attributes"]
                [attribute] = value.clone();

            assert_rejected_by_both(report);
        }
    }
}

#[test]
fn causal_socket_finding_profiles_reject_semantic_mutations() {
    for (provider, cause) in [
        (
            "linux.tracepoint.udp_fail_queue_rcv_skb",
            Some("receive_buffer"),
        ),
        (
            "linux.tracepoint.udp_fail_queue_rcv_skb",
            Some("protocol_memory"),
        ),
        ("linux.tracepoint.sock_rcvqueue_full", None),
    ] {
        for (field, replacement) in [
            ("id", json!("socket.unregistered_rejection")),
            ("severity", json!("info")),
            ("confidence", json!("correlated")),
            ("title", json!("Misleading causal title")),
            ("summary", json!("Misleading causal summary")),
            ("count", json!(2)),
        ] {
            let mut value = fixture();
            causal_finding_mut(&mut value, provider, cause)[field] = replacement.clone();

            assert_semantically_rejected(value);
        }
    }
}

#[test]
fn causal_socket_finding_ids_are_reserved_for_their_registered_events() {
    let mut value = fixture();
    let unrelated = value["findings"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|finding| finding["id"] == "drop_reason.netfilter_drop")
        .unwrap();
    unrelated["id"] = json!("socket.receive_queue_rejection");

    assert_semantically_rejected(value);
}

#[test]
fn causal_socket_findings_cannot_swap_or_reuse_event_evidence() {
    let mut swapped = fixture();
    let generic_evidence = observation_for_provider_and_cause_mut(
        &mut swapped,
        "linux.tracepoint.sock_rcvqueue_full",
        None,
    )["meta"]["id"]
        .clone();
    causal_finding_mut(
        &mut swapped,
        "linux.tracepoint.udp_fail_queue_rcv_skb",
        Some("receive_buffer"),
    )["evidence"][0]["id"] = generic_evidence;
    assert_semantically_rejected(swapped);

    let mut reused = fixture();
    let duplicate =
        causal_finding_mut(&mut reused, "linux.tracepoint.sock_rcvqueue_full", None).clone();
    reused["findings"].as_array_mut().unwrap().push(duplicate);
    assert_semantically_rejected(reused);
}

#[test]
fn report_v5_fixture_keeps_rust_serialization_parity() {
    let value = fixture();
    let report: Report = serde_json::from_value(value.clone()).unwrap();
    report.validate().unwrap();

    assert_eq!(serde_json::to_value(report).unwrap(), value);
}

#[test]
fn report_v5_does_not_expose_effective_uid_and_v4_profile_stays_frozen() {
    let mut v5 = fixture();
    assert!(v5["capabilities"].get("effectiveUid").is_none());
    v5["capabilities"]["effectiveUid"] = json!(424_242);
    assert_rejected_by_both(v5);

    let mut v4 = fixture_v4();
    assert!(rust_accepts(v4.clone()));
    v4["capabilities"]
        .as_object_mut()
        .unwrap()
        .remove("effectiveUid");
    assert!(!rust_accepts(v4));
}

#[test]
fn frozen_fixtures_remain_valid_only_for_their_schema_versions() {
    let v1: Value = serde_json::from_str(include_str!("fixtures/report-evidence-v1.json")).unwrap();
    let v2: Value = serde_json::from_str(include_str!("fixtures/report-evidence-v2.json")).unwrap();
    let v3: Value = serde_json::from_str(include_str!("fixtures/report-evidence-v3.json")).unwrap();
    let v4 = fixture_v4();
    let v5 = fixture();
    let fixtures = [&v1, &v2, &v3, &v4, &v5];
    let validators = [
        validator_for(include_str!("../docs/schema/report-v1.schema.json")),
        validator_for(include_str!("../docs/schema/report-v2.schema.json")),
        validator_for(include_str!("../docs/schema/report-v3.schema.json")),
        validator_v4(),
        validator(),
    ];

    for (fixture_index, fixture) in fixtures.into_iter().enumerate() {
        for (validator_index, validator) in validators.iter().enumerate() {
            assert_eq!(
                validator.is_valid(fixture),
                fixture_index == validator_index,
                "report v{} fixture against report v{} schema",
                fixture_index + 1,
                validator_index + 1
            );
        }
    }

    let mut generic_sock_diag_as_v4 = socket_diag_report();
    generic_sock_diag_as_v4["schemaVersion"] = json!(4);
    generic_sock_diag_as_v4["capabilities"]["schemaVersion"] = json!(4);
    assert!(!validators[3].is_valid(&generic_sock_diag_as_v4));
}

#[test]
fn frozen_report_contract_files_keep_their_sha256() {
    for (path, expected) in [
        (
            "docs/schema/report-v1.schema.json",
            "5ae0f22d8372168f64b5af4af57925ff36826eb84ce05f7891c6a736046ff6c5",
        ),
        (
            "docs/schema/report-v2.schema.json",
            "dda310dcd11e585ef859c43bde7bc1bd255bd664640e2e215beb0b945f7b3719",
        ),
        (
            "tests/fixtures/report-evidence-v1.json",
            "9c879caf0784a5b1224a34ce82814637dbd982f18a4f31bb66cc87ef03cec97d",
        ),
        (
            "tests/fixtures/report-evidence-v2.json",
            "4d1097b83b62032fa33f6d0e296042f0c2000742c91be4cec3f0babaa6d75c51",
        ),
        (
            "docs/schema/report-v3.schema.json",
            "e6fa16944605159da66014c8c04a9934e4210c6721acd5b11408c96ed7c7dc97",
        ),
        (
            "tests/fixtures/report-evidence-v3.json",
            "ea955c23b8629bef6b480c22d6bbbb722e9108290c62a668c13337b4918e3e97",
        ),
        (
            "docs/schema/report-v4.schema.json",
            "d15cd3804e88da00334cfecb1b9962b926c8ab7e84ffc4da579f716dc89392b5",
        ),
        (
            "tests/fixtures/report-evidence-v4.json",
            "bfb15aa9784d697f4169020b658065e01ed0e8afdc960b20b765d7fc4c650996",
        ),
        (
            "docs/schema/report-v5.schema.json",
            "9a6d12f3f0745b6f34865ab5cabb0ca4c0e75c82a3f4246ad2819e05cfe234d9",
        ),
        (
            "tests/fixtures/report-evidence-v5.json",
            "1138c0e78f97b4319114c5224c262d65a21337f88c2a8ac3a1441e4d1becae65",
        ),
    ] {
        let output = Command::new("sha256sum")
            .arg(format!("{}/{path}", env!("CARGO_MANIFEST_DIR")))
            .output()
            .expect("sha256sum is required by the Linux contract test gate");
        assert!(output.status.success(), "sha256sum failed for {path}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.split_whitespace().next(), Some(expected), "{path}");
    }
}

#[test]
fn execution_domain_and_transition_are_required_nullable_fields() {
    for pointer in ["/metrics/0/meta", "/observations/0/meta", "/findings/0"] {
        for field in ["executionDomain", "transition"] {
            let mut value = fixture();
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert_rejected_by_both(value);
        }
    }

    let mut missing_coverage_domain = fixture();
    missing_coverage_domain["capabilities"]["stageCoverage"][0]
        .as_object_mut()
        .unwrap()
        .remove("executionDomain");
    assert_rejected_by_both(missing_coverage_domain);

    let mut nullable = fixture();
    nullable["capabilities"]["stageCoverage"][0]["executionDomain"] = Value::Null;
    nullable["capabilities"]["stageCoverage"][1]["executionDomain"] = Value::Null;
    nullable["metrics"][0]["meta"]["executionDomain"] = Value::Null;
    nullable["observations"][0]["meta"]["executionDomain"] = Value::Null;
    nullable["findings"][0]["executionDomain"] = Value::Null;
    nullable["findings"][1]["executionDomain"] = Value::Null;
    assert!(schema_accepts(&nullable));
    assert!(rust_accepts(nullable));
}

#[test]
fn required_nullable_fields_are_required_by_both_contracts() {
    let mut value = fixture();
    value["scope"]["requested"]
        .as_object_mut()
        .unwrap()
        .remove("interfacePath");

    assert_rejected_by_both(value);
}

#[test]
fn interface_name_unicode_whitespace_is_rejected_by_both_contracts() {
    let mut value = fixture();
    value["scope"]["requested"]["interfacePath"]["anchor"]["name"] =
        serde_json::json!("eth\u{00a0}0");
    let requested = value["scope"]["requested"].clone();
    for provider in value["scope"]["providers"].as_array_mut().unwrap() {
        provider["requested"] = requested.clone();
        if provider["effective"]["interfaceScope"]["extent"] == "path" {
            provider["effective"]["interfaceScope"]["path"]["anchor"]["name"] =
                serde_json::json!("eth\u{00a0}0");
        }
    }

    assert_rejected_by_both(value);
}

#[test]
fn fixed_schema_version_is_enforced_by_both_contracts() {
    let mut value = fixture();
    value["schemaVersion"] = json!(1);

    assert_rejected_by_both(value);
}

#[test]
fn removed_scalar_telemetry_fields_are_rejected_by_both_contracts() {
    let mut value = fixture();
    value["telemetry"]["bpfEventsSeen"] = json!(0);

    assert_rejected_by_both(value);
}

#[test]
fn reason_name_and_u32_reason_code_limits_match() {
    let mut bad_name = fixture();
    let attributes = bad_name["observations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|observation| {
            observation["attributes"]
                .as_object_mut()
                .filter(|attributes| attributes.contains_key("linux.skb_free.reason_name"))
        })
        .expect("fixture contains a named skb-free reason");
    attributes["linux.skb_free.reason_name"]["value"] = json!("bad-reason");
    assert_rejected_by_both(bad_name);

    let mut oversized_code = fixture();
    let attributes = oversized_code["observations"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|observation| {
            observation["attributes"]
                .as_object_mut()
                .filter(|attributes| attributes.contains_key("linux.skb_free.reason_code"))
        })
        .expect("fixture contains a raw skb-free reason");
    attributes["linux.skb_free.reason_code"]["value"] = json!(u64::from(u32::MAX) + 1);
    assert_rejected_by_both(oversized_code);
}

#[test]
fn sampling_u32_limits_match() {
    let mut value = fixture();
    value["telemetry"]["providers"][0]["sampling"] = json!({
        "mode": "sampled",
        "method": "nwdiag.every_n",
        "scope": "linux.skb.free",
        "effectiveNumerator": u64::from(u32::MAX) + 1,
        "effectiveDenominator": u64::from(u32::MAX) + 1
    });

    assert_rejected_by_both(value);
}

#[test]
fn u64_limits_match() {
    let mut value = fixture();
    value["window"]["durationMs"] = serde_json::from_str("18446744073709551616").unwrap();

    assert_rejected_by_both(value);

    let mut metric_value = fixture();
    metric_value["metrics"][0]["values"]["start"] =
        serde_json::from_str("18446744073709551616").unwrap();

    assert_rejected_by_both(metric_value);
}

#[test]
fn duplicate_evidence_ids_are_a_semantic_error() {
    let mut value = fixture();
    let id = value["metrics"][0]["meta"]["id"].clone();
    value["observations"][0]["meta"]["id"] = id;

    assert_semantically_rejected(value);
}

#[test]
fn dangling_and_wrong_kind_evidence_refs_are_semantic_errors() {
    let mut dangling = fixture();
    dangling["findings"][0]["evidence"][0]["id"] = json!("e_ffffffffffffffffffffffffffffffff_999");
    assert_semantically_rejected(dangling);

    let mut wrong_kind = fixture();
    let kind = wrong_kind["findings"][0]["evidence"][0]["kind"]
        .as_str()
        .unwrap();
    wrong_kind["findings"][0]["evidence"][0]["kind"] = json!(if kind == "metric" {
        "observation"
    } else {
        "metric"
    });
    assert_semantically_rejected(wrong_kind);
}

#[test]
fn duplicate_and_dangling_subject_ids_are_semantic_errors() {
    let mut duplicate = fixture();
    let subject = duplicate["subjects"][0].clone();
    duplicate["subjects"].as_array_mut().unwrap().push(subject);
    assert_semantically_rejected(duplicate);

    let mut dangling = fixture();
    dangling["metrics"][0]["meta"]["subjects"][0]["id"] =
        json!("s_ffffffffffffffffffffffffffffffff_999");
    assert_semantically_rejected(dangling);
}

#[test]
fn invalid_subject_role_and_context_conflict_are_semantic_errors() {
    let mut invalid_role = fixture();
    invalid_role["metrics"][0]["meta"]["subjects"][0]["role"] = json!("before");
    assert_semantically_rejected(invalid_role);

    let mut conflict = fixture();
    let subject_id = conflict["metrics"][0]["meta"]["subjects"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let subject = conflict["subjects"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|subject| subject["id"] == subject_id)
        .unwrap();
    subject["attributes"]["linux.interface.ifindex"]["value"] = json!(999);
    assert_semantically_rejected(conflict);
}

#[test]
fn undirected_and_owner_subjects_cannot_bypass_ifindex_context() {
    for role in ["primary", "owner", "peer"] {
        let mut value = fixture();
        value["metrics"][0]["meta"]["subjects"][0]["role"] = json!(role);
        value["metrics"][0]["meta"]["descriptor"]["direction"] = Value::Null;
        let subject_id = value["metrics"][0]["meta"]["subjects"][0]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let subject = value["subjects"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|subject| subject["id"] == subject_id)
            .unwrap();
        subject["attributes"]["linux.interface.ifindex"]["value"] = json!(999);

        assert_semantically_rejected(value);
    }
}

#[test]
fn subject_provider_kind_registry_is_closed() {
    let mut value = fixture();
    value["subjects"][0]["provider"] = json!("linux.proc.protocol_counters");
    value["subjects"][0]["attributes"] = json!({});

    assert_rejected_by_both(value);
}

#[test]
fn metric_values_and_bounds_must_be_consistent() {
    let mut decreasing = fixture();
    decreasing["metrics"][0]["values"] = json!({
        "start": 10,
        "end": 2,
        "delta": 4,
        "reset": false
    });
    assert_semantically_rejected(decreasing);

    let mut wrong_delta = fixture();
    wrong_delta["metrics"][0]["values"]["delta"] = json!(3);
    assert_semantically_rejected(wrong_delta);

    let mut unavailable_delta = fixture();
    unavailable_delta["metrics"][0]["values"] = json!({
        "start": 10,
        "end": null,
        "delta": null,
        "reset": false
    });
    assert_semantically_rejected(unavailable_delta);
}

#[test]
fn valid_reset_and_missing_endpoint_metrics_remain_reportable() {
    for values in [
        json!({"start": 10, "end": 2, "delta": null, "reset": true}),
        json!({"start": 10, "end": null, "delta": null, "reset": false}),
    ] {
        let mut value = fixture();
        let metric_id = value["metrics"][0]["meta"]["id"].clone();
        value["metrics"][0]["values"] = values;
        value["metrics"][0]["meta"]["descriptor"]["measurement"]["bound"] = Value::Null;
        value["findings"]
            .as_array_mut()
            .unwrap()
            .retain(|finding| finding["evidence"][0]["id"] != metric_id);

        assert!(schema_accepts(&value));
        assert!(rust_accepts(value));
    }
}

#[test]
fn provider_stage_coverage_keys_are_unique_and_required_by_evidence() {
    let mut duplicate = fixture();
    let mut duplicate_row = duplicate["capabilities"]["stageCoverage"][0].clone();
    duplicate_row["limitations"] = json!(["same provider-stage-domain key"]);
    duplicate["capabilities"]["stageCoverage"]
        .as_array_mut()
        .unwrap()
        .push(duplicate_row);
    assert_semantically_rejected(duplicate);

    let mut missing = fixture();
    missing["capabilities"]["stageCoverage"]
        .as_array_mut()
        .unwrap()
        .retain(|coverage| coverage["provider"] != "linux.link.counters");
    assert_semantically_rejected(missing);
}

#[test]
fn capability_provider_and_layer_coverage_rows_are_unique() {
    let mut duplicate_provider = fixture();
    let provider = duplicate_provider["capabilities"]["providers"][0].clone();
    duplicate_provider["capabilities"]["providers"]
        .as_array_mut()
        .unwrap()
        .push(provider);
    assert_semantically_rejected(duplicate_provider);

    let mut duplicate_layer = fixture();
    let coverage = duplicate_layer["capabilities"]["coverage"][0].clone();
    duplicate_layer["capabilities"]["coverage"]
        .as_array_mut()
        .unwrap()
        .push(coverage);
    assert_semantically_rejected(duplicate_layer);

    let mut missing_layer = fixture();
    missing_layer["capabilities"]["coverage"]
        .as_array_mut()
        .unwrap()
        .retain(|coverage| coverage["layer"] != "netdevice");
    assert_semantically_rejected(missing_layer);

    let mut inconsistent_state = fixture();
    inconsistent_state["capabilities"]["coverage"][0]["availability"] = json!("unsupported");
    assert_semantically_rejected(inconsistent_state);
}

#[test]
fn provider_registry_rejects_layers_outside_declared_ownership() {
    let mut aggregate = fixture();
    aggregate["capabilities"]["coverage"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|coverage| coverage["layer"] == "netfilter")
        .unwrap()["sources"] = json!(["rtnetlink_link_stats"]);
    assert!(schema_accepts(&aggregate));
    assert_rust_validation_error_contains(
        &aggregate,
        "layer coverage netfilter is outside source rtnetlink_link_stats ownership",
    );

    let mut stage = fixture();
    stage_coverage_for_provider_mut(&mut stage, "linux.tracepoint.kfree_skb")["provider"] =
        json!("linux.link.counters");
    assert!(schema_accepts(&stage));
    assert_rust_validation_error_contains(&stage, "outside provider linux.link.counters ownership");

    let mut scope = fixture();
    scope["scope"]["providers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|provider| provider["provider"] == "linux.link.counters")
        .unwrap()["effective"]["layers"] = json!(["netfilter"]);
    assert!(schema_accepts(&scope));
    assert_rust_validation_error_contains(
        &scope,
        "provider scope linux.link.counters includes a layer outside its ownership",
    );
}

#[test]
fn active_stage_coverage_requires_an_available_provider_and_aggregate_layer() {
    let mut unavailable_provider = fixture();
    unavailable_provider["capabilities"]["providers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|provider| provider["name"] == "linux.link.counters")
        .unwrap()["state"] = json!("unavailable");
    assert!(schema_accepts(&unavailable_provider));
    assert_rust_validation_error_contains(
        &unavailable_provider,
        "belongs to unavailable provider linux.link.counters",
    );

    let mut unavailable_layer = fixture();
    let layer = unavailable_layer["capabilities"]["coverage"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|coverage| coverage["layer"] == "netdevice")
        .unwrap();
    layer["availability"] = json!("unsupported");
    layer["forms"] = json!([]);
    assert!(schema_accepts(&unavailable_layer));
    assert_rust_validation_error_contains(
        &unavailable_layer,
        "has unavailable aggregate layer netdevice",
    );

    let mut missing_aggregate_form = fixture();
    missing_aggregate_form["capabilities"]["coverage"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|coverage| coverage["layer"] == "netdevice")
        .unwrap()["forms"] = json!(["event"]);
    assert!(schema_accepts(&missing_aggregate_form));
    assert_rust_validation_error_contains(
        &missing_aggregate_form,
        "forms are absent from aggregate layer netdevice",
    );
}

#[test]
fn evidence_must_match_stage_coverage_domain_form_and_status() {
    let mut wrong_domain = fixture();
    stage_coverage_for_provider_mut(&mut wrong_domain, "linux.link.counters")["executionDomain"] =
        json!("linux.hardware");
    assert_semantically_rejected(wrong_domain);

    let mut wrong_form = fixture();
    stage_coverage_for_provider_mut(&mut wrong_form, "linux.link.counters")["forms"] =
        json!(["event"]);
    assert_semantically_rejected(wrong_form);

    let mut unavailable = fixture();
    let coverage = stage_coverage_for_provider_mut(&mut unavailable, "linux.link.counters");
    coverage["availability"] = json!("error");
    coverage["forms"] = json!([]);
    assert_semantically_rejected(unavailable);
}

#[test]
fn transitions_require_both_before_and_after_endpoints() {
    for only_role in ["before", "after"] {
        let mut value = fixture();
        make_first_subject_a_hop(&mut value, Some(1));
        set_first_metric_transition(&mut value, "nwdiag.transition.fixture");
        value["metrics"][0]["meta"]["subjects"][0]["role"] = json!(only_role);

        assert!(!schema_accepts(&value));
        assert_rust_validation_error_contains(
            &value,
            "transition requires before and after endpoints",
        );
    }

    let mut overlapping = fixture();
    make_first_subject_a_hop(&mut overlapping, Some(1));
    let subject_id = overlapping["metrics"][0]["meta"]["subjects"][0]["id"].clone();
    set_first_metric_transition(&mut overlapping, "nwdiag.transition.fixture");
    overlapping["metrics"][0]["meta"]["subjects"] = json!([
        {"role": "before", "id": subject_id},
        {"role": "after", "id": subject_id}
    ]);
    assert!(schema_accepts(&overlapping));
    assert_rust_validation_error_contains(
        &overlapping,
        "transition reuses one endpoint as both before and after",
    );
}

#[test]
fn transitions_require_a_domain_and_hop_or_flow_domain_endpoints() {
    let mut missing_domain = fixture();
    make_first_subject_a_hop(&mut missing_domain, Some(1));
    let mut second_hop = missing_domain["subjects"][0].clone();
    second_hop["id"] = json!("s_00000000000000000000000000000000_99");
    second_hop["attributes"]["nwdiag.path.hop_ordinal"]["value"] = json!(2);
    missing_domain["subjects"]
        .as_array_mut()
        .unwrap()
        .push(second_hop);
    set_first_metric_transition(&mut missing_domain, "nwdiag.transition.fixture");
    missing_domain["metrics"][0]["meta"]["executionDomain"] = Value::Null;
    missing_domain["findings"][0]["executionDomain"] = Value::Null;
    missing_domain["metrics"][0]["meta"]["subjects"] = json!([
        {"role": "before", "id": "s_00000000000000000000000000000000_1"},
        {"role": "after", "id": "s_00000000000000000000000000000000_99"}
    ]);
    assert!(!schema_accepts(&missing_domain));
    assert_rust_validation_error_contains(&missing_domain, "transition has no execution domain");

    let mut invalid_kinds = fixture();
    invalid_kinds["subjects"][0]["provider"] = json!("nwdiag.core");
    invalid_kinds["subjects"][0]["kind"] = json!("rule");
    invalid_kinds["subjects"][0]["attributes"] = json!({});
    let mut program = invalid_kinds["subjects"][0].clone();
    program["id"] = json!("s_00000000000000000000000000000000_99");
    program["kind"] = json!("program");
    invalid_kinds["subjects"]
        .as_array_mut()
        .unwrap()
        .push(program);
    set_first_metric_transition(&mut invalid_kinds, "nwdiag.transition.fixture");
    invalid_kinds["metrics"][0]["meta"]["subjects"] = json!([
        {"role": "before", "id": "s_00000000000000000000000000000000_1"},
        {"role": "after", "id": "s_00000000000000000000000000000000_99"}
    ]);
    assert!(schema_accepts(&invalid_kinds));
    assert_rust_validation_error_contains(&invalid_kinds, "is not a hop or flow domain");
}

#[test]
fn hop_subjects_require_a_positive_ordinal() {
    let mut missing = fixture();
    make_first_subject_a_hop(&mut missing, None);
    assert_rejected_by_both(missing);

    let mut zero = fixture();
    make_first_subject_a_hop(&mut zero, Some(0));
    assert_rejected_by_both(zero);

    let mut oversized = fixture();
    make_first_subject_a_hop(&mut oversized, Some(u64::from(u32::MAX) + 1));
    assert_rejected_by_both(oversized);
}

#[test]
fn network_route_and_xfrm_stage_namespaces_cannot_claim_other_layers() {
    for (stage, layer) in [
        ("network.receive_validation", "route"),
        ("route.lookup", "xfrm"),
        ("xfrm.policy", "network"),
    ] {
        let mut value = fixture();
        let coverage = stage_coverage_for_provider_mut(&mut value, "linux.link.counters");
        coverage["stage"] = json!(stage);
        coverage["layer"] = json!(layer);

        assert!(schema_accepts(&value));
        assert_rust_validation_error_contains(
            &value,
            &format!("stage coverage {stage} conflicts with layer {layer}"),
        );
    }
}

#[test]
fn layer_requires_a_registered_stage_namespace() {
    let mut missing = fixture();
    missing["metrics"][0]["meta"]["descriptor"]["stage"] = Value::Null;
    assert_semantically_rejected(missing);

    let mut unknown = fixture();
    unknown["metrics"][0]["meta"]["descriptor"]["stage"] = json!("vendor.unknown");
    assert_semantically_rejected(unknown);
}

#[test]
fn finding_cannot_combine_different_measurement_identities() {
    let mut value = fixture();
    let mut second = value["metrics"][0].clone();
    second["meta"]["id"] = json!("e_00000000000000000000000000000000_99");
    second["metricType"] = json!("linux.link.rx_errors");
    value["metrics"].as_array_mut().unwrap().push(second);
    value["findings"][0]["evidence"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "kind": "metric",
            "id": "e_00000000000000000000000000000000_99"
        }));

    assert_semantically_rejected(value);
}

#[test]
fn unknown_counter_has_no_zero_value_payload() {
    let mut value = fixture();
    value["telemetry"]["providers"][0]["counters"]["parseErrors"] = json!({
        "status": "unknown",
        "value": 0
    });

    assert_rejected_by_both(value);
}

#[test]
fn telemetry_totals_must_match_provider_rows() {
    let mut value = fixture();
    let total = value["telemetry"]["totals"]["parseErrors"]["value"]
        .as_u64()
        .unwrap();
    value["telemetry"]["totals"]["parseErrors"]["value"] = json!(total + 1);

    assert_semantically_rejected(value);
}

#[test]
fn evidence_and_error_providers_require_telemetry_rows() {
    let mut missing_evidence_provider = fixture();
    missing_evidence_provider["telemetry"]["providers"]
        .as_array_mut()
        .unwrap()
        .retain(|provider| provider["provider"] != "linux.tracepoint.kfree_skb");
    set_all_totals_to_exact_zero(&mut missing_evidence_provider);
    set_observation_bound(&mut missing_evidence_provider, "exact");
    assert_semantically_rejected(missing_evidence_provider);

    let mut missing_error_provider = fixture();
    missing_error_provider["telemetry"]["collectionErrors"] = json!([{
        "provider": "nwdiag.core",
        "message": "core accounting unavailable"
    }]);
    assert_semantically_rejected(missing_error_provider);
}

#[test]
fn evidence_provider_cannot_mark_every_boundary_not_applicable() {
    let mut value = fixture();
    let provider = value["telemetry"]["providers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|provider| provider["provider"] == "linux.tracepoint.kfree_skb")
        .unwrap();
    for status in provider["counters"].as_object_mut().unwrap().values_mut() {
        *status = json!({"status": "not_applicable"});
    }
    set_all_totals_to_exact_zero(&mut value);
    set_observation_bound(&mut value, "exact");

    assert_semantically_rejected(value);
}

#[test]
fn unknown_applicable_counter_prevents_exact_evidence() {
    let mut value = fixture();
    let provider = value["telemetry"]["providers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|provider| provider["provider"] == "linux.tracepoint.kfree_skb")
        .unwrap();
    for status in provider["counters"].as_object_mut().unwrap().values_mut() {
        *status = json!({"status": "measured", "value": 0});
    }
    provider["counters"]["netlinkLossEvents"] = json!({"status": "not_applicable"});
    provider["counters"]["netlinkDumpInterruptions"] = json!({"status": "not_applicable"});
    provider["counters"]["bpfEventsSeen"] = json!({"status": "unknown"});
    set_all_totals_to_exact_zero(&mut value);
    value["telemetry"]["totals"]["bpfEventsSeen"]["bound"] = json!("lower_bound");
    set_observation_bound(&mut value, "exact");

    assert_semantically_rejected(value);
}

#[test]
fn unregistered_pointer_attributes_are_rejected() {
    let mut value = fixture();
    value["observations"][0]["attributes"]["linux.kernel.pointer"] = json!({
        "type": "string",
        "value": "0xffff888012345678"
    });

    assert_rejected_by_both(value);
}

#[test]
fn provider_scopes_are_unique_and_match_telemetry() {
    let mut duplicate = fixture();
    let scope = duplicate["scope"]["providers"][0].clone();
    duplicate["scope"]["providers"]
        .as_array_mut()
        .unwrap()
        .push(scope);
    assert_semantically_rejected(duplicate);

    let mut missing = fixture();
    missing["scope"]["providers"].as_array_mut().unwrap().pop();
    assert_semantically_rejected(missing);

    let mut unavailable_with_evidence = fixture();
    let provider = unavailable_with_evidence["scope"]["providers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|provider| provider["provider"] == "linux.link.counters")
        .unwrap();
    provider["effective"] = Value::Null;
    assert_semantically_rejected(unavailable_with_evidence);
}

#[test]
fn evidence_provider_missing_from_scope_and_telemetry_is_a_semantic_error() {
    let mut value = fixture();
    value["scope"]["providers"]
        .as_array_mut()
        .unwrap()
        .retain(|provider| provider["provider"] != "linux.link.counters");
    value["telemetry"]["providers"]
        .as_array_mut()
        .unwrap()
        .retain(|provider| provider["provider"] != "linux.link.counters");

    assert_semantically_rejected(value);
}

#[test]
fn unresolved_interface_anchor_is_a_semantic_error() {
    let mut value = fixture();
    let unresolved = serde_json::json!({
        "anchor": {"kind": "name", "name": "eth0"},
        "resolvedAnchorIfindex": null,
        "visibleIfindices": [],
        "topologyGaps": ["anchor_unresolved"]
    });
    value["scope"]["requested"]["interfacePath"] = unresolved.clone();
    for provider in value["scope"]["providers"].as_array_mut().unwrap() {
        provider["requested"]["interfacePath"] = unresolved.clone();
        if provider["effective"].is_object() {
            provider["effective"]["interfaceScope"] = serde_json::json!({
                "extent": "all_visible"
            });
            provider["filterSupport"]["interfacePath"] = serde_json::json!("broader_only");
        }
    }

    assert_semantically_rejected(value);
}

#[test]
fn every_provider_scope_repeats_the_report_request() {
    let mut value = fixture();
    value["scope"]["providers"][0]["requested"]["direction"] = json!("ingress");
    value["scope"]["providers"][0]["effective"]["direction"] = json!("ingress");

    assert_semantically_rejected(value);
}

#[test]
fn broader_provider_scope_cannot_copy_the_requested_interface_anchor() {
    let mut value = fixture();
    let requested_path = value["scope"]["requested"]["interfacePath"].clone();
    let provider = value["scope"]["providers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|provider| provider["provider"] == "linux.tracepoint.kfree_skb")
        .unwrap();
    provider["effective"]["networkNamespace"] = json!({
        "extent": "current",
        "identity": "net:[4026531840]"
    });
    provider["effective"]["interfaceScope"] = json!({
        "extent": "path",
        "path": requested_path
    });

    assert_semantically_rejected(value);
}
