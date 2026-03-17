from app.kill_chain import describe_technique, enrich_techniques, kill_chain_for, tactic_for


def test_kill_chain_for_deduplicates_and_orders():
    stages = kill_chain_for(["T1046", "T1040", "T1105", "T1046"])
    assert "reconnaissance" in stages
    assert "delivery" in stages
    assert stages.index("reconnaissance") < stages.index("delivery")


def test_kill_chain_for_unknown_returns_empty():
    assert kill_chain_for(["T9999"]) == []


def test_tactic_for_known_technique():
    assert tactic_for("T1110") == "credential-access"


def test_tactic_for_unknown_returns_none():
    assert tactic_for("T9999") is None


def test_describe_technique():
    assert describe_technique("T1110") == "Brute Force"


def test_enrich_techniques_returns_full_info():
    result = enrich_techniques(["T1110"])
    assert result[0]["tactic"] == "credential-access"
    assert "attack.mitre.org" in result[0]["url"]


def test_enrich_techniques_unknown():
    result = enrich_techniques(["T9999"])
    assert result[0]["tactic"] == "unknown"


def test_brute_force_maps_to_exploitation():
    assert kill_chain_for(["T1110"]) == ["exploitation"]


def test_lateral_movement_maps():
    lateral = kill_chain_for(["T1021.001"])
    assert "command_and_control" in lateral


def test_exfil_maps_to_objectives():
    exfil = kill_chain_for(["T1048"])
    assert "actions_on_objectives" in exfil
