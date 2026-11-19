# SPDX-License-Identifier: GPL-3.0-only
"""Native evidence is separate from the historical ESR compatibility contract."""
import hashlib
import json
from pathlib import Path
import re
import runpy

HERE = Path(__file__).resolve().parent
NATIVE = runpy.run_path(str(HERE / "browser-native-runtime.py"))


def require(condition):
    if not condition:
        raise ValueError("native browser core evidence missing")


def provision_summary(root):
    value = NATIVE["validate"](root)
    pins = NATIVE["checked_pins"](value["browser_revision"])
    require(value["browser_pins"] == pins and value["browser_revision"] == pins["revision"])
    driver = root / "scripts/browser_native_core.py"
    require(NATIVE["digest"](driver) == NATIVE["digest"](HERE / "browser-native-core.py"))
    result = dict(version=1, kind="local-reviewed-native-firefox", browser_revision=pins["revision"],
        original_build_receipt_sha256=value["original_build_receipt_sha256"],
        native_bundle_sha256=NATIVE["digest"](root / "native-bundle.json"),
        native_driver_sha256=NATIVE["digest"](driver),
        runtime_version="157.0.1", runtime_source_stamp=NATIVE["FIREFOX_REVISION"],
        javascript_overlay=value["javascript_overlay"], local_disposable_only=True)
    if "tab_chrome_patch_sha256" in value.get("source_build", {}):
        helper = root / "scripts/browser-native-ui.py"
        result["tab_controls_driver_sha256"] = NATIVE["digest"](helper)
        require(result["tab_controls_driver_sha256"] == NATIVE["digest"](HERE / "browser-native-ui.py"))
    if value["kind"] == "source-built-native-firefox-core-trial":
        result.update(version=2, kind="source-built-native-firefox", source_build=value["source_build"])
    return result


def validate_browser(evidence):
    browser, provision = evidence["browser"], evidence["provision"]
    pins = NATIVE["checked_pins"](provision["browser_revision"])
    require(provision["browser_revision"] == pins["revision"]
        and provision["native_driver_sha256"] == NATIVE["digest"](HERE / "browser-native-core.py")
        and provision["local_disposable_only"] is True
        and re.fullmatch(r"[0-9a-f]{64}", provision["native_bundle_sha256"]))
    source = NATIVE["source_checks"]()
    if provision["browser_revision"] == source["TAB_BROWSER"]:
        require(provision["tab_controls_driver_sha256"] == NATIVE["digest"](HERE / "browser-native-ui.py"))
        require(browser["tab_controls"] == dict(physical_tab_menu=True, native_file_picker=True,
            verified_authority_confirmations=3, cancelled_without_binding=True,
            owner_approved_tabs=2, explicit_releases=2))
        provider = browser["provider_selector"]
        require(set(provider) == {"physical_provider_changes", "native_ask_prefill",
            "public_rights_and_consent_clear", "public_license_empty", "public_submit_disabled", "sidebar_closed",
            "public_socket_contacts"}
            and type(provider["physical_provider_changes"]) is int and provider["physical_provider_changes"] == 2
            and type(provider["public_socket_contacts"]) is int and provider["public_socket_contacts"] == 0
            and all(provider[key] is True for key in provider if key not in ("public_socket_contacts", "physical_provider_changes")))
    if provision["kind"] == "source-built-native-firefox":
        record = provision["source_build"]
        source["validate_record"](record)
        require(record["browser_revision"] == provision["browser_revision"]
                and provision["version"] == 2 and provision["javascript_overlay"] is None
                and provision["original_build_receipt_sha256"] == record["receipt_sha256"])
    else:
        require(provision["browser_revision"] == source["BROWSER"]
                and provision["version"] == 1 and provision["kind"] == "local-reviewed-native-firefox"
                and provision["original_build_receipt_sha256"] == NATIVE["BASE_RECEIPT_SHA"])
        overlay = provision["javascript_overlay"]
        require(overlay["original_build_receipt_sha256"] == NATIVE["BASE_RECEIPT_SHA"]
            and overlay["original_sha256"] == NATIVE["BEFORE_CONTROLLER"]
            and overlay["runtime_sha256"] == NATIVE["AFTER_CONTROLLER"]
            and overlay["native_rebuild"] is False and overlay["compatibility_rewrite"] is False
            and overlay["original_build_modified"] is False)
    require(browser["version"] == 1 and browser["passed"] is True
        and browser["runtime_version"] == "157.0.1"
        and browser["runtime_source_stamp"] == NATIVE["FIREFOX_REVISION"]
        and all(browser[name] == provision[name] for name in ("browser_revision", "native_bundle_sha256",
            "original_build_receipt_sha256", "javascript_overlay"))
        and browser["profile_ech_grease_disabled"] is False and browser["native_ech_wire_proven"] is False
        and browser["full_browser_killswitch"] is False and browser["overlay_kernel_proof_external"] is True
        and browser["expected_bytes"] == 33554432 and browser["ordinary_tab_bodies_verified"] == 2
        and browser["cleanup"] == dict(browser_exited=True, profile_removed=True))
    run_id = evidence["origin"]["run_id"]
    require(re.fullmatch(r"[a-f0-9]{32}", run_id))
    seed = b"volparossa-browser-network:" + run_id.encode("ascii") + b"\n"
    block = (seed * (65536 // len(seed) + 1))[:65536]
    require(browser["expected_sha256"] == hashlib.sha256(block * 512).hexdigest())
    result = browser["result"]
    booleans = {"native_ech_abi", "builtin_modules", "ordinary_tabs", "independent_attachments",
                "wrong_scope_blocked", "a_detached", "b_survives_a_detach"}
    require(set(result) == booleans | {"a", "b"} and all(result[k] is True for k in booleans)
        and result["a"] == result["b"] == dict(bytes=33554432, sha256_verified=True))
    require(browser["socket_access"] == dict(path_type_verified=True, socket_parent_owner_group_match=True,
        peer_uid_matches_socket=True, unix_connect_verified=True, capability_sent=False)
        and browser["control_namespace"] == dict(scope="client-control-directory", original_socket_inode_preserved=True,
        original_parent_inode_preserved=True, read_only=True, grant_unmodified=True))
    isolation = evidence["isolation"]
    require(isolation["user_uid"] == 985 and isolation["client_namespace"] is True
        and isolation["outside_parent_namespace"] is True and isolation["all_capabilities_dropped"] is True
        and isolation["no_new_privileges"] is True and browser["namespace"] == isolation["netns"]
        and isolation["fixture_loopback_only_uid_guard"] is True)
