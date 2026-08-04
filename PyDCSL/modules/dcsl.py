"""PyDCSL CDM/device info check (Python port of kk/dcsl.go).

Local reimplementation of the kk/test_dcsl.py flow — builds a Widevine
LicenseRequest protobuf, signs it with RSA-PSS / SHA-1, double JSON-envelopes
it and POSTs it straight to the Widevine license server, then decodes the
device and the license response with the merged schema in widevine_info.proto
(compiled to widevine_info_pb2.py).

Usage:
    from PyDCSL.modules.dcsl import dcsl
    dcsl(wvd_file="device.wvd")
    dcsl(client_id="cid.bin", private_key="key.pem", output="report.json")
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import re
import sys
from pathlib import Path

try:
    from curl_cffi import requests as http
    _HTTP_BACKEND = "curl_cffi"
except ImportError:
    try:
        import requests as http
        _HTTP_BACKEND = "requests"
    except ImportError:
        http = None
        _HTTP_BACKEND = None

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA1

try:
    from .widevine_info_pb2 import (
        ClientIdentification,
        SignedDrmCertificate,
        DrmCertificate,
        License,
        SignedMessage,
        RootOfTrustId,
    )
except ImportError:
    _KK = Path(__file__).resolve().parent.parent.parent / "kk"
    sys.path.insert(0, str(_KK))
    from widevine_info_pb2 import (
        ClientIdentification,
        SignedDrmCertificate,
        DrmCertificate,
        License,
        SignedMessage,
        RootOfTrustId,
    )

from .logging import NOTICE, get_report_logger

LOG = get_report_logger("PyDCSL.dcsl")

LICENSE_URL = "https://license.uat.widevine.com/cenc/getlicense"
CONTENT_ID = "fkj3ljaSdfalkr3j"
REQUEST_TIMEOUT = 40
IMPERSONATE = "chrome"


# --------------------------------------------------------------------------- #
# protobuf wire-format helpers                                                #
# --------------------------------------------------------------------------- #
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _field_bytes(field: int, data: bytes) -> bytes:
    return _varint((field << 3) | 2) + _varint(len(data)) + data


def _field_varint(field: int, n: int) -> bytes:
    return _varint((field << 3) | 0) + _varint(n)


def _field_msg(field: int, inner: bytes) -> bytes:
    return _field_bytes(field, inner)


# --------------------------------------------------------------------------- #
# request construction (mirrors diana/widevine request.go + pssh.go)          #
# --------------------------------------------------------------------------- #
def build_license_request(client_id: bytes, content_id: bytes) -> bytes:
    pssh = _field_bytes(4, content_id)
    widevine_pssh_data = _field_msg(1, _field_bytes(1, pssh))
    content_id_field = _field_msg(2, widevine_pssh_data)
    return _field_bytes(1, client_id) + content_id_field + _field_varint(3, 1)


def sign_message(request_data: bytes, pem: bytes) -> bytes:
    """RSA-PSS / SHA-1, salt length == hash length (crypto.go: signMessage)."""
    key = RSA.import_key(pem)
    return pss.new(key, salt_bytes=SHA1.digest_size).sign(SHA1.new(request_data))


def build_signed_message(request_data: bytes, pem: bytes) -> bytes:
    """SignedMessage { type = 1 (LICENSE_REQUEST), msg = 2, signature = 3 }."""
    sig = sign_message(request_data, pem)
    return (_field_varint(1, 1) + _field_bytes(2, request_data)
            + _field_bytes(3, sig))


def build_body(signed_message: bytes) -> bytes:
    """Double JSON envelope from dcsl.go:94-106."""
    payload = json.dumps(
        {"payload": base64.b64encode(signed_message).decode()},
        separators=(",", ":"),
    ).encode()
    return json.dumps(
        {"request": base64.b64encode(payload).decode(),
         "signer": "widevine_test"},
        separators=(",", ":"),
    ).encode()


# --------------------------------------------------------------------------- #
# device loading                                                              #
# --------------------------------------------------------------------------- #
def load_device(wvd, client_id=None, private_key=None):
    if client_id and private_key:
        ci_name = Path(client_id).name
        pk_name = Path(private_key).name
        client_id = Path(client_id).read_bytes()
        pem = Path(private_key).read_bytes()
        src = f"raw {pk_name} + {ci_name}"
    else:
        from pywidevine.device import Device
        device = Device.load(wvd)
        client_id = device.client_id.SerializeToString()
        pem = device.private_key.export_key()
        src = f"{Path(wvd).name} (L{device.security_level})"
    return client_id, pem, src


def report_path(ci: ClientIdentification, wvd, client_id, private_key) -> Path:
    model = next((nv.value for nv in ci.client_info if nv.name == "model_name"),
                 None)
    if model:
        name = re.sub(r"[^A-Za-z0-9_-]", "_", model.strip())
        name = re.sub(r"_+", "_", name).strip("_")
        if name:
            return Path(f"{name}.json")
    if client_id and private_key:
        return Path(client_id).with_suffix(".json")
    return Path(wvd).with_suffix(".json")


# --------------------------------------------------------------------------- #
# advanced CDM/device info parser (merged schema in widevine_info.proto)      #
# --------------------------------------------------------------------------- #
def _ts(secs: int):
    if not secs:
        return None
    return _dt.datetime.fromtimestamp(secs, _dt.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC")


def _key_info(pub: bytes) -> dict:
    try:
        return {"bits": RSA.import_key(pub).size_in_bits(), "bytes": len(pub)}
    except Exception:
        return {"bits": None, "bytes": len(pub)}


def _enum(name_fn, value):
    """Enum -> readable name, falling back to the numeric value for unknowns."""
    name = name_fn(value)
    if name and "_UNKNOWN" not in name:
        return name
    return value


def _is_empty(v) -> bool:
    if v is None or v is False or v == 0 or v == "" or v == [] or v == {}:
        return True
    if isinstance(v, str) and ("_UNKNOWN" in v or "_UNSPECIFIED" in v):
        return True
    return False


def _drop_empty(d: dict) -> dict:
    return {k: v for k, v in d.items() if not _is_empty(v)}


def parse_drm_certificate(sdc: SignedDrmCertificate) -> DrmCertificate:
    dc = DrmCertificate()
    dc.ParseFromString(sdc.drm_certificate)
    return dc


def cert_chain(sdc: SignedDrmCertificate):
    """Return the list of certs from device cert up through its signers."""
    chain = []
    cur = sdc
    while cur is not None and len(cur.drm_certificate):
        chain.append(parse_drm_certificate(cur))
        cur = cur.signer if cur.HasField("signer") else None
    return chain


def parse_client_identification(ci: ClientIdentification) -> dict:
    TT = ClientIdentification.TokenType
    cc = ci.client_capabilities
    caps = None
    if cc is not None:
        caps = _drop_empty({
            "client_token": bool(cc.client_token),
            "session_token": bool(cc.session_token),
            "video_resolution_constraints": bool(cc.video_resolution_constraints),
            "max_hdcp_version": _enum(
                ClientIdentification.ClientCapabilities.HdcpVersion.Name,
                cc.max_hdcp_version),
            "oem_crypto_api_version": cc.oem_crypto_api_version
            if cc.HasField("oem_crypto_api_version") else None,
            "anti_rollback_usage_table": bool(cc.anti_rollback_usage_table),
            "srm_version": cc.srm_version if cc.HasField("srm_version") else None,
            "can_update_srm": bool(cc.can_update_srm),
            "supported_certificate_key_type": [
                ClientIdentification.ClientCapabilities.CertificateKeyType.Name(t)
                for t in cc.supported_certificate_key_type],
            "analog_output_capabilities": _enum(
                ClientIdentification.ClientCapabilities.AnalogOutputCapabilities.Name,
                cc.analog_output_capabilities),
            "can_disable_analog_output": bool(cc.can_disable_analog_output),
            "resource_rating_tier": cc.resource_rating_tier
            if cc.HasField("resource_rating_tier") else None,
        })
    out = {
        "token_type": _enum(TT.Name, ci.type),
        "device_info": {nv.name: nv.value for nv in ci.client_info},
    }
    if caps:
        out["capabilities"] = caps
    return out


def parse_drm_certificate_info(sdc: SignedDrmCertificate) -> dict:
    chain = cert_chain(sdc)
    dc = chain[0]
    out = {
        "type": _enum(DrmCertificate.Type.Name, dc.type),
        "serial_number": dc.serial_number.hex(),
        "creation_time": _ts(dc.creation_time_seconds),
        "public_key_bits": _key_info(dc.public_key)["bits"],
        "algorithm": _enum(DrmCertificate.Algorithm.Name, dc.algorithm),
        "system_id": dc.system_id if dc.HasField("system_id") else None,
    }
    if dc.HasField("expiration_time_seconds"):
        exp = _ts(dc.expiration_time_seconds)
        if exp:
            out["expiration_time"] = exp
    if dc.HasField("rot_id"):
        rot = dc.rot_id
        out["root_of_trust_id"] = {
            "version": RootOfTrustId.RootOfTrustIdVersion.Name(rot.version),
            "key_id": rot.key_id,
            "encrypted_unique_id_size_bytes": len(rot.encrypted_unique_id),
        }
    if dc.HasField("encryption_key"):
        out["encryption_key"] = {
            "public_key_bits": _key_info(dc.encryption_key.public_key)["bits"],
            "algorithm": _enum(DrmCertificate.EncryptionKey.Algorithm.Name,
                               dc.encryption_key.algorithm),
        }
    if len(sdc.signature):
        out["signature_size_bytes"] = len(sdc.signature)
    if chain[1:]:
        out["signer_chain"] = [
            {
                "type": _enum(DrmCertificate.Type.Name, ca.type),
                "serial_number": ca.serial_number.hex(),
                "system_id": ca.system_id if ca.HasField("system_id") else None,
            }
            for ca in chain[1:]
        ]
    return _drop_empty(out)


def infer_security_level(ci: ClientIdentification) -> int | None:
    """Security level inferred from client_id evidence.

    In raw client_id/private_key mode there is no .wvd header to read the
    level from, so the level is derived from the client_id itself:
      - "OEMCrypto LevelN Code ..." in oem_crypto_build_information, or
      - hardware-only capability flags (anti_rollback_usage_table + HDCP)
        indicating a hardware-backed (L1) CDM.
    Returns None when no reliable evidence is present.
    """
    info = {nv.name: nv.value for nv in ci.client_info}
    text = info.get("oem_crypto_build_information") or ""
    m = re.search(r"Level\s*(\d)", text)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    cc = ci.client_capabilities
    if cc is not None and cc.anti_rollback_usage_table:
        return 1
    return None


def infer_provisioning(ci: ClientIdentification, dc: DrmCertificate,
                       security_level: int | None) -> dict:
    """Best-effort provisioning method derived from certificate evidence.

    The authoritative value lives in the on-device ProvisionedDeviceInfo
    record (system_id/soc/... + provisioning_method field 9), which is *not*
    stored in .wvd dumps, so this is inferred rather than authoritative.
    """
    TT = ClientIdentification.TokenType
    if ci.type == TT.KEYBOX:
        return {"method": "FACTORY_KEYBOX",
                "reason": "client_id.token is a KEYBOX (factory-provisioned)."}
    if ci.type == TT.OEM_DEVICE_CERTIFICATE:
        return {"method": "FACTORY_OEM_DEVICE_CERTIFICATE",
                "reason": "client_id.token is an OEM device certificate."}
    if ci.type != TT.DRM_DEVICE_CERTIFICATE:
        return {"method": "PROVISIONING_METHOD_UNSPECIFIED",
                "reason": f"unexpected token type {ci.type}."}
    if dc.type != DrmCertificate.DEVICE:
        return {"method": "PROVISIONING_METHOD_UNSPECIFIED",
                "reason": f"DrmCertificate type is {DrmCertificate.Type.Name(dc.type)}."}
    if security_level is None:
        return {
            "method": "PROVISIONING_METHOD_UNSPECIFIED",
            "reason": "security level unknown (raw client_id/private_key mode); "
                      "cannot distinguish OTA from factory provisioning.",
            "candidates": [
                "OTA_DRM_DEVICE_CERTIFICATE - OTA-provisioned device-unique DRM certificate",
                "FACTORY_DRM_GROUP_CERTIFICATE - factory model-group DRM certificate",
                "DRM_REPROVISIONING - re-provisioned internal L3 embedded certificate",
            ],
        }
    if security_level == 3:
        candidates = [
            "FACTORY_DRM_GROUP_CERTIFICATE - Level-3 model-group DRM certificate baked in at factory",
            "OTA_DRM_DEVICE_CERTIFICATE - OTA-provisioned device-unique DRM certificate (Bedrock)",
            "DRM_REPROVISIONING - re-provisioned internal L3 embedded certificate",
        ]
    else:
        candidates = [
            "OTA_DRM_DEVICE_CERTIFICATE - OTA-provisioned device-unique DRM certificate",
            "FACTORY_DRM_GROUP_CERTIFICATE - factory model-group DRM certificate",
        ]
    return {
        "method": candidates[0].split(" - ")[0],
        "reason": "client_id.token is a DRM device certificate with a "
                  "device-unique DEVICE serial number.",
        "candidates": candidates,
    }


def parse_license_response(license_b64: str):
    sm = SignedMessage()
    sm.ParseFromString(base64.b64decode(license_b64))
    out = {
        "message_type": _enum(SignedMessage.MessageType.Name, sm.type),
        "session_key_type": _enum(SignedMessage.SessionKeyType.Name,
                                  sm.session_key_type)
        if sm.HasField("session_key_type") else None,
    }
    if sm.HasField("service_version_info") and sm.service_version_info.license_sdk_version:
        out["service_version"] = sm.service_version_info.license_sdk_version
    if sm.type != SignedMessage.LICENSE:
        return _drop_empty(out)

    lic = License()
    lic.ParseFromString(sm.msg)
    if lic.HasField("license_start_time"):
        out["license_start_time"] = _ts(lic.license_start_time)
    if lic.HasField("protection_scheme") and lic.protection_scheme:
        scheme = lic.protection_scheme
        chars = bytes((scheme >> s) & 0xFF for s in (24, 16, 8, 0))
        out["protection_scheme"] = f"0x{scheme:08x} ({chars.decode('latin1')})"
    if lic.HasField("policy"):
        p = lic.policy
        pol = _drop_empty({
            "can_play": bool(p.can_play),
            "can_persist": bool(p.can_persist),
            "can_renew": bool(p.can_renew),
            "rental_duration_seconds": p.rental_duration_seconds,
            "playback_duration_seconds": p.playback_duration_seconds,
            "license_duration_seconds": p.license_duration_seconds,
            "renewal_server_url": p.renewal_server_url or None,
            "renewal_delay_seconds": p.renewal_delay_seconds,
            "renewal_retry_interval_seconds": p.renewal_retry_interval_seconds,
            "renew_with_usage": bool(p.renew_with_usage),
            "soft_enforce_playback_duration": bool(p.soft_enforce_playback_duration),
            "soft_enforce_rental_duration": bool(p.soft_enforce_rental_duration),
        })
        if pol:
            out["policy"] = pol
    return _drop_empty(out)


# --------------------------------------------------------------------------- #
# JSON report + pretty console output                                         #
# --------------------------------------------------------------------------- #
def save_json(report: dict, path: Path) -> None:
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def plain_print(report: dict) -> None:
    from colorama import Fore, Style

    PINK = "\x1b[38;2;255;20;147m"
    C_SEC = Fore.YELLOW
    C_KEY = Fore.GREEN
    C_VAL = Fore.LIGHTWHITE_EX
    C_SEP = Fore.RED
    C_RST = Style.RESET_ALL

    dev = report["device"]
    ident = report["identity"]
    cert = report["certificate"]
    prov = report["provisioning"]
    lic = report.get("license")
    v = report["verdict"]
    status = "VALID" if v["valid"] else "INVALID / REVOKED"
    status_color = Fore.GREEN if v["valid"] else Fore.RED

    def section(title: str, gap: bool = True) -> None:
        print()
        LOG.log(NOTICE, f"{C_SEC}.++=====[ {title} ]=====++.{C_RST}")
        if gap:
            print()

    def rows(items) -> None:
        for k, v in items:
            label = f"  {k:<20}"
            sep = ": "
            value = str(v) if v is not None else ""
            lines = value.split("\n") if value else [""]
            LOG.info(f"{C_KEY}{label}{C_SEP}{sep}{C_VAL}{lines[0]}{C_RST}")
            for ln in lines[1:]:
                LOG.info(" " * len(label + sep) + f"{C_VAL}{ln}{C_RST}")

    section("Device")
    dev_rows = [
        ("system id", dev["system_id"] or "-"),
        ("security level", dev["security_level"]),
        ("token type", ident["token_type"]),
    ]
    dev_rows += [(k.replace("_", " "), v)
                 for k, v in (ident.get("device_info") or {}).items()]
    rows(dev_rows)

    if ident.get("capabilities"):
        section("Client capabilities")
        rows([(k.replace("_", " "), str(v))
              for k, v in ident["capabilities"].items()])

    section("Device certificate")
    cert_rows = [
        ("certificate type", cert["type"]),
        ("DRM serial number", cert["serial_number"]),
        ("creation time", cert.get("creation_time") or "-"),
        ("expiration time", cert.get("expiration_time") or "indefinite"),
        ("public key", f"{cert['public_key_bits']}-bit RSA"),
        ("algorithm", cert["algorithm"]),
        ("system id", cert.get("system_id") or "-"),
    ]
    if cert.get("signature_size_bytes"):
        cert_rows.append(("signature", f"{cert['signature_size_bytes']} bytes"))
    if cert.get("root_of_trust_id"):
        rot = cert["root_of_trust_id"]
        cert_rows.append(("root of trust id",
                          f"version={rot['version']} key_id={rot['key_id']} "
                          f"encrypted_unique_id={rot['encrypted_unique_id_size_bytes']} bytes"))
    for i, ca in enumerate(cert.get("signer_chain") or [], 1):
        cert_rows.append((f"signer CA [{i}]",
                          f"{ca['type']} serial={ca['serial_number']} "
                          f"system_id={ca['system_id']}"))
    cert_rows.append(("method (inferred)", prov["method"]))
    rows(cert_rows)

    section("License policy" if lic else "Verdict", gap=False)
    LOG.info(f"  {C_KEY}{'status':<20}{C_SEP}: {status_color}{status}{C_RST}")
    if lic and lic.get("policy"):
        rows([(k.replace("_", " "), str(v))
              for k, v in lic["policy"].items()])


# --------------------------------------------------------------------------- #
# public entry point                                                          #
# --------------------------------------------------------------------------- #
def dcsl(wvd_file=None, client_id=None, private_key=None, output=None) -> int:
    try:
        client_id, pem, src = load_device(wvd_file, client_id, private_key)
    except Exception as e:
        LOG.error(f"could not load device: {e}")
        return 2
    rsa_key = RSA.import_key(pem)

    ci = ClientIdentification()
    ci.ParseFromString(client_id)
    sdc = SignedDrmCertificate()
    sdc.ParseFromString(ci.token)
    dc = parse_drm_certificate(sdc)

    json_path = Path(output) if output else report_path(
        ci, wvd_file, client_id, private_key)

    security_level = None
    if wvd_file:
        try:
            from pywidevine.device import Device
            security_level = Device.load(wvd_file).security_level
        except Exception as e:
            LOG.error(f"could not read security level from {wvd_file}: {e}")
            return 2
    if security_level is None:
        security_level = infer_security_level(ci)

    report = {
        "device": {
            "source": src,
            "system_id": dc.system_id if dc.HasField("system_id") else None,
            "security_level": f"L{security_level}" if security_level else "unknown",
            "client_id_bytes": len(client_id),
            "private_key_bits": rsa_key.size_in_bits(),
        },
        "identity": parse_client_identification(ci),
        "certificate": parse_drm_certificate_info(sdc),
        "provisioning": infer_provisioning(ci, dc, security_level),
    }

    request_data = build_license_request(client_id, CONTENT_ID.encode())
    signed = build_signed_message(request_data, pem)
    body = build_body(signed)

    if http is None:
        LOG.error("'curl_cffi' or 'requests' is required")
        return 4
    try:
        if _HTTP_BACKEND == "curl_cffi":
            r = http.post(LICENSE_URL, data=body, impersonate=IMPERSONATE,
                          timeout=REQUEST_TIMEOUT)
        else:
            r = http.post(LICENSE_URL, data=body, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        LOG.error(f"request failed: {e}")
        return 4

    server = {"http_status": r.status_code}

    if r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            data = {}
        if data.get("status"):
            server["status"] = data["status"]
        if data.get("status_message"):
            server["status_message"] = data["status_message"]
        if "internal_status" in data:
            server["internal_status"] = data["internal_status"]
        for field in ("make", "model", "platform", "soc", "security_level"):
            if data.get(field) not in (None, ""):
                server[field] = data[field]
        if data.get("license"):
            report["license"] = parse_license_response(data["license"])

    ok = bool(server.get("status") == "OK" and server.get("http_status") == 200)
    report["verdict"] = {
        "valid": ok,
        "message": ("VALID - device certificate accepted, license obtained"
                    if ok else
                    "REVOKED / INVALID - device rejected by license server"),
        "exit_code": 0 if ok else 1,
    }

    save_json(report, json_path)
    plain_print(report)
    return report["verdict"]["exit_code"]
