#!/usr/bin/env python3
"""Pure protocol-based per-device direct-first connection review; NO probe.
RFC1918 text alone never proves a private/isolated network or trust.
A healthy TCP handshake never proves an API implementation.
"""
from dataclasses import dataclass
import ipaddress

PROFILES = {
    'zte_c320': ('ssh_pinned','snmpv3_authpriv'),
    'cdata_olt': ('ssh_pinned','snmpv3_authpriv','https_vendor_verified'),
    'mikrotik_routeros7': ('routeros_api_ssl','routeros_rest_https','ssh_pinned','snmpv3_authpriv'),
    'ont_tr069': ('cwmp_https','usp_authenticated'),
    'ont_usp': ('usp_authenticated','cwmp_https'),
    'generic_router': ('https_vendor_verified','ssh_pinned','snmpv3_authpriv'),
}
TLS = frozenset(('routeros_api_ssl','routeros_rest_https','https_vendor_verified','cwmp_https'))

@dataclass(frozen=True)
class Evidence:
    device_profile: str
    endpoint_ip: str
    path_observed: bool
    management_segment_isolated: bool
    exact_protocol_on_firmware_verified: bool
    exact_device_identity_independently_verified: bool
    restricted_account_verified: bool
    actual_service_baseline_approved: bool
    candidate_protocol: str
    requested_tunnel: str = 'none'


def evaluate(e):
    if not isinstance(e,Evidence) or e.device_profile not in PROFILES:
        raise ValueError('known device class required; never claim universal HTTPS API')
    try: ip=ipaddress.ip_address(e.endpoint_ip)
    except ValueError: raise ValueError('invalid management address') from None
    if ip.version!=4 or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        raise ValueError('actual routable IPv4 management endpoint required')
    if e.candidate_protocol not in PROFILES[e.device_profile]:
        raise ValueError('protocol unsupported as a candidate for this device class')
    if e.requested_tunnel not in ('none','wireguard','ipsec'):
        raise ValueError('unknown optional tunnel type')
    for field in ('path_observed','management_segment_isolated',
        'exact_protocol_on_firmware_verified','exact_device_identity_independently_verified',
        'restricted_account_verified','actual_service_baseline_approved'):
        if type(getattr(e,field)) is not bool:
            raise ValueError('only independent boolean attestation metadata; no credentials')
    # Even operator flags are UNTRUSTED; an actual worker MUST verify each
    # evidence through real signed identity & immutable reviewer records.
    missing = []
    if not e.path_observed: missing.append('ACTUAL_NETWORK_REACHABILITY_UNKNOWN')
    if not e.management_segment_isolated: missing.append('MANAGEMENT_PATH_ISOLATION_UNVERIFIED')
    if not e.exact_protocol_on_firmware_verified: missing.append('EXACT_FIRMWARE_PROTOCOL_UNVERIFIED')
    if not e.exact_device_identity_independently_verified: missing.append('OOB_DEVICE_IDENTITY_UNVERIFIED')
    if not e.restricted_account_verified: missing.append('RESTRICTED_DEVICE_ROLE_UNVERIFIED')
    if not e.actual_service_baseline_approved: missing.append('LIVE_SERVICE_BASELINE_NOT_APPROVED')
    if e.candidate_protocol in TLS:
        missing.extend(['TLS_SERVER_CERTIFICATE_PINNING_EVIDENCE','PROTOCOL_AUTHENTICATION_PROOF'])
    if e.candidate_protocol=='ssh_pinned':
        missing.extend(['PINNED_DEVICE_HOST_KEY_EVIDENCE','RESTRICTED_PUBLIC_KEY_LOGIN_PROOF'])
    if e.candidate_protocol=='snmpv3_authpriv':
        missing.append('SNMPV3_AUTH_PRIV_AND_ENGINE_ID_EVIDENCE')
    if e.requested_tunnel!='none':
        missing.extend(['OPTIONAL_TUNNEL_ACTIVATION_SEPARATE_APPROVAL','SITE_GATEWAY_RECOVERY_PROOF'])
    return {
        'device_profile':e.device_profile,
        'preferred_transport':'DIRECT_TO_DEVICE_OVER_EXISTING_NETWORK'
            if e.requested_tunnel=='none' else 'OPTIONAL_SEPARATELY_APPROVED_MANAGEMENT_TUNNEL',
        'candidate_protocol':e.candidate_protocol,
        'available_candidate_protocols':list(PROFILES[e.device_profile]),
        'wireguard_required':False,
        'vpn_requested':e.requested_tunnel!='none',
        'missing_independent_proofs':missing,
        'device_authentication_allowed':False,
        'actual_protocol_compatibility_proven':False,
        'device_adopted':False,
        'network_actions':0,
    }
