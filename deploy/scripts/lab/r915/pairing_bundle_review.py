#!/usr/bin/env python3
"""Offline nondeployable Site A hub + disabled RouterOS Site B pairing preview.
Never generates/accepts private keys, starts VPN, or pushes to router B.
"""
import base64
import ipaddress
import re
from site_a_plan import review

SITE = re.compile(r'^[a-z0-9][a-z0-9-]{0,19}$')

def public_key(value):
    if type(value) is not str or len(value) != 44:
        raise ValueError('only full WireGuard PUBLIC key is permitted')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError('invalid public key') from None
    if len(raw) != 32 or raw == bytes(32):
        raise ValueError('invalid WireGuard public key length or value')
    if base64.b64encode(raw).decode('ascii') != value:
        raise ValueError('public key encoding must be canonical')
    return value

def render(topology, site_slug, site_a_public_key, site_b_public_key, port):
    plan = review(topology)
    if plan['link_mode'] == 'direct_private':
        return {'mode':'DIRECT_PRIVATE_NO_PAIRING', 'network_actions':0,
                'router_push_enabled':False, 'config_generated':False,
                'device_adopted':False,
                'remaining_evidence':plan['missing_independent_evidence']}
    if plan['link_mode'] != 'wireguard':
        raise ValueError('IPsec package remains unsupported')
    if topology['site_b_gateway'] != 'routeros7':
        raise ValueError('Linux Site B package requires a separate reviewed adapter')
    if not SITE.fullmatch(site_slug) or site_slug.startswith('wg-'):
        raise ValueError('safe unique site suffix required')
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('reviewed unprivileged UDP port required')
    a_key = public_key(site_a_public_key)
    b_key = public_key(site_b_public_key)
    if a_key == b_key:
        raise ValueError('both sites must have independent public keys')
    name = 'wg-ipat-' + site_slug
    a_host = plan['a_tunnel_host']
    b_host = plan['b_tunnel_host']
    target = ipaddress.ip_address(topology['management_host'])
    hub = str(ipaddress.ip_address(topology['site_a_endpoint']))
    # Intentionally omit private key and active firewall/route changes.
    # RouterOS commands are DISABLED review artifacts, NEVER pushed.
    site_b_preview = [
        f'/interface/wireguard/add name={name} disabled=yes comment=IPAT-PENDING-REVIEW',
        f'/ip/address/add address={b_host}/30 interface={name} disabled=yes',
        f'/interface/wireguard/peers/add interface={name} '
        f'public-key="{a_key}" endpoint-address={hub} endpoint-port={port} '
        f'allowed-address={a_host}/32 persistent-keepalive=25 disabled=yes',
    ]
    hub_peer = [
        '# REVIEW ONLY: site A private key remains in its own vault',
        f'# Site A tunnel address {a_host}/30, reviewed UDP port {port}',
        f'# Site A peer public-key: {b_key}',
        f'# Site A peer AllowedIPs {b_host}/32, {target}/32',
        '# DO NOT enable before site B trusted identity, firewall/route',
        '# ordering, isolated local OLT hop and return path are verified.'
    ]
    return {
        'schema_version':1, 'mode':'NONEXECUTABLE_PAIRING_REVIEW',
        'site_a_role':'HUB_LOCAL_ONLY',
        'site_b_role':'OPERATOR_APPLIES_DISABLED_REVIEW_COMMANDS',
        'site_b_routeros_disabled_review_commands':site_b_preview,
        'site_a_nonexecutable_review_notes':hub_peer,
        'site_a_management_route':str(target)+'/32',
        'site_b_peer_allowed_ips':[a_host+'/32'],
        'site_a_peer_allowed_ips':[b_host+'/32',str(target)+'/32'],
        'server_endpoint_source':'USER_DECLARED_NOT_VERIFIED',
        'site_b_key_generated_and_custodied_at_site_b':True,
        'site_a_key_generated_and_custodied_at_site_a':True,
        'router_push_enabled':False,'config_applied':False,
        'network_actions':0,'device_adopted':False,
        'remaining_evidence':plan['missing_independent_evidence']
    }
