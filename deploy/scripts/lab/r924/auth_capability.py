"""Offline C320 SSH auth-method readiness; never initiates login or stores secrets."""
VALID = frozenset({'password', 'publickey', 'keyboard-interactive'})


def evaluate(methods, verified_host=False, restricted_account=False,
             operator_approved=False, baseline_checked=False):
    if type(methods) is not str:
        raise ValueError('SSH methods must be a bounded text string')
    options = methods.split(',')
    if not options or len(options) > 4 or any(item not in VALID for item in options):
        raise ValueError('Unexpected server SSH auth method list')
    if len(set(options)) != len(options):
        raise ValueError('Duplicate server SSH auth methods')
    if any(type(v) is not bool for v in
           (verified_host, restricted_account, operator_approved, baseline_checked)):
        raise ValueError('Independent bool gate values required')
    matched = frozenset(options)
    return {
        'observed_methods': sorted(matched),
        'key_only_collector_compatible_with_observed_account': 'publickey' in matched,
        'manual_password_supported_by_observed_account': 'password' in matched,
        'server_host_identity_trusted_by_auth_offer': False,
        'actual_olt_authenticated': False,
        'firmware_read_performed': False,
        'physical_read_eligible': all((verified_host,restricted_account,
                                        operator_approved,baseline_checked)),
        'physical_read_dispatched': False,
        'device_adopted': False,
        'olt_commands_executed': 0,
    }
