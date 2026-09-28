"""Mr. iPat R5.8: source-level fail-closed deploy and negative smoke contracts."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / 'deploy/scripts/lab/r58/app-smoke.sh'
WRAPPER = ROOT / 'deploy/scripts/lab/k3s-ubuntu26-ephemeral-ci.sh'
HELM = ROOT / 'deploy/helm/ipat-lab'
VALIDATOR = ROOT / 'deploy/scripts/lab/r58/verify-rendered.py'

class K3sR58SourceSafety(unittest.TestCase):
    def test_no_live_install_or_external_provider_mutation(self):
        text = SCRIPT.read_text()
        for marker in ('GITHUB_ACTIONS:-', 'RUNNER_ENVIRONMENT:-', 'RUNNER_ARCH:-',
                       'IPAT_K3S_DISPOSABLE_LAB:-', 'IPAT_R58_SMOKE:-',
                       'ipat-k3s-ci.*', 'ubuntu:26.04', 'python3',
                       'helm template', 'verify-rendered.py'):
            self.assertIn(marker, text)
        for forbidden in ('ssh ipat-lab', 'ufw allow', 'nft -f',
                          'git push', 'docker push', '--type=NodePort', '--host-network',
                          'sudo kubectl', 'curl -sfL https://get.k3s.io'):
            self.assertNotIn(forbidden, text)
        self.assertIn('IPAT_R58_SMOKE:-0', WRAPPER.read_text())
        self.assertIn('R58_ACTUAL_UNAPPROVED_SAME_NAMESPACE_POD_INGRESS_DENIED=PASS', text)
        self.assertIn('test -S /run/k3s/containerd/containerd.sock', text)
        self.assertNotIn('--address "$lab_dir/data/agent', text)
        self.assertIn('R56_EPHEMERAL_ETCD_SNAPSHOT_CREATED=PASS', WRAPPER.read_text())

    def test_untrusted_mac_or_real_vps_cannot_execute_app_script(self):
        result = subprocess.run(['bash', str(SCRIPT), '/var/lib/ipat-k3s-ci.fake',
                                 '10.0.0.12'], cwd=ROOT,
                                env={'PATH': os.environ.get('PATH','/usr/bin:/bin')},
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 4)
        self.assertIn('R58_DENIED', result.stderr)

    def test_app_binaries_loopback_default_and_no_data_access(self):
        for name, port in [('control-api','3000'),('usp-controller','3100')]:
            rust=(ROOT / f'apps/{name}/src/main.rs').read_text()
            self.assertIn(f'127.0.0.1:{port}', rust)
            self.assertIn(f'0.0.0.0:{port}', rust)
            self.assertIn('IPAT_RUN_K3S_LAB', rust)
            self.assertIn('network_bind_is_loopback_unless_explicit_k3s_lab', rust)
        self.assertIn('StatusCode::UNAUTHORIZED',
                      (ROOT/'apps/control-api/src/main.rs').read_text())
        self.assertIn('StatusCode::SERVICE_UNAVAILABLE',
                      (ROOT/'apps/usp-controller/src/main.rs').read_text())

    def test_chart_is_private_unprivileged_and_uses_only_local_images(self):
        charts=list((HELM/'templates').glob('*.yaml'))
        self.assertEqual(len(charts), 4)
        for name in ('control-api','usp-controller'):
            text=(HELM/f'templates/{name}.yaml').read_text()
            for marker in ('ClusterIP','imagePullPolicy: Never',
                           'automountServiceAccountToken: false',
                           'runAsNonRoot: true', 'runAsUser: 65532',
                           'type: RuntimeDefault', 'readOnlyRootFilesystem: true',
                           'allowPrivilegeEscalation: false'):
                self.assertIn(marker, text)
            self.assertIn('drop: ["ALL"]', text)
            docker = (ROOT / f'deploy/container/{name}.Dockerfile').read_text()
            self.assertIn('COPY --chmod=0755 ', docker)
            self.assertIn('USER 65532:65532', docker)
            for hazard in ('type: NodePort', 'type: LoadBalancer',
                           'hostNetwork: true', 'privileged: true', 'hostPath:'):
                self.assertNotIn(hazard, text)
        policy=(HELM/'templates/networkpolicy.yaml').read_text()
        self.assertEqual(policy.count('egress: []'), 2)
        self.assertEqual(policy.count('ipat-role: smoke'), 2)
        self.assertIn('safe_load_all', VALIDATOR.read_text())
        self.assertIn('extra/missing K3s objects', VALIDATOR.read_text())

    def test_actual_ci_app_smoke_is_opt_in_and_pinned(self):
        ci=(ROOT/'.github/workflows/ci.yml').read_text()
        self.assertIn('IPAT_R58_SMOKE: "1"', ci)
        self.assertIn('x86_64-unknown-linux-musl', ci)
        self.assertIn('helm-v3.21.3-linux-amd64.tar.gz', ci)
        self.assertIn('test_r58_review.py', ci)
        self.assertIn('test_r58_manifest.py', ci)

    def test_helm_rollout_diagnostics_are_redacted_and_bounded(self):
        from importlib.util import module_from_spec, spec_from_file_location
        from contextlib import redirect_stdout
        from io import StringIO
        helper = ROOT / 'deploy/scripts/lab/r58/ci-safe-status.py'
        spec = spec_from_file_location('ipat_ci_safe', helper)
        assert spec and spec.loader
        mod = module_from_spec(spec)
        spec.loader.exec_module(mod)
        output = StringIO()
        fake = {'items':[{'reason':'Failed','message':'NEVER_PRINT_SECRET=example'}]}
        with redirect_stdout(output):
            mod.report('events', fake)
        self.assertIn('R58_SAFE_EVENT_REASON Failed', output.getvalue())
        self.assertNotIn('NEVER_PRINT_SECRET', output.getvalue())
        classified = StringIO()
        with redirect_stdout(classified):
            mod.report('events', {'items':[{'reason':'Failed',
                'message':'OCI runtime permission denied NEVER_PRINT_SECRET=example'}]})
        self.assertIn('R58_SAFE_EVENT_CLASS EXEC_PERMISSION', classified.getvalue())
        self.assertNotIn('NEVER_PRINT_SECRET', classified.getvalue())
        self.assertIn('R58_HELM_ROLLOUT_FAILED_WITH_SAFE_STATUS_ONLY', SCRIPT.read_text())
        self.assertIn('R58_BOTH_NORMALIZED_LOCAL_IMAGES_PRESENT=PASS', SCRIPT.read_text())

if __name__=='__main__':
    unittest.main()
