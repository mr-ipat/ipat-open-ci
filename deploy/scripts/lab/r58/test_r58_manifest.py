"""Dynamic, real Helm-rendered lab-only manifest assertions and mutation checks."""
from copy import deepcopy
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[4]
source = ROOT / 'deploy/scripts/lab/r58/verify-rendered.py'
spec = spec_from_file_location('r58_render_guard', source)
assert spec and spec.loader
validator = module_from_spec(spec)
spec.loader.exec_module(validator)

class ActualHelmR58RenderedSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=subprocess.run(['helm','template','ipat-r58',
            str(ROOT/'deploy/helm/ipat-lab'),'-n','ipat-r58'],
            check=True,stdout=subprocess.PIPE,text=True,timeout=25).stdout
        cls.docs=list(yaml.safe_load_all(cls.raw))

    def assert_invalid(self, mutate):
        docs=deepcopy(self.docs)
        mutate(docs)
        with self.assertRaises(ValueError):
            validator.validate(yaml.safe_dump_all(docs))

    def test_actual_chart_has_only_expected_private_objects(self):
        validator.validate(self.raw)

    def test_mutated_public_load_balancer_is_rejected(self):
        self.assert_invalid(lambda d: next(x for x in d if x['kind']=='Service')['spec']
            .update(type='LoadBalancer'))

    def test_mutated_pod_host_namespace_is_rejected(self):
        self.assert_invalid(lambda d: next(x for x in d if x['kind']=='Deployment')
            ['spec']['template']['spec'].update(hostNetwork=True))

    def test_mutated_privileged_container_is_rejected(self):
        self.assert_invalid(lambda d: next(x for x in d if x['kind']=='Deployment')
            ['spec']['template']['spec']['containers'][0]['securityContext']
            .update(privileged=True))

    def test_mutated_public_network_policy_is_rejected(self):
        self.assert_invalid(lambda d: next(x for x in d if x['kind']=='NetworkPolicy')
            ['spec'].update(ingress=[{}]))

    def test_mutated_unaudited_additional_object_is_rejected(self):
        self.assert_invalid(lambda d: d.append({'apiVersion':'v1',
            'kind':'Service','metadata':{'name':'unexpected'},
            'spec':{'type':'ClusterIP'}}))

if __name__=='__main__':
    unittest.main()
