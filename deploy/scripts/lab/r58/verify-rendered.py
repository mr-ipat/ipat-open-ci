#!/usr/bin/env python3
"""Mr. iPat: fail-closed verification of Helm's lab-only rendered API surface."""
import sys
from pathlib import Path

try:
    import yaml
except ImportError as err:
    raise SystemExit("R58_DENIED: disposable CI must install python3-yaml") from err

EXPECTED = {
    ("ServiceAccount", "ipat-control-api"),
    ("ServiceAccount", "ipat-usp-controller"),
    ("Deployment", "ipat-control-api"),
    ("Deployment", "ipat-usp-controller"),
    ("Service", "ipat-control-api"),
    ("Service", "ipat-usp-controller"),
    ("NetworkPolicy", "ipat-control-api"),
    ("NetworkPolicy", "ipat-usp-controller"),
}

def validate(content: str) -> None:
    parsed = list(yaml.safe_load_all(content))
    actual = {(doc.get("kind"), doc.get("metadata", {}).get("name"))
              for doc in parsed if isinstance(doc, dict)}
    if len(parsed) != len(EXPECTED) or actual != EXPECTED:
        raise ValueError("extra/missing K3s objects; external exposure is forbidden")
    for obj in parsed:
        kind = obj["kind"]
        name = obj["metadata"]["name"]
        spec = obj.get("spec", {})
        if kind == "Service":
            if spec.get("type") != "ClusterIP" or "externalIPs" in spec:
                raise ValueError(f"{name}: no external Kubernetes service allowed")
            if "loadBalancerIP" in spec or "loadBalancerClass" in spec:
                raise ValueError(f"{name}: load balancer is forbidden")
        elif kind == "ServiceAccount":
            if obj.get("automountServiceAccountToken") is not False:
                raise ValueError(f"{name}: account tokens must not auto-mount")
        elif kind == "Deployment":
            pod = spec["template"]["spec"]
            if spec.get("replicas") != 1 or pod.get("automountServiceAccountToken") is not False:
                raise ValueError(f"{name}: invalid lab replica/token boundary")
            if pod.get("hostNetwork") or pod.get("hostPID") or pod.get("hostIPC"):
                raise ValueError(f"{name}: host namespaces are forbidden")
            sec = pod.get("securityContext", {})
            if not sec.get("runAsNonRoot") or sec.get("seccompProfile", {}).get("type") != "RuntimeDefault":
                raise ValueError(f"{name}: pod confinement is required")
            if pod.get("volumes"):
                raise ValueError(f"{name}: no sensitive host/persistent volumes permitted")
            containers = pod.get("containers", [])
            if len(containers) != 1:
                raise ValueError(f"{name}: unexpected additional containers")
            c = containers[0]
            cs = c.get("securityContext", {})
            if c.get("imagePullPolicy") != "Never":
                raise ValueError(f"{name}: must use only locally imported lab image")
            if cs.get("privileged") or cs.get("allowPrivilegeEscalation") is not False:
                raise ValueError(f"{name}: escalation is forbidden")
            if cs.get("readOnlyRootFilesystem") is not True or cs.get("capabilities", {}).get("drop") != ["ALL"]:
                raise ValueError(f"{name}: require readonly filesystem and zero Linux caps")
            ports = c.get("ports", [])
            if len(ports) != 1 or "hostPort" in ports[0]:
                raise ValueError(f"{name}: fixed app-only listener required")
            expected_port = 3000 if name == "ipat-control-api" else 3100
            if ports[0].get("containerPort") != expected_port:
                raise ValueError(f"{name}: service port mismatch")
            env = {e.get("name"): e.get("value") for e in c.get("env", [])}
            allowed_env = {"IPAT_RUN_K3S_LAB"} if name == "ipat-control-api" else {
                "IPAT_RUN_K3S_LAB", "IPAT_RUN_OFFLINE_USP_LAB"
            }
            if set(env) != allowed_env or set(env.values()) != {"1"}:
                raise ValueError(f"{name}: forbid arbitrary environment and secrets")
        elif kind == "NetworkPolicy":
            if spec.get("policyTypes") != ["Ingress", "Egress"] or spec.get("egress") != []:
                raise ValueError(f"{name}: policy must explicitly deny application egress")
            ingress = spec.get("ingress", [])
            if len(ingress) != 1 or ingress[0].get("from") != [{
                "podSelector": {"matchLabels": {"ipat-role": "smoke"}}
            }]:
                raise ValueError(f"{name}: ingress is only for same-namespace smoke pods")
    return None

def main() -> int:
    if len(sys.argv) != 2:
        return 4
    validate(Path(sys.argv[1]).read_text())
    print("R58_HELM_RENDER_STRICT_NO_PUBLIC_SERVICE_AND_POD_CONFINEMENT=PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
