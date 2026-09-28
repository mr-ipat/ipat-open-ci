#!/usr/bin/env python3
"""Mr. iPat: bounded, allowlisted disposable CI Kubernetes diagnostics.

Never print event messages, container logs, images, command/env, annotations,
addresses, Helm values or Secret/ConfigMap bodies.
"""
import json
import sys

ALLOWED = {"pods", "deployments", "events"}
ALLOWED_PODS = {"ipat-control-api", "ipat-usp-controller", "ipat-smoke",
                "ipat-unapproved"}
ALLOWED_REASONS = {"Pending", "Running", "Succeeded", "Failed", "Unknown",
                   "ImagePullBackOff", "ErrImageNeverPull", "CrashLoopBackOff",
                   "CreateContainerConfigError", "CreateContainerError",
                   "FailedCreatePodSandBox", "FailedMount", "Unhealthy",
                   "BackOff", "FailedScheduling", "Pulled", "Pulling"}

def report(kind: str, doc: dict) -> None:
    if kind not in ALLOWED:
        raise ValueError("unsupported diagnostics; refuse other resources")
    for item in (doc.get("items") or [])[:24]:
        metadata = item.get("metadata") or {}
        name = metadata.get("name", "")
        if kind == "pods":
            if not any(name.startswith(prefix + "-") or name == prefix
                       for prefix in ALLOWED_PODS):
                continue
            status = item.get("status") or {}
            phase = status.get("phase", "Unknown")
            if phase not in ALLOWED_REASONS:
                phase = "Unknown"
            states = []
            for c in (status.get("containerStatuses") or [])[:3]:
                waiting = ((c.get("state") or {}).get("waiting") or {})
                reason = waiting.get("reason", "unknown")
                if reason not in ALLOWED_REASONS:
                    reason = "unknown"
                last = ((c.get("lastState") or {}).get("terminated") or {})
                exitcode = last.get("exitCode")
                if not isinstance(exitcode, int):
                    exitcode = -1
                states.append((reason, exitcode, bool(c.get("ready"))))
            print("R58_SAFE_POD", name, phase, states)
        elif kind == "deployments":
            if name not in ("ipat-control-api", "ipat-usp-controller"):
                continue
            spec = item.get("spec") or {}
            status = item.get("status") or {}
            print("R58_SAFE_DEPLOYMENT", name,
                  int(spec.get("replicas") or 0),
                  int(status.get("readyReplicas") or 0))
        elif kind == "events":
            reason = item.get("reason", "")
            # No event messages: these may contain credentials and addresses.
            if reason not in ALLOWED_REASONS:
                reason = "other"
            print("R58_SAFE_EVENT_REASON", reason)
            # Output only fixed diagnostic category names. Event messages
            # may contain paths, host data or sensitive environment values.
            message = str(item.get("message") or "").lower()
            signatures = {
                "EXEC_PERMISSION": ("permission denied", "operation not permitted"),
                "EXEC_FORMAT": ("exec format error",),
                "OCI_RUNTIME": ("runc", "failed to create containerd task"),
                "IMAGE_PULL": ("imagepull", "image pull", "image not present"),
            }
            for label, needles in signatures.items():
                if any(needle in message for needle in needles):
                    print("R58_SAFE_EVENT_CLASS", label)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(4)
    report(sys.argv[1], json.load(sys.stdin))
