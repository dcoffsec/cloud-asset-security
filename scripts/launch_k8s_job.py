#!/usr/bin/env python3
"""
Launch a Kubernetes scan job for an asset.

Usage:
  python scripts/launch_k8s_job.py --asset-id abc-123
  python scripts/launch_k8s_job.py --hostname api.example.com
"""
import argparse
import os
import subprocess
import sys
import tempfile
import uuid


JOB_TEMPLATE = """
apiVersion: batch/v1
kind: Job
metadata:
  name: security-scan-{asset_id_short}
  namespace: security-scanning
  labels:
    app: cloud-asset-security-review
    asset-id: "{asset_id}"
spec:
  ttlSecondsAfterFinished: 600
  backoffLimit: 1
  template:
    metadata:
      labels:
        app: cloud-asset-security-review
    spec:
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      automountServiceAccountToken: false
      containers:
        - name: scanner
          image: {image_uri}
          command: ["python", "-m", "src.main", "worker", "--once"]
          env:
            - name: ASSET_ID
              value: "{asset_id}"
            - name: DB_PATH
              value: "/tmp/asset_registry.db"
            - name: REPORTS_OUTPUT_DIR
              value: "/tmp/reports"
            - name: ANTHROPIC_API_KEY
              valueFrom:
                secretKeyRef:
                  name: scanner-secrets
                  key: anthropic-api-key
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: "100Mi"
"""


def main():
    parser = argparse.ArgumentParser(description="Launch a Kubernetes scan job")
    parser.add_argument("--asset-id", help="Asset ID from registry")
    parser.add_argument("--hostname", help="Hostname to scan (registers new asset)")
    parser.add_argument("--image",
                        default=os.getenv("SCANNER_IMAGE", "cloud-asset-scanner:latest"),
                        help="Scanner Docker image URI")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print manifest without applying")
    args = parser.parse_args()

    if not args.asset_id and not args.hostname:
        print("Error: --asset-id or --hostname required", file=sys.stderr)
        sys.exit(1)

    asset_id = args.asset_id or str(uuid.uuid4())

    if args.hostname and not args.asset_id:
        # Register asset first
        print(f"Registering asset: {args.hostname}")
        result = subprocess.run(
            ["python", "-m", "src.main", "scan",
             "--target", args.hostname, "--json"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"Registration failed: {result.stderr}", file=sys.stderr)
            sys.exit(1)

    manifest = JOB_TEMPLATE.format(
        asset_id=asset_id,
        asset_id_short=asset_id[:8],
        image_uri=args.image,
    )

    if args.dry_run:
        print(manifest)
        return

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(manifest)
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["kubectl", "apply", "-f", tmp_path],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"Job created: security-scan-{asset_id[:8]}")
            print(f"Watch with: kubectl logs -n security-scanning "
                  f"-l asset-id={asset_id} -f")
        else:
            print(f"kubectl error: {result.stderr}", file=sys.stderr)
            sys.exit(1)
    finally:
        os.unlink(tmp_path)


if __name__ == "__main__":
    main()
