# Terraform: plan-only existing-host manifest

This is **not full Terraform provisioning**. It binds the pinned V1 and staged Shuffle Compose sources to a reviewable manifest without any provider, resource, provisioner, secrets, SSH or apply side effect. Full-stack activation is intentionally blocked on Shuffle worker isolation and persistent host firewall/lifecycle review. Compose remains the actual deployment specification.

No Terraform/OpenTofu binary was installed on the build machine; HCL formatting, validate and plan are NOT claimed. Python tests inspect safety invariants only, not HCL validity. On a reviewer machine with Terraform >=1.5,<2 already installed:

    terraform -chdir=infra/terraform fmt -check
    terraform -chdir=infra/terraform init -backend=false
    terraform -chdir=infra/terraform validate
    terraform -chdir=infra/terraform plan -input=false -lock=false

Expect zero resources and only deployment_manifest output changes. Do not apply, add paid providers, or use a local-exec provisioner to disguise uncontrolled shell deployment. Plans/state may expose file paths; keep them private. No provider download should be needed. If validation fails, fix source and rerun; do not describe Python lint as Terraform validation.

See ../../docs/BUILD-GUIDE.md for synthetic build and gated existing-host lifecycle. Stopping containers preserves data but does not stop an existing VPS subscription or storage billing.
