# Cloud Lab from GitHub Actions

Create temporary VMs on **AWS, Azure or GCP** straight from the GitHub UI. No server, no website, no third-party service.

**Use it:** repo -> **Actions** -> **Cloud Lab (create / destroy VMs)** -> **Run workflow**, then choose:

| Option | Choices |
|---|---|
| action | create / destroy |
| cloud | aws / azure / gcp |
| lab_name | e.g. `demo1` (2-24 chars) |
| region | default or a listed region |
| vm_count | 1-5 |
| size | small / medium / large |
| os | ubuntu-24.04 / ubuntu-22.04 |
| disk_gb | 10-200 |
| lifetime_hours | 1, 2, 4, 8, 24, 72 |
| allowed_cidr | your IP as `x.x.x.x/32` (0.0.0.0/0 is rejected) |

When the run finishes, the **run summary** shows each VM's IP and SSH command.

| size | AWS | Azure | GCP |
|---|---|---|---|
| small | t3.micro | Standard_B1s | e2-micro |
| medium | t3.small | Standard_B2s | e2-small |
| large | t3.medium | Standard_B2ms | e2-medium |

## Auto-destroy
After a create, the lab is recorded on an orphan branch `lab-registry` in this repo. The **Cloud Lab reaper** workflow runs every 15 minutes, finds expired labs and starts a `destroy` run for each. Nothing depends on your browser. GitHub cron can be delayed by several minutes, so destruction happens at expiry plus up to roughly 15-30 minutes. Check the cloud console for anything left over; a failed destroy run leaves resources running and billing.

## One-time setup (per cloud you use)
Everything is a repository **Variable** (Settings -> Secrets and variables -> Actions -> Variables). There are no long-lived cloud keys: login uses GitHub OIDC.

Common: `LAB_SSH_PUBLIC_KEY` = contents of your `.pub` file. Keep the private key yourself.
Also create GitHub Environments named `lab-aws`, `lab-azure`, `lab-gcp` (no reviewers, see note below).

**AWS**: create an S3 bucket for state and an IAM role trusting `token.actions.githubusercontent.com` for this repo (subject `repo:<owner>/<repo>:environment:lab-aws`) with EC2/VPC and state-bucket permissions. Variables: `AWS_ROLE_ARN`, `TF_STATE_BUCKET`, `TF_STATE_REGION`.

**Azure**: create a storage account + container for state and an app registration with a federated credential for `repo:<owner>/<repo>:environment:lab-azure`, role Contributor on the subscription. Variables: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `TF_STATE_RESOURCE_GROUP`, `TF_STATE_STORAGE_ACCOUNT`, `TF_STATE_CONTAINER` (default `tfstate`).

**GCP**: create a GCS bucket for state, a service account (Compute Admin + bucket access) and Workload Identity Federation for this repo. Variables: `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT`, `TF_STATE_BUCKET`, `GCP_PROJECT`.

## Safety notes
- SSH is open only to the CIDR you enter; inputs are validated before anything runs; size, count, disk and lifetime are capped.
- One Terraform state per lab (`labs/<cloud>/<name>`), and runs for the same lab are serialized.
- Do **not** add required reviewers to the `lab-*` environments if you want auto-destroy to work unattended: the reaper's destroy runs would wait for approval.
- Anyone with write access to the repo can start billable runs. Restrict access accordingly.
- Provider lock files (`.terraform.lock.hcl`) are not committed yet. Run `terraform init` once locally in each `terraform/vm/<cloud>` folder and commit them.

## Status
Written and statically checked (`tofu fmt`, YAML and shell syntax). **Not run against a real cloud account**, and `terraform validate` was not run (providers could not be downloaded in the authoring environment). Expect to fix small issues on the first real run; start with `small`, 1 VM, 1 hour.
