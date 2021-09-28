# octoup

### AWS
uncomment [source = "./multi-cloud/aws"](https://github.com/octopus-network/octoup/blob/main/main.tf#L35)
```
export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""

terraform init
terraform apply -var-file=terraform-aws.json
terraform destroy -var-file=terraform-aws.json
```

### GCP
uncomment [source = "./multi-cloud/gcp"](https://github.com/octopus-network/octoup/blob/main/main.tf#L36)
```
export GOOGLE_PROJECT=""
export GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)

terraform init
terraform apply -var-file=terraform-gcp.json
terraform destroy -var-file=terraform-gcp.json
```

###
```

```
<!-- export GOOGLE_CREDENTIALS="$(gcloud info --format='value(config.paths.global_config_dir)')/application_default_credentials.json" -->