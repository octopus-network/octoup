# aws ec2 describe-regions
AWS_EC2_REGIONS = {
    'ap': ['ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2'],
    'eu': ['eu-north-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1'],
    'us': ['ca-central-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',]
}

# aws ec2 describe-availability-zones --region us-east-1
AWS_EC2_ZONES = {
    'ap-south-1': ['ap-south-1a', 'ap-south-1b', 'ap-south-1c'], 
    'ap-northeast-1': ['ap-northeast-1a', 'ap-northeast-1c', 'ap-northeast-1d'], 
    'ap-northeast-2': ['ap-northeast-2a', 'ap-northeast-2b', 'ap-northeast-2c', 'ap-northeast-2d'], 
    'ap-southeast-1': ['ap-southeast-1a', 'ap-southeast-1b', 'ap-southeast-1c'], 
    'ap-southeast-2': ['ap-southeast-2a', 'ap-southeast-2b', 'ap-southeast-2c'], 
    'eu-north-1': ['eu-north-1a', 'eu-north-1b', 'eu-north-1c'], 
    'eu-west-1': ['eu-west-1a', 'eu-west-1b', 'eu-west-1c'], 
    'eu-west-2': ['eu-west-2a', 'eu-west-2b', 'eu-west-2c'], 
    'eu-west-3': ['eu-west-3a', 'eu-west-3b', 'eu-west-3c'], 
    'eu-central-1': ['eu-central-1a', 'eu-central-1b', 'eu-central-1c'], 
    'ca-central-1': ['ca-central-1a', 'ca-central-1b', 'ca-central-1d'], 
    'us-east-1': ['us-east-1a', 'us-east-1b', 'us-east-1c', 'us-east-1d', 'us-east-1e', 'us-east-1f'], 
    'us-east-2': ['us-east-2a', 'us-east-2b', 'us-east-2c'], 
    'us-west-1': ['us-west-1a', 'us-west-1c'], 
    'us-west-2': ['us-west-2a', 'us-west-2b', 'us-west-2c', 'us-west-2d']
}

# gcloud compute regions list
GCP_VM_REGIONS = {
    'ap': ['asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2', 'asia-northeast3', 'asia-south1', 'asia-south2', 'asia-southeast1', 'asia-southeast2', 'australia-southeast1', 'australia-southeast2'],
    'eu': ['europe-central2', 'europe-north1', 'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6'],
    'us': ['northamerica-northeast1', 'northamerica-northeast2', 'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4']
}

# gcloud compute zones list
GCP_VM_ZONES = {
    'northamerica-northeast1': ['northamerica-northeast1-a', 'northamerica-northeast1-b', 'northamerica-northeast1-c'], 
    'northamerica-northeast2': ['northamerica-northeast2-a', 'northamerica-northeast2-b', 'northamerica-northeast2-c'], 
    'us-central1': ['us-central1-a', 'us-central1-b', 'us-central1-c', 'us-central1-f'], 
    'us-east1': ['us-east1-b', 'us-east1-c', 'us-east1-d'], 
    'us-east4': ['us-east4-a', 'us-east4-b', 'us-east4-c'], 
    'us-west1': ['us-west1-a', 'us-west1-b', 'us-west1-c'], 
    'us-west2': ['us-west2-a', 'us-west2-b', 'us-west2-c'], 
    'us-west3': ['us-west3-a', 'us-west3-b', 'us-west3-c'], 
    'us-west4': ['us-west4-a', 'us-west4-b', 'us-west4-c'],
    'europe-central2': ['europe-central2-a', 'europe-central2-b', 'europe-central2-c'], 
    'europe-north1': ['europe-north1-a', 'europe-north1-b', 'europe-north1-c'], 
    'europe-west1': ['europe-west1-b', 'europe-west1-c', 'europe-west1-d'], 
    'europe-west2': ['europe-west2-a', 'europe-west2-b', 'europe-west2-c'], 
    'europe-west3': ['europe-west3-a', 'europe-west3-b', 'europe-west3-c'], 
    'europe-west4': ['europe-west4-a', 'europe-west4-b', 'europe-west4-c'], 
    'europe-west6': ['europe-west6-a', 'europe-west6-b', 'europe-west6-c'],
    'asia-east1': ['asia-east1-a', 'asia-east1-b', 'asia-east1-c'], 
    'asia-east2': ['asia-east2-a', 'asia-east2-b', 'asia-east2-c'], 
    'asia-northeast1': ['asia-northeast1-a', 'asia-northeast1-b', 'asia-northeast1-c'], 
    'asia-northeast2': ['asia-northeast2-a', 'asia-northeast2-b', 'asia-northeast2-c'], 
    'asia-northeast3': ['asia-northeast3-a', 'asia-northeast3-b', 'asia-northeast3-c'], 
    'asia-south1': ['asia-south1-a', 'asia-south1-b', 'asia-south1-c'], 
    'asia-south2': ['asia-south2-a', 'asia-south2-b', 'asia-south2-c'], 
    'asia-southeast1': ['asia-southeast1-a', 'asia-southeast1-b', 'asia-southeast1-c'], 
    'asia-southeast2': ['asia-southeast2-a', 'asia-southeast2-b', 'asia-southeast2-c'], 
    'australia-southeast1': ['australia-southeast1-a', 'australia-southeast1-b', 'australia-southeast1-c'], 
    'australia-southeast2': ['australia-southeast2-a', 'australia-southeast2-b', 'australia-southeast2-c']
}

OCTOUP_DEFAULT_TFVARS_AWS = {
    "cloud_vendor": "aws",
    "region": "ap-northeast-1",
    "availability_zones": ["ap-northeast-1a"],
    "instance_type": "t3.small",
    "instance_count": "1",
    "volume_type": "gp2",
    "volume_size": "128",
    # base iamge
    "base_image": "gcr.io/octopus-dev-309403/substrate-octopus:v3.0.0",
    "start_cmd": "",
    # instance user
    "user": "ubuntu",
}

OCTOUP_DEFAULT_TFVARS_GCP = {
    "cloud_vendor": "gcp",
    "region": "asia-northeast1",
    "zone": "asia-northeast1-a",
    "instance_type": "e2-small",
    "instance_count": "1",
    "volume_type": "pd-standard",
    "volume_size": "128",
    # base iamge
    "base_image": "gcr.io/octopus-dev-309403/substrate-octopus:v3.0.0",
    "start_cmd": "",
    # instance user
    "user": "ubuntu",
}

STATUS_INIT            = '0'
STATUS_INIT_FAILED     = '1'
STATUS_INIT_SUCCESS    = '2'
STATUS_APPLY_PROCESS   = '10'
STATUS_APPLY_FAILED    = '11'
STATUS_APPLY_SUCCESS   = '12'
STATUS_DESTROY_PROCESS = '20'
STATUS_DESTROY_FAILED  = '21'
STATUS_DESTROY_SUCCESS = '22'

IP_ADDRESS_RE = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

INIT_SCRIPT = '''
#!/bin/bash

MSGID="{}"
USER="{}"
UUID="{}"
ACTION="{}"
S3_URI="s3://{}/terraform.workspace/$UUID"
WORKSPACE="/root/bootnodes/workspace/$UUID"
LOG_FILE="$MSGID.log"
OUT_FILE="$MSGID.out"

# awslogs
echo "
[/octoup/bootnodes/workspace]
datetime_format = %b %d %H:%M:%S
file = "$WORKSPACE/$LOG_FILE"
buffer_duration = 5000
log_stream_name = $MSGID
initial_position = start_of_file
log_group_name = /octoup/bootnodes/workspace
" >> /etc/awslogs/awslogs.conf

systemctl start awslogsd

# sync from s3
aws s3 sync $S3_URI $WORKSPACE

# output file
ec2-metadata -i > "$WORKSPACE/$OUT_FILE"
echo $MSGID >> "$WORKSPACE/$OUT_FILE"
echo $USER >> "$WORKSPACE/$OUT_FILE"
echo $UUID >> "$WORKSPACE/$OUT_FILE"
echo $ACTION >> "$WORKSPACE/$OUT_FILE"

# terraform.tfvars.json
if [ ! -f "$WORKSPACE/terraform.tfvars.json" ]; then
    echo "1" >> "$WORKSPACE/$OUT_FILE"
    aws s3 sync $WORKSPACE $S3_URI
    exit 1
fi

# ssh-key
if [ ! -f "$WORKSPACE/id_rsa" ]; then
    ssh-keygen -t rsa -P "" -f "$WORKSPACE/id_rsa"
fi

# node-key
if [ ! -f "$WORKSPACE/node-key" ]; then
    subkey generate-node-key --file "$WORKSPACE/node-key" > "$WORKSPACE/peer-id" 2>&1
fi

# terraform
cd /root/bootnodes

# terraform workspace new/select
terraform_workspace=$(terraform workspace list)
if [[ "$terraform_workspace" == *"$UUID"* ]]; then
    echo "terraform workspace select $UUID -no-color" | tee "$WORKSPACE/$LOG_FILE"
    terraform workspace select $UUID -no-color 2>&1 | tee -a "$WORKSPACE/$LOG_FILE"
else
    echo "terraform workspace new $UUID -no-color" | tee "$WORKSPACE/$LOG_FILE"
    terraform workspace new $UUID -no-color 2>&1 | tee -a "$WORKSPACE/$LOG_FILE"
fi

# terraform apply/destroy
echo "terraform $ACTION -var-file=$WORKSPACE/terraform.tfvars.json -no-color -auto-approve" | tee -a "$WORKSPACE/$LOG_FILE"
terraform $ACTION -var-file="$WORKSPACE/terraform.tfvars.json" -no-color -auto-approve 2>&1 | tee -a "$WORKSPACE/$LOG_FILE"

# terraform $? & out
terraform_action_result=${{PIPESTATUS[0]}}
echo $terraform_action_result >> "$WORKSPACE/$OUT_FILE"
if [ $terraform_action_result -eq 0 ] && [ $ACTION = "apply" ]; then
    terraform output -no-color | tee -a "$WORKSPACE/$OUT_FILE"
fi

if [ $terraform_action_result -eq 0 ] && [ $ACTION = "destroy" ]; then
    rm -f "$WORKSPACE/id_rsa"
    rm -f "$WORKSPACE/id_rsa.pub"
    rm -f "$WORKSPACE/peer-id"
    rm -f "$WORKSPACE/node-key"
    rm -f "$WORKSPACE/terraform.tfvars.json"
fi

# sync to s3 (.log .out)
aws s3 sync $WORKSPACE $S3_URI --delete

# sleep 5s wait for awslogs
sleep 5
'''
