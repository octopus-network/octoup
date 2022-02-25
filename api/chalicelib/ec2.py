
def create_instance(ec2_client, image_id, key_name, user_data):
    instances = ec2_client.run_instances(
        ImageId=image_id,
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
        KeyName=key_name,
        UserData=user_data
    )
    instance = instances["Instances"][0]
    return instance


def terminate_instance(ec2_client, instance_id):
    response = ec2_client.terminate_instances(InstanceIds=[instance_id])
    return response
