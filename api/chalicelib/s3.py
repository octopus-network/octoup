
from botocore.exceptions import ClientError

def generate_presigned_url(s3_client, client_method, method_parameters, expires_in):
    try:
        url = s3_client.generate_presigned_url(
            ClientMethod=client_method,
            Params=method_parameters,
            ExpiresIn=expires_in
        )
        print('Presigned URL:', url)
    except ClientError:
        url = None
        print('Presigned Error:', method_parameters)
    return url


def upload_file(s3_client, file_name, bucket, object_name):
    try:
        s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        print(e)
        return False
    return True


def download_file(s3_client, bucket, object_name, file_name):
    try:
        s3_client.download_file(bucket, object_name, file_name)
    except ClientError as e:
        print(e)
        return False
    return True