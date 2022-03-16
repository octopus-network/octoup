import base64
import gzip
import json
import os
import re
import time
import boto3
from boto3.session import Session
from chalice import (
    Chalice,
    CognitoUserPoolAuthorizer,
    BadRequestError,
    NotFoundError,
    WebsocketDisconnectedError
)
from jose import jwk, jwt

from chalicelib import db, auth, s3, ec2
from chalicelib.constants import *

app = Chalice(app_name='seashell')
app.websocket_api.session = Session()
app.experimental_feature_flags.update([
    'WEBSOCKETS'
])
app.debug = True

# authorizer = CognitoUserPoolAuthorizer(
#     'seashell-user-pool', provider_arns=[os.environ['USER_POOL_ARN']]
# )

_TASK_DB = None
def get_task_db():
    global _TASK_DB
    if _TASK_DB is None:
        _TASK_DB = db.SeashellTaskTable(
            boto3.resource('dynamodb').Table(os.environ['TASKS_TABLE_NAME'])
        )
    return _TASK_DB


_TASK_LOG_DB = None
def get_task_log_db():
    global _TASK_LOG_DB
    if _TASK_LOG_DB is None:
        _TASK_LOG_DB = db.SeashellTaskLogTable(
            boto3.resource('dynamodb').Table(os.environ['TASKS_LOG_TABLE_NAME'])
        )
    return _TASK_LOG_DB


_WEBSOCKET_DB = None
def get_websocket_db():
    global _WEBSOCKET_DB
    if _WEBSOCKET_DB is None:
        _WEBSOCKET_DB = db.SeashellWebsocketTable(
            boto3.resource('dynamodb').Table(os.environ['WEBSOCKET_TABLE_NAME'])
        )
    return _WEBSOCKET_DB


_TASK_SQS = None
def get_task_sqs_client():
    global _TASK_SQS
    if _TASK_SQS is None:
        _TASK_SQS = boto3.client('sqs')
    return _TASK_SQS


_S3_CLIENT = None
def get_s3_client():
    global _S3_CLIENT
    if _S3_CLIENT is None:
        _S3_CLIENT = boto3.client('s3')
    return _S3_CLIENT


_EC2_CLIENT = None
def get_ec2_client():
    global _EC2_CLIENT
    if _EC2_CLIENT is None:
        _EC2_CLIENT = boto3.client('ec2')
    return _EC2_CLIENT


# def get_authorized_username(current_request):
#     '''
#     {'claims': {'aud': 'v2eif4vnbfupcill47qajp0h3',
#             'auth_time': '1618641665',
#             'cognito:username': 'ruanyu',
#             'email': '1246335686@qq.com',
#             'email_verified': 'true',
#             'event_id': '16deec67-33a5-4315-870e-fa1ac9c2200b',
#             'exp': 'Mon Apr 19 04:56:52 UTC 2021',
#             'iat': 'Mon Apr 19 03:56:52 UTC 2021',
#             'iss': 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_7UQfcVKDY',
#             'phone_number': '+8613426255727',
#             'phone_number_verified': 'false',
#             'sub': '107168c6-0704-469d-b5a8-acf746337fbe',
#             'token_use': 'id'}}
#     '''
#     auth = current_request.context['authorizer']
#     return auth['claims']['cognito:username']




################################################################################
# temp
################################################################################
from chalice import AuthResponse
@app.authorizer()
def authorizer(auth_request):
    token = auth_request.token
    return AuthResponse(routes=['*'], principal_id=token)

def get_authorized_username(current_request):
    return current_request.context['authorizer']['principalId']

@app.lambda_function()
def websocket_authorizer(event, context):
    principalId = event['queryStringParameters'].get('token')
    # arn:aws:execute-api:ap-northeast-1:425660444042:317ea2csve/api/$connect
    tmp = event['methodArn'].split(':')
    apiGatewayArnTmp = tmp[5].split('/')
    awsAccountId = tmp[4]
    # print(apiGatewayArnTmp, awsAccountId)

    policy = auth.AuthPolicy(principalId, awsAccountId)
    policy.restApiId = apiGatewayArnTmp[0]
    policy.region = tmp[3]
    policy.stage = apiGatewayArnTmp[1]
    if principalId:
        policy.allowAllMethods()
    else:
        policy.denyAllMethods()

    authResponse = policy.build()
    app.log.info(authResponse)
    return authResponse
################################################################################
# temp
################################################################################




@app.route('/tasks', methods=['GET'], cors=True, authorizer=authorizer)
def get_tasks():
    user = get_authorized_username(app.current_request)
    items = get_task_db().list_items(user=user)
    s3_client = get_s3_client()
    for item in items:
        item['task'].pop('access_key', None)
        item['task'].pop('secret_key', None)
        # item['task']['secret_key'] = '******'
        # item['task'].pop('base_image', None)
        item['task'].pop('start_cmd', None)
        task_user = item['task'].pop('user', 'root')
        # extend --> instance
        extend = item.pop('extend', {})
        ip, key = extend.get('ip'), extend.get('key')
        if ip and key:
            params = {'Bucket': os.environ['OCTOUP_BUCKET'], 'Key': key}
            url = s3.generate_presigned_url(s3_client, 'get_object', params, 3600*24)
            item['instance'] = {
                'ip': ip,
                'user': task_user,
                'ssh_key': url
            }
    return items


@app.route('/tasks', methods=['POST'], cors=True, authorizer=authorizer)
def add_task():
    user = get_authorized_username(app.current_request)
    body = app.current_request.json_body
    # if not body.get('access_key') or not body.get('secret_key'):
    #     raise BadRequestError()

    # 20211213 cloud vendor & gcp project
    cloud = body.pop('cloud_vendor', 'AWS').upper() # default AWS
    if cloud not in ['AWS', 'GCP']:
        raise BadRequestError('Only support [AWS|GCP]')

    if cloud == 'AWS':
        task = OCTOUP_DEFAULT_TFVARS_AWS.copy()
    elif cloud == 'GCP':
        task = OCTOUP_DEFAULT_TFVARS_GCP.copy()
    task['cloud_vendor'] = cloud

    if cloud == 'GCP':
        # https://cloud.google.com/resource-manager/reference/rest/v3/projects/list
        project = body.get('project', None)
        if not project:
            raise BadRequestError('GCP project')
        task['project'] = project

    # 20211207 random choice region/zone
    import random
    _regions = AWS_EC2_REGIONS if cloud=='AWS' else GCP_VM_REGIONS
    _zones = AWS_EC2_ZONES if cloud=='AWS' else GCP_VM_ZONES
    body.pop('availability_zones', None)
    r = body.pop('region', None)
    if r not in _regions.keys():
        r = random.choice(list(_regions.keys()))
    region = random.choice(_regions[r])
    zone = random.choice(_zones[region])
    task['region'] = region
    if cloud == 'AWS':
        task['availability_zones'] = [zone]
    elif cloud == 'GCP':
        task['zone'] = zone
    # 20211207 random choice region/zone

    task['telemetry_url'] = os.environ['SUBSTRATE_TELEMETRY_URL']

    task.update(body)
    uuid = get_task_db().add_item(task=task, user=user)
    app.log.info(f'{user} - create - {uuid}')
    return {'uuid': uuid}


@app.route('/tasks/{uuid}', methods=['GET'], cors=True, authorizer=authorizer)
def get_task(uuid):
    user = get_authorized_username(app.current_request)
    item = get_task_db().get_item(uuid, user=user)
    if not item:
        raise NotFoundError("Task doesn't exist")

    item['task'].pop('access_key', None)
    item['task'].pop('secret_key', None)
    # item['task']['secret_key'] = '******'
    # item['task'].pop('base_image', None)
    item['task'].pop('start_cmd', None)
    task_user = item['task'].pop('user', 'root')
    # extend --> instance
    extend = item.pop('extend', {})
    ip, key = extend.get('ip'), extend.get('key')
    if ip and key:
        s3_client = get_s3_client()
        params = {'Bucket': os.environ['OCTOUP_BUCKET'], 'Key': key}
        url = s3.generate_presigned_url(s3_client, 'get_object', params, 3600*24)
        item['instance'] = {
            'ip': ip,
            'user': task_user,
            'ssh_key': url
        }
    return item


@app.route('/tasks/{uuid}/metrics', methods=['GET'], cors=True, authorizer=authorizer)
def get_task(uuid):
    '''
    {
        'cpu': {
            '0': {'id': 49383555.15, 'wa': 7006.39, 'hi': 0.0, 'ni': 3419.42, 'si': 6318.0, 'st': 193679.68, 'sy': 763925.34, 'us': 47050038.59, 'percentage': 0.4930233218455299}, 
            '1': {'id': 49336940.52, 'wa': 6468.56, 'hi': 0.0, 'ni': 3534.65, 'si': 44747.13, 'st': 195782.7, 'sy': 761354.65, 'us': 47042978.06, 'percentage': 0.49341795362925245}
        }, 
        'memory': {'buff': 85889024.0, 'cache': 1078288384.0, 'avail': 1501220864.0, 'free': 159641600.0, 'total': 2097152000.0, 'used': 1937510400.0. 'percentage': 0.927876953125}, 
        'filesystem': {'avail': 26138632192.0, 'total': 41442127872.0, 'percentage': 0.36927388784830395}
    }
    '''
    user = get_authorized_username(app.current_request)
    item = get_task_db().get_item(uuid, user=user)
    if not item:
        raise NotFoundError("Task doesn't exist")

    ip = item.get('extend', {}).get('ip')
    if not ip or item['state'] != STATUS_APPLY_SUCCESS:
        raise NotFoundError("Task not deployed")

    import requests
    from prometheus_client.parser import text_string_to_metric_families

    u, p = 'prometheus', 'node_exporter'
    r = requests.get(f'http://{ip}:9100/metrics', auth=(u, p), timeout=10)
    if r.status_code != 200:
        raise NotFoundError("Task not monitored")

    # parse metric
    CPU = {
        'user': 'us',
        'system': 'sy',
        'nice': 'ni',
        'idle': 'id',
        'iowait': 'wa',
        'irq': 'hi',
        'softirq': 'si',
        'steal': 'st'
    }
    MEMORY = {
        'node_memory_MemTotal_bytes': 'total',
        'node_memory_MemFree_bytes': 'free',
        'node_memory_MemAvailable_bytes': 'avail',
        'node_memory_Buffers_bytes': 'buff',
        'node_memory_Cached_bytes': 'cache'
    }
    FILESYSTEM = {
        'node_filesystem_size_bytes': 'total',
        'node_filesystem_avail_bytes': 'avail',
    }

    metrics = {'cpu': {}, 'memory': {}, 'filesystem': {}}
    for family in text_string_to_metric_families(r.text):
        for sample in family.samples:
            # cpu
            if sample[0] == 'node_cpu_seconds_total':
                cpu, mode = sample[1].get('cpu'), CPU.get(sample[1].get('mode'))
                if cpu and mode:
                    info = metrics['cpu'].get(cpu, {})
                    info[mode] = sample[2]
                    metrics['cpu'][cpu] = info
            # memory
            if sample[0] in MEMORY:
                key = MEMORY.get(sample[0])
                metrics['memory'][key] = sample[2]
            # filesysytem /
            if sample[0] in FILESYSTEM and sample[1].get('mountpoint') == '/':
                key = FILESYSTEM.get(sample[0])
                metrics['filesystem'][key] = sample[2]
    # cpu used percentage
    for _, v in metrics['cpu'].items():
        total = sum(v.values())
        idle = v.get('id') / total
        v['percentage'] = 1 - idle # used
    # memory used bytes
    memory_total = metrics['memory'].get('total')
    memory_free = metrics['memory'].get('free')
    if memory_total and memory_free:
        metrics['memory']['used'] = memory_total- memory_free
        metrics['memory']['percentage'] = metrics['memory']['used']/memory_total
    # filesysytem used percentage
    filesystem_total = metrics['filesystem'].get('total')
    filesystem_avail = metrics['filesystem'].get('avail')
    if filesystem_total and filesystem_avail:
        metrics['filesystem']['percentage'] = 1 - filesystem_avail/filesystem_total
    return metrics


@app.route('/tasks/{uuid}', methods=['DELETE'], cors=True, authorizer=authorizer)
def delete_task(uuid):
    user = get_authorized_username(app.current_request)
    item = get_task_db().get_item(uuid, user=user)
    if not item:
        raise NotFoundError("Task doesn't exist")
    if item['state'] not in (STATUS_INIT, STATUS_DESTROY_SUCCESS):
        raise BadRequestError(f"Task[state {item['state']}] doesn't support this action")
    return get_task_db().delete_item(uuid, user=user)


@app.route('/tasks/{uuid}', methods=['PUT'], cors=True, authorizer=authorizer)
def update_task(uuid):
    """
    apply:
        init 0 -> apply 10 -> 11/12
    destroy:
        11, 12 -> destroy 20 -> 21/22
    update:
        12 -> update 30 -> 31/32
        31/32 -> destroy 20 -> 21/22
    # https://docs.aws.amazon.com/zh_cn/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
    """
    user = get_authorized_username(app.current_request)
    body = app.current_request.json_body
    item = get_task_db().get_item(uuid, user=user)
    if not item:
        raise NotFoundError("Task doesn't exist")

    action = body.get('action')
    secret = body.get('secret_key') or body.get('access_token')
    if len(secret) < 8:
        raise BadRequestError("Invalid secret_key|access_token")

    # check update paramaters: base_image
    base_image = body.get('base_image')
    if action == 'update' and not base_image:
        raise BadRequestError("Invalid docker image")

    hidden = secret[:4] + '*'*max(len(secret)-8, 0) + secret[-4:]
    app.log.info(f'{user} - {action} - {uuid} - {hidden} | {base_image}')

    # patch: appchain-12-cloud-AWS-AKIA24NPM6LZW76RJSQG
    if action in ('apply', 'destroy', 'update'):
        task = item['task']
        if task['cloud_vendor'] == 'AWS':
            task['access_key'] = user.rsplit('-', 1)[1]
            task['secret_key'] = secret
        elif task['cloud_vendor'] == 'GCP':
            task['access_token'] = secret
        # 20210923 add validator name
        if not task.get('name', None):
            task['name'] = 'validator-' + item['uuid']
        # 20220312 update base image
        if action == 'update':
            task['base_image'] = base_image

    if action == 'apply':
        if item['state'] in (STATUS_INIT, STATUS_DESTROY_SUCCESS):
            item['state'] = STATUS_APPLY_PROCESS
            get_task_db().update_item(item)
            get_task_sqs_client().send_message(
                QueueUrl=os.environ['TASKS_QUEUE_URL'],
                MessageBody=json.dumps({
                    'user': user,
                    'action': action,
                    'uuid': item['uuid'],
                    'task': task
                })
            )
            return {'state': STATUS_APPLY_PROCESS}
        else:
            raise BadRequestError(f"Task[state {item['state']}] doesn't support this action")
    elif action == 'destroy':
        if item['state'] in (STATUS_APPLY_FAILED, STATUS_APPLY_SUCCESS, STATUS_DESTROY_FAILED, STATUS_UPDATE_FAILED, STATUS_UPDATE_SUCCESS):
            item['state'] = STATUS_DESTROY_PROCESS
            get_task_db().update_item(item)
            get_task_sqs_client().send_message(
                QueueUrl=os.environ['TASKS_QUEUE_URL'],
                MessageBody=json.dumps({
                    'user': user,
                    'action': action,
                    'uuid': item['uuid'],
                    'task': task
                })
            )
            return {'state': STATUS_DESTROY_PROCESS}
        else:
            raise BadRequestError(f"Task[state {item['state']}] doesn't support this action")
    elif action == 'update':
        if item['state'] in (STATUS_APPLY_SUCCESS,):
            item['state'] = STATUS_UPDATE_PROCESS
            get_task_db().update_item(item)
            get_task_sqs_client().send_message(
                QueueUrl=os.environ['TASKS_QUEUE_URL'],
                MessageBody=json.dumps({
                    'user': user,
                    'action': action,
                    'uuid': item['uuid'],
                    'task': task
                })
            )
            return {'state': STATUS_UPDATE_PROCESS}
        else:
            raise BadRequestError(f"Task[state {item['state']}] doesn't support this action")
    else:
        raise BadRequestError("Task doesn't support this action")


@app.on_dynamodb_record(stream_arn=os.environ['TASKS_TABLE_STREAM'])
def handle_task(event):
    for record in event:
        if record.event_name == 'INSERT':
            continue
        elif record.event_name == 'REMOVE':
            continue
        else: # MODIFY
            old_item, new_item = record.old_image, record.new_image
            user = old_item['user']['S']
            uuid = old_item['uuid']['S']
            old_state, new_state = old_item['state']['S'], new_item['state']['S']
            if old_state == new_state:
                continue
            
            app.log.info(f'state: {old_state} --> {new_state}')
            # extend None or {'M': {}}
            extend = new_item.get('extend', {'M': {}}).get('M')
            if extend:
                s3_client = get_s3_client()
                # patch
                # private_key = extend.get('key', {}).get('S') or extend.get('private_key', {}).get('S')
                # params = {'Bucket': 'octoup', 'Key': private_key}
                params = {'Bucket': os.environ['OCTOUP_BUCKET'], 'Key': extend['key']['S']}
                url = s3.generate_presigned_url(s3_client, 'get_object', params, 3600*24)
                extend = {
                    'ip': extend['ip']['S'],
                    'user': new_item['task']['M']['user']['S'],
                    'ssh_key': url
                }
            message = json.dumps({
                'uuid': uuid,
                'type': 'state',
                'data': {
                    'old_state': old_state,
                    'new_state': new_state,
                    'instance': extend
                }
            })
            # websocket
            wss = get_websocket_db().list_items(user)
            try:
                app.websocket_api.configure(
                    os.environ['WEBSOCKET_DOMAIN_NAME'],
                    os.environ['WEBSOCKET_STAGE']
                )
                for ws in wss:
                    app.log.info(f'[{ws}] -> {message}')
                    app.websocket_api.send(ws, message)
            except WebsocketDisconnectedError as e:
                app.log.error(str(e))


# @app.lambda_function()
# def websocket_authorizer(event, context):
#     token = event['queryStringParameters'].get('token')
#     if token:
#         unverified_claims = jwt.get_unverified_claims(token)
#         # print(json.dumps(unverified_claims))
#         principalId = unverified_claims.get('cognito:username')
#     else:
#         principalId = None

#     # arn:aws:execute-api:ap-northeast-1:425660444042:317ea2csve/api/$connect
#     tmp = event['methodArn'].split(':')
#     apiGatewayArnTmp = tmp[5].split('/')
#     awsAccountId = tmp[4]
#     # print(apiGatewayArnTmp, awsAccountId)

#     policy = auth.AuthPolicy(principalId, awsAccountId)
#     policy.restApiId = apiGatewayArnTmp[0]
#     policy.region = tmp[3]
#     policy.stage = apiGatewayArnTmp[1]
#     try:
#         claims = auth.auth_cognito_token(
#             token, 
#             os.environ['USER_POOL_ID'], 
#             os.environ['USER_POOL_CLIENT_ID']
#         )
#         if claims != False:
#             policy.allowAllMethods()
#         else:
#             policy.denyAllMethods()
#     except:
#         policy.denyAllMethods()

#     authResponse = policy.build()
#     app.log.info(authResponse)
#     return authResponse


@app.on_ws_connect()
def ws_connect(event):
    principalId = event._event_dict['requestContext']['authorizer']['principalId']
    app.log.info(f'ws_connect: {event.connection_id} -> {principalId}')
    get_websocket_db().add_item(event.connection_id, principalId)


@app.on_ws_disconnect()
def ws_disconnect(event):
    app.log.info(f'ws_disconnect: {event.connection_id}')
    get_websocket_db().delete_item(event.connection_id)


@app.on_ws_message()
def message(event):
    try:
        app.websocket_api.send(connection_id=event.connection_id, message=event.body)
    except WebsocketDisconnectedError as e:
        app.log.error(str(e))


@app.on_sqs_message(queue=os.environ['TASKS_QUEUE_NAME'], batch_size=1)
def handle_message(event):
    for record in event:
        msgid = record._event_dict['messageId']
        body = json.loads(record.body)
        user, action, uuid, task = body["user"], body["action"], body['uuid'], body['task']
        app.log.info(f'{msgid}: {user} - {action} - {uuid}')

        workspace = os.path.join('/tmp', uuid)
        if not os.path.exists(workspace):
            os.makedirs(workspace)

        # upload terraform.tfvars.json
        var_file = os.path.join(workspace, 'terraform.tfvars.json')
        # patch: terraform default action is setup, process update action
        if action == 'update':
            task['action'] = 'update'
        else:
            task.pop('action', None)
        # patch: terraform default action is setup, process update action
        with open(var_file, 'w') as f:
            task.update({'workspace': os.path.join('workspace', uuid)})
            f.write(json.dumps(task))
        s3_client = get_s3_client()
        object_name = f'terraform.workspace/{uuid}/terraform.tfvars.json'
        s3.upload_file(s3_client, var_file, os.environ['OCTOUP_BUCKET'], object_name)

        # launch ec2
        # 20211214 AWS/GCP ami
        cloud = task.get('cloud_vendor', 'AWS') # default AWS
        image_id = os.environ[f'OCTOUP_EC2_AMI_{cloud.upper()}']
        # 20211214 AWS/GCP ami
        # image_id = os.environ['OCTOUP_EC2_AMI']
        key_name = os.environ['OCTOUP_EC2_KEY']
        bucket = os.environ['OCTOUP_BUCKET']
        user_data = base64.b64encode(INIT_SCRIPT.format(msgid, user, uuid, action, bucket).encode())
        ec2_client = get_ec2_client()
        instance = ec2.create_instance(ec2_client, image_id, key_name, user_data)
        instance_id = instance['InstanceId']
        app.log.info(f'{msgid}: launch ec2 {instance_id}')
        
        # new task log
        get_task_log_db().add_item(msgid, user, uuid, action, str(time.time()))


@app.on_s3_event(os.environ['OCTOUP_BUCKET'], events=['s3:ObjectCreated:*'], 
                 prefix=os.environ['OCTOUP_PREFIX'], suffix='.out')
def handle_object(event):
    s3_client = get_s3_client()
    file_name = os.path.join('/tmp', os.path.basename(event.key))
    s3.download_file(s3_client, event.bucket, event.key, file_name)
    with open(file_name) as f:
        lines = f.readlines()
    app.log.info(f'{event.key}: {lines}')
    # instance, msg, user, uuid, action, ret, out...
    instance = lines[0]
    msgid    = lines[1].strip()
    user     = lines[2].strip()
    uuid     = lines[3].strip()
    action   = lines[4].strip()
    ret      = lines[5].strip()
    out      = ''.join(lines[6:])

    # terminate ec2
    instance_id = instance.split(':')[1].strip()
    ec2_client = get_ec2_client()
    ec2.terminate_instance(ec2_client, instance_id)
    app.log.info(f'{event.key}: terminate ec2 {instance_id}')

    # update table
    item = get_task_db().get_item(uuid, user=user)
    if not item:
        app.log.error(f'{event.key}: {user} - {uuid} not exists')
        return
    if action == 'apply':
        state = STATUS_APPLY_SUCCESS if ret == '0' else STATUS_APPLY_FAILED
        item['state'] = state
        if ret == '0':
            ips = re.findall(IP_ADDRESS_RE, out)
            extend = {'ip': ips[0], 'key': f'{os.environ["OCTOUP_PREFIX"]}{uuid}/id_rsa'} if ips else None
            if extend:
                item['extend'] = extend
    elif action == 'destroy':
        state = STATUS_DESTROY_SUCCESS if ret == '0' else STATUS_DESTROY_FAILED
        item['state'] = state
        if ret == '0':
            item['extend'] = {}
    elif action == 'update':
        state = STATUS_APPLY_SUCCESS if ret == '0' else STATUS_APPLY_FAILED
        item['state'] = state
        # item['base_image'] = ?
    get_task_db().update_item(item)

    # update task log
    get_task_log_db().update_item(msgid, str(time.time()))


@app.lambda_function()
def handle_logs(event, context):
    data = event['awslogs']['data']
    try:
        decoded = base64.b64decode(data)
        unziped = gzip.decompress(decoded)
        log = json.loads(unziped)
        logStream = log['logStream']
        logEvents = log['logEvents']

        item = get_task_log_db().get_item(logStream)
        if not item:
            app.log.error(f'{logStream} not in SeashellTaskLogTable')
            return

        wss = get_websocket_db().list_items(item['user'])
        app.websocket_api.configure(
            os.environ['WEBSOCKET_DOMAIN_NAME'],
            os.environ['WEBSOCKET_STAGE']
        )
        for le in logEvents:
            message = json.dumps({
                'uuid': item['uuid'],
                'type': 'log',
                'data': le['message']
            })
            app.log.debug(f'{message}')
            for ws in wss:
                # app.log.debug(f'[{ws}] -> {message}')
                app.websocket_api.send(ws, message)

    except Exception as e:
        app.log.error(str(e))