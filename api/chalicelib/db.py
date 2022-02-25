from uuid import uuid4

from boto3.dynamodb.conditions import Key


DEFAULT_USERNAME = 'default'

class SeashellTaskTable(object):
    def __init__(self, table_resource):
        self._table = table_resource

    def list_all_items(self):
        response = self._table.scan()
        return response['Items']

    def list_items(self, user=DEFAULT_USERNAME):
        response = self._table.query(
            KeyConditionExpression=Key('user').eq(user)
        )
        return response['Items']

    def add_item(self, task, user=DEFAULT_USERNAME):
        uuid = str(uuid4())
        self._table.put_item(
            Item={
                'user': user,
                'uuid': uuid,
                'task': task,
                'state': '0',
            }
        )
        return uuid

    def get_item(self, uuid, user=DEFAULT_USERNAME):
        response = self._table.get_item(
            Key={
                'user': user,
                'uuid': uuid,
            },
        )
        return response.get('Item', {})

    def delete_item(self, uuid, user=DEFAULT_USERNAME):
        self._table.delete_item(
            Key={
                'user': user,
                'uuid': uuid,
            }
        )

    def update_item(self, item, user=DEFAULT_USERNAME):
        self._table.put_item(Item=item)


class SeashellTaskLogTable(object):
    def __init__(self, table_resource):
        self._table = table_resource

    def add_item(self, msgid, user, uuid, action, start):
        self._table.put_item(
            Item={
                'msgid': msgid,
                'user': user,
                'uuid': uuid,
                'action': action,
                'start': start,
            }
        )

    def get_item(self, msgid):
        response = self._table.get_item(
            Key={'msgid': msgid},
        )
        return response.get('Item', {})

    def update_item(self, msgid, stop):
        item = self.get_item(msgid)
        item['stop'] = stop
        self._table.put_item(Item=item)


class SeashellWebsocketTable(object):
    def __init__(self, table_resource):
        self._table = table_resource

    def add_item(self, conn, user):
        self._table.put_item(
            Item={
                'PK': conn,
                'SK': user,
            },
        )

    def delete_item(self, conn):
        try:
            r = self._table.query(
                KeyConditionExpression=(
                    Key('PK').eq(conn)
                ),
                Select='ALL_ATTRIBUTES',
            )
            for item in r['Items']:
                self._table.delete_item(
                    Key={
                        'PK': conn,
                        'SK': item['SK'],
                    },
                )
        except Exception as e:
            print(e)

    def list_items(self, user):
        r = self._table.query(
            IndexName='ReverseLookup',
            KeyConditionExpression=(
                Key('SK').eq(user)
            ),
            Select='ALL_ATTRIBUTES',
        )
        return [item['PK'] for item in r['Items']]

    