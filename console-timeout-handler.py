import json
import boto3
import os
from datetime import datetime, timedelta


timeout = 5
BAN_POLICY_ARN = 'arn:aws-cn:iam::<account-id>:policy/deny-all'
WHITELIST = os.environ["WHITELIST"]

# a function named get_iam_console_users to get a list of AWS IAM users who have a login profile
def get_iam_console_users():
    iam_console_users = []
    iam_client = boto3.client('iam')
    for user in iam_client.list_users()['Users']:
        try:
            iam_client.get_login_profile(UserName=user['UserName'])
            iam_console_users.append(user['UserName'])
        except:
            pass
    return iam_console_users


def deny_all(username):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName = username,
        PolicyArn = BAN_POLICY_ARN
    )

def lambda_handler(event, context):
    client = boto3.client('cloudtrail')
    now_time = datetime.now()
    for user in get_iam_console_users():
        if user in WHITELIST:
            print('Ignore ban because {} is in whitelist'.format(user))
            continue
            
        # get events for user within the last 5 minutes
        # if no events, deny all access to user's console access 
        # otherwise, allow access to user's console access
        response = client.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'Username',
                    'AttributeValue': user
                },
            ],
            StartTime = now_time - timedelta(minutes=timeout),
            EndTime = now_time
        )
        if not response['Events']:
            print('No events found for user: ' + user)
            deny_all(user)
            
    return {
        'statusCode': 200,
        'body': json.dumps('Done')
    }

