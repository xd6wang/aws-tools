import json
import boto3
import os
from datetime import datetime, timezone


client = boto3.client('ssm')
PREFIX = '/console-login-failure/users/'
THRESHOLD = int(os.environ["THRESHOLD"])
WHITELIST = os.environ["WHITELIST"]
BAN_POLICY_ARN = 'arn:aws-cn:iam::<account-id>:policy/deny-all'
SNS_TOPIC = 'arn:aws-cn:sns:cn-north-1:<account-id>:guardduty-demo-email-alert'


def send_mail_alert(title, content):
    client = boto3.client('sns')
    response = client.publish(
        TopicArn=SNS_TOPIC,
        Message=content,
        Subject=title
    )
    

def success_handler(username):
    param_name = PREFIX + username
    client.put_parameter(
        Name = param_name,
        Value = '0',
        Type = 'String',
        Overwrite = True
    )
    # after login, the deny policy should be removed
    iam = boto3.client('iam')
    try:
        iam.detach_user_policy(
            UserName = username,
            PolicyArn = BAN_POLICY_ARN
        )
    except iam.exceptions.NoSuchEntityException:
        pass


def deny_all(username):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName = username,
        PolicyArn = BAN_POLICY_ARN
    )


def remove_password(username):
    iam = boto3.client('iam')
    iam.delete_login_profile(UserName=username)
    
    
def failure_handler(username):
    param_name = PREFIX + username
    try:
        response = client.get_parameter(
            Name = param_name
        )
        count_str = response['Parameter']['Value']
        count = int(count_str) + 1
        if count >= THRESHOLD:
            remove_password(username)
            send_mail_alert(
                'Too many login failure, user {} was locked.'.format(username),
                'IAM User {} was just locked due to too many failure login attempts.'.format(username)    
            )
    except client.exceptions.ParameterNotFound:
        count = 1
    client.put_parameter(
        Name = param_name,
        Value = str(count),
        Type = 'String',
        Overwrite = True
    )
    

def lambda_handler(event, context):
    if event["detail"]["userIdentity"]["type"] != "IAMUser":
        return {
            'statusCode': 200,
            'body': json.dumps('Ignore event from non-IAMUser.')
        }
        
    event_time = event["detail"]["eventTime"]
    user_name = event["detail"]["userIdentity"]["userName"]
    result = event["detail"]["responseElements"]["ConsoleLogin"]
    # put_cloudwath_metric(user_name, event_time, result)

    # check if need to ban
    if user_name == 'HIDDEN_DUE_TO_SECURITY_REASONS':
        print('Ignore ban if username is HIDDEN_DUE_TO_SECURITY_REASONS')
        return {
            'statusCode': 200,
            'body': json.dumps('Ignore ban if username is HIDDEN_DUE_TO_SECURITY_REASONS')
        }
    if user_name in WHITELIST.split(','):
        print('Ignore ban because {} is in whitelist'.format(user_name))
        return {
            'statusCode': 200,
            'body': json.dumps('Ignore ban because {} is in whitelist'.format(user_name))
        }
        
    if result == 'Failure':
        failure_handler(user_name)
    else:
        success_handler(user_name)
    
    return {
        'statusCode': 200,
        'body': json.dumps('OK!')
    }

