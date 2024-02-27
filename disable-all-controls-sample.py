import boto3
import time

PROFILE_NAME = 'PLEASE_PUT_YOUR_AWS_CREDENTIAL_PROFILE_NAME_HERE'
REGION = 'cn-northwest-1' # NINGXIA, ZHY

TARGET_STANDARD_NAME = 'aws-foundational-security-best-practices'
DISABLE_REASON = 'Disable all controls and will enable them one by one later.'

if __name__ == "__main__":
    session = boto3.Session(profile_name=PROFILE_NAME)
    client = session.client('sts')
    account_id = client.get_caller_identity()['Account']
    
    found = False
    
    client = session.client('securityhub', region_name=REGION)
    res = client.get_enabled_standards()
    if res['StandardsSubscriptions']:
        print("Currently enabled standards of account '{}' in region '{}':".format(account_id, REGION))
        for i in res['StandardsSubscriptions']:
            print("    - {}".format(i['StandardsArn']))
            if TARGET_STANDARD_NAME in i['StandardsArn']:
                std_sub_arn = i['StandardsSubscriptionArn']
                found = True
    
    if found:
        delete_choice = input("Disable all controls in {} of account '{}' in region '{}'? (yes/no): ".format(TARGET_STANDARD_NAME, account_id, REGION))
        if delete_choice.lower() == 'yes':
            paginator = client.get_paginator('describe_standards_controls')
            page_iterator = paginator.paginate(StandardsSubscriptionArn=std_sub_arn)
            controls = []
            for page in page_iterator:
                controls += page['Controls']

            print('In total {} controls found in standard {}'.format(len(controls), TARGET_STANDARD_NAME))
            for i in controls:
                std_ctrl_arn = i['StandardsControlArn']
                ctrl_status = i['ControlStatus']
                ctrl_id = i['ControlId']
                ctrl_title = i['Title']
                if ctrl_status == 'ENABLED':
                    print('Disabling {}:{}    '.format(ctrl_id, ctrl_title), end="")
                    client.update_standards_control(
                        StandardsControlArn=std_ctrl_arn,
                        ControlStatus='DISABLED',
                        DisabledReason=DISABLE_REASON
                    )
                    time.sleep(0.8)
                    print("DONE!")
                else:
                    print('{}:{} is already in disabled status, skipped...'.format(ctrl_id, ctrl_title))
        else:
            print("Skipping disable controls.")
    else:
        print('{} is not currently enabled, skipping...'.format(TARGET_STANDARD_NAME))
            
    
