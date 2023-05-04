# coding=utf-8
import boto3
import os

ec2Client = boto3.client('ec2')

def identifyInstanceVpcId(instanceId):
    instanceReservations = ec2Client.describe_instances(InstanceIds=[instanceId])['Reservations']
    for instanceReservation in instanceReservations:
        instancesDescription = instanceReservation['Instances']
        for instance in instancesDescription:
            return instance['VpcId']

def modifyInstanceAttribute(instanceId,securityGroupId):
    response = ec2Client.modify_instance_attribute(
        Groups=[securityGroupId],
        InstanceId=instanceId)

def createSecurityGroup(groupName, descriptionString, vpcId):
    resource = boto3.resource('ec2')
    securityGroupId = resource.create_security_group(GroupName=groupName, Description=descriptionString, VpcId=vpcId)
    securityGroupId.revoke_egress(IpPermissions= [{'IpProtocol': '-1','IpRanges': [{'CidrIp': '0.0.0.0/0'}],'Ipv6Ranges': [],'PrefixListIds': [],'UserIdGroupPairs': []}])
    return securityGroupId.id

def lambda_handler(event, context):
    securityGroupName = os.environ['SG_NAME']
    securityGroupDescription = os.environ['SG_DESCRIPTION']
    # EC2IsolationRoleOutput = os.environ['EC2IsolationRoleOutput']
    
    # instanceId = event['resources'][0].split("/")[1]
    instanceId = event['detail']['resource']['instanceDetails']['instanceId']
    if instanceId == 'i-99999999':
        instanceId = '<demo-instance-id>'
    print(instanceId)

    # IamInstanceProfileAssociations = ec2Client.describe_iam_instance_profile_associations(Filters=[{'Name': 'instance-id','Values': [instanceId]}])['IamInstanceProfileAssociations']
    # if len(IamInstanceProfileAssociations) > 0:
    #     for associatedIamRole in IamInstanceProfileAssociations:
    #         AssociationId = associatedIamRole['AssociationId']
    #         IamInstanceProfileArn = associatedIamRole['IamInstanceProfile']['Arn']
    #         print("Current IAM Instance Profile:", IamInstanceProfileArn)
    #         ec2Client.disassociate_iam_instance_profile(AssociationId=AssociationId)
    #         print("Disassociated IAM Role from", instanceId)

    # ec2Client.associate_iam_instance_profile(IamInstanceProfile={'Arn': EC2IsolationRoleOutput},InstanceId=instanceId)

    vpcId = identifyInstanceVpcId(instanceId)
    try:
        securityGroupsInVpc = ec2Client.describe_security_groups(Filters=[{'Name': 'vpc-id','Values': [vpcId]}, {'Name': 'group-name','Values': [securityGroupName]}])['SecurityGroups']
        if securityGroupsInVpc:
            securityGroupId = securityGroupsInVpc[0]['GroupId']
        else:
            securityGroupId = createSecurityGroup(securityGroupName, securityGroupDescription, vpcId)
        print(f'Modifying Instance {instanceId} with Incident Response Isolation Security Group: {securityGroupId}')
        modifyInstanceAttribute(instanceId,securityGroupId)
    except Exception as e:
        raise e
