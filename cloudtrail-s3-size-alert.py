import json
import os
import boto3

client = boto3.client('cloudwatch')

def get_bucket_size(bucket_name):
    total_size = 0
    bucket = boto3.resource('s3').Bucket(bucket_name)
    for object in bucket.objects.all():
        total_size += object.size
    return total_size


def put_cloudwath_metric(bucket_name, size):
    metric_data = [
            {
                'MetricName': 'guardduty_log_size',
                'Dimensions': [
                    {
                        'Name': 'Bucket',
                        'Value': bucket_name
                    },
                ],
                'Value': size,
                'Unit': 'Megabytes'
            }
        ]
    client.put_metric_data(
        Namespace='Guardduty Log storage size',
        MetricData=metric_data
    )
    print(metric_data)
    
    
def lambda_handler(event, context):
    # TODO implement
    target_buckets = os.environ['TARGET_BUCKETS']
    # size_threshold = os.environ['SIZE_THRESHOLD']
    buckets = target_buckets.split(',')

    for bucket_name in buckets:
        total_size = get_bucket_size(bucket_name)
        put_cloudwath_metric(bucket_name, total_size / 1024 / 1024)

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
    

