import json
import boto3
import os
import datetime


DEFAULT_SEVERITY = "HIGH"
DEFAULT_TYPES = ["TTPs/Defense Evasion"]
DEFAULT_TITLE = "DNS Firewall generated an alert"
DEFAULT_PRODUCT_NAME = "DNS Firewall"
DEFAULT_COMPANY_NAME = "Personal"
DEFAULT_DESC = DEFAULT_TITLE
PRODUCT_FIELDS_KEYS = [
    "transport",
    "query-name",
    "query-type",
    "query-class",
    "firewall-rule-action",
    "firewall-rule-group-id",
    "firewall-domain-list-id",
    "src-addr",
    "src-port",
    "vpc-id",
]

# Initialize AWS clients
securityhub = boto3.client("securityhub")
sts = boto3.client("sts")

AWS_REGION = os.environ["AWS_REGION"]
iam_identity = sts.get_caller_identity()
ACCOUNT_ID = iam_identity["Account"]
AWS_PARTITION = iam_identity["Arn"].split(":")[1]
PRODUCT_ARN = (
    "arn:"
    + AWS_PARTITION
    + ":securityhub:"
    + AWS_REGION
    + ":"
    + ACCOUNT_ID
    + ":product/"
    + ACCOUNT_ID
    + "/default"
)


def flatten_dict(dd, separator ='.', prefix =''):
    return { prefix + separator + k if prefix else k : v
             for kk, vv in dd.items()
             for k, v in flatten_dict(vv, separator, kk).items()
             } if isinstance(dd, dict) else { prefix : dd }


# function find_by_key to find a key and its value from a nested dict with a key_name as parameter
def find_by_key(key_name, dict_to_search):
    for key, value in dict_to_search.items():
        if key == key_name:
            return value
        elif isinstance(value, dict):
            result = find_by_key(key_name, value)
            if result is not None:
                return result


def get_resource_id(dict_to_search):
    if isinstance(dict_to_search, dict):
        resouce_id = find_by_key("id", dict_to_search)
        if resouce_id is not None and isinstance(resouce_id, str):
            return resouce_id
    return "dummy-resource-id-" + str(id(dict_to_search))


def lambda_handler(event, context):
    findings = []
    for record in event["Records"]:
        msg = json.loads(record["body"])
        detail = msg["detail"]
        findings.append(
            {
                # required top-level attributes
                "SchemaVersion": "2018-10-08",
                "AwsAccountId": msg["account"],
                "CreatedAt": msg["time"],
                "UpdatedAt": msg["time"],
                "Severity": {"Label": DEFAULT_SEVERITY},
                "Title": DEFAULT_TITLE,
                "Description": DEFAULT_DESC,
                "Types": DEFAULT_TYPES,
                "ProductArn": PRODUCT_ARN,
                "GeneratorId": msg["source"],
                "Id": detail['id'] if 'id' in detail.keys() else msg["id"],
                "Resources": [
                    {
                        "Type": "Other", 
                        "Id": get_resource_id(x), 
                        "Details": {"Other": flatten_dict(x)}
                    } for x in detail["resources"]
                ],
                # optional top-level attributes
                "CompanyName": DEFAULT_COMPANY_NAME,
                "ProductName": DEFAULT_PRODUCT_NAME,
                "LastObservedAt": datetime.datetime.fromtimestamp(
                    int(detail["last-observed-at"])
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "Region": msg["region"],
                "Action": {
                    "ActionType": "DNS_REQUEST",
                    "DnsRequestAction": {
                        "Blocked": (
                            False if detail["firewall-rule-action"] == "ALERT" else True
                        ),
                        "Domain": detail["query-name"],
                        "Protocol": detail["transport"],
                    },
                },
                "ProductFields": {
                    k: detail[k] for k in PRODUCT_FIELDS_KEYS if k in detail.keys()
                },
            }
        )
    response = securityhub.batch_import_findings(Findings=findings)
    print(response)
    if response["FailedCount"] != 0:
        raise Exception(json.dumps(response))
