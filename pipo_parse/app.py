import json
import os

import requests

import fileinput
import re
import boto3


def lambda_handler(event, context):
    """Sample pure Lambda function

    Parameters
    ----------
    event: dict, required
        API Gateway Lambda Proxy Input Format

        {
            "resource": "Resource path",
            "path": "Path parameter",
            "httpMethod": "Incoming request's method name"
            "headers": {Incoming request headers}
            "queryStringParameters": {query string parameters }
            "pathParameters":  {path parameters}
            "stageVariables": {Applicable stage variables}
            "requestContext": {Request context, including authorizer-returned key-value pairs}
            "body": "A JSON string of the request payload."
            "isBase64Encoded": "A boolean flag to indicate if the applicable request payload is Base64-encode"
        }

        https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format

    context: object, required
        Lambda Context runtime methods and attributes

    Attributes
    ----------

    context.aws_request_id: str
         Lambda request ID
    context.client_context: object
         Additional context when invoked through AWS Mobile SDK
    context.function_name: str
         Lambda function name
    context.function_version: str
         Function version identifier
    context.get_remaining_time_in_millis: function
         Time in milliseconds before function times out
    context.identity:
         Cognito identity provider context when invoked through AWS Mobile SDK
    context.invoked_function_arn: str
         Function ARN
    context.log_group_name: str
         Cloudwatch Log group name
    context.log_stream_name: str
         Cloudwatch Log stream name
    context.memory_limit_in_mb: int
        Function memory

        https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html

    Returns
    ------
    API Gateway Lambda Proxy Output Format: dict
        'statusCode' and 'body' are required

        {
            "isBase64Encoded": true | false,
            "statusCode": httpStatusCode,
            "headers": {"headerName": "headerValue", ...},
            "body": "..."
        }

        # api-gateway-simple-proxy-for-lambda-output-format
        https: // docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
    """

    try:
        s3 = boto3.client('s3')

        bucketName = event['Records'][0]['s3']['bucket']['name']
        fileKey = event['Records'][0]['s3']['object']['key']

        print(bucketName)
        print(fileKey)

        if os.environ["TEST_LOCALLY"]:
            dynamodb = boto3.client('dynamodb',
                endpoint_url="http://172.16.123.1:8000", # Para que esto ande hay que hacer esta magia: 'sudo ifconfig lo0 -alias 172.16.123.1'
                region_name='us-west-2', 
                aws_access_key_id="Al final ninguna de estas 2",
                aws_secret_access_key="era verdaderamente importante")
            content_file = open('files/pipo1.txt')    
        else:
            dynamodb = boto3.client('dynamodb')
            content_file = s3.get_object(Bucket=bucketName, Key=filekey)

        pipoRecord = dynamodb.scan(TableName='Pipo')['Items'][0] or { 'id': { 'S': 'pipoId' } } # Solo usamos un record

        regex = r"([^\s]*pipo[^\s]*)"
        content = content_file.read()
        matches = re.finditer(regex, content, re.IGNORECASE | re.MULTILINE)

        for _, match in enumerate(matches):
            matchName = match.group().lower()
            pipoRecord.setdefault(matchName, {'N': '0'})
            pipoCurrentValue = int(pipoRecord[matchName]['N'])
            pipoRecord[matchName] = { 'N': str(pipoCurrentValue + 1) }

        output = dynamodb.put_item(
            TableName='Pipo',
            Item=pipoRecord
        )

    except Exception as inst:
        output = "Unexpected error: {0}: {1}".format(type(inst), inst)

    return {
        "statusCode": 200,
        "body": json.dumps({"message": output}, default=str),
    }
