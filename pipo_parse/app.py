import json

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
    
    pipoResults = {}
    regex = r"([^\s]*pipo[^\s]*)"
    output = ""

    try:
        dynamodb = boto3.client('dynamodb',
            endpoint_url="http://172.16.123.1:8000", # Para que esto ande hay que hacer esta magia: 'sudo ifconfig lo0 -alias 172.16.123.1'
            region_name='us-west-2', 
            aws_access_key_id="Al final ninguna de estas 2",
            aws_secret_access_key="era verdaderamente importante")

        # # Insertar un item
        # output = dynamodb.put_item(
        #     TableName='Pipo',
        #     Item={
        #         'filename':{
        #             'S': 'pipofile2.txt'
        #         },
        #         'pipo': {
        #             'N': "12"
        #         },
        #         'pipopi': {
        #             'N': "35"
        #         }
        #     }
        # )

        # # SELECT * FROM Pipo (Esto tiene que hacer la otra funcion)
        # results = dynamodb.scan(TableName='Pipo')['Items']
        # output = results
     
        # resultHash = {}
        # for result in results:
        #     for key in result.keys():
        #         if 'N' in result[key].keys():
        #             resultHash[key] = str(int(resultHash.get(key, '0')) + int(result[key]['N']))
        # output = resultHash
        
        # table = dynamodb.get_table('Pipo')
       
        # table = dynamodb.delete_table(TableName='Pipo')
       
        # # Asi se creo la tabla
        # table = dynamodb.create_table(
        #     TableName='Pipo',
        #     KeySchema=[
        #         {
        #             'AttributeName': "filename",
        #             'KeyType': "HASH"

        #         }
        #     ],
        #     AttributeDefinitions=[
        #         {
        #             'AttributeName': "filename",
        #             'AttributeType': "S"
        #         }
        #     ],
        #     ProvisionedThroughput={
        #         'ReadCapacityUnits': 10,
        #         'WriteCapacityUnits': 10
        #     }
        # )
        # output = table

        # # Esto es el parser, gracias regex101.com
        # with open('files/pipo1.txt', 'r') as content_file:
        #     content = content_file.read()
        #     matches = re.finditer(regex, content, re.IGNORECASE | re.MULTILINE)
        #     for matchNum, match in enumerate(matches):
        #         matchNum = matchNum + 1
                
        #         print ("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
                
        #         for groupNum in range(0, len(match.groups())):
        #             groupNum = groupNum + 1
                    
        #             print ("Group {groupNum} found at {start}-{end}: {group}".format(groupNum = groupNum, start = match.start(groupNum), end = match.end(groupNum), group = match.group(groupNum)))
         
    except Exception as inst:
        output = "Unexpected error: {0}: {1}".format(type(inst), inst)

    return {
        "statusCode": 200,
        "body": json.dumps({"message": output}, default=str),
    }
