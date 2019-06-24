import boto3
import json

print('Loading function')
dynamo = boto3.client('dynamodb')


def respond(err=None, res=None):
    return {
        'statusCode': '400' if err else '200',
        'body': err if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }


def lambda_handler(event, context):
    '''
    INPUT:
    {
        "resource": "Resource path",
        "path": "Path parameter",
        "httpMethod": "Incoming request's method name"
        "headers": {String containing incoming request headers}
        "multiValueHeaders": {List of strings containing incoming request headers}
        "queryStringParameters": {query string parameters }
        "multiValueQueryStringParameters": {List of query string parameters}
        "pathParameters":  {path parameters}
        "stageVariables": {Applicable stage variables}
        "requestContext": {Request context, including authorizer-returned key-value pairs}
        "body": "A JSON string of the request payload."
        "isBase64Encoded": "A boolean flag to indicate if the applicable request payload is Base64-encode"
    }

    OUTPUT:
    {
        "isBase64Encoded": true|false,
        "statusCode": httpStatusCode,
        "headers": { "headerName": "headerValue", ... },
        "multiValueHeaders": { "headerName": ["headerValue", "headerValue2", ...], ... },
        "body": "..."
    }

    '''
    print("Received event: " + json.dumps(event, indent=2))

    operation = event['httpMethod']
    resource = event['resource']

    if operation == 'GET':
        if resource == '/challenges':
            return get_challenges(event)
        elif resource == '/challenges/{id}/hint':
            return get_challenge_hint(event)
        elif resource == '/leaderboard':
            return get_leaderboard(event)
        else:
            respond(ValueError('Unknown resource "{}"'.format(resource)))

    elif operation == 'POST':
        if resource == '/challenges/{id}/answer':
            return post_challenge_answer(event)
        else:
            respond(ValueError('Unknown resource "{}"'.format(resource)))

    else:
        respond(ValueError('Unsupported method "{}"'.format(operation)))

def get_challenges(event):
    return respond(res=json.dumps([
        {
            "challengeId": "ch01",
            "title": "Challenge 1",
            "description": "This is the first challenge and is a very easy one",
            "points": 100,
            "hinted": False,
            "hint": None,
            "status": "UNANSWERED",
            "answer": None
        },
        {
            "challengeId": "ch02",
            "title": "Challenge 2",
            "description": "This is the second challenge and is not that easy",
            "points": 200,
            "hinted": True,
            "hint": "This is a hint!!",
            "status": "ANSWERED",
            "answer": "This is an answer for the challenge"
        }
    ]))

def get_challenge_hint(event):
    respond(res=json.dumps({
            "hint" : "This is a hint for the challenge"
        }))
    
def get_leaderboard(event):
    respond(res=json.dumps([
        {
            "position": 1,
            "teamName": "team 1",
            "score": 400
        },
        {
            "position": 2,
            "teamName": "team 2",
            "score": 300
        },
        {
            "position": 3,
            "teamName": "team 3",
            "score": 200
        },
        {
            "position": 4,
            "teamName": "team 4",
            "score": 100
        }]))
    
def post_challenge_answer(event):
    respond()
