import boto3
from boto3.dynamodb.conditions import Key, Attr
import json
import logging

## Logging setup
logger=logging.getLogger()
logger.setLevel(logging.INFO)

logger.info('Loading function')

dynamodb = boto3.resource('dynamodb')
teams_table = dynamodb.Table('datathon-teams')
challenges_table = dynamodb.Table('datathon-challenges')
answers_table = dynamodb.Table('datathon-answers')

def respond(err=None, res=None, status=200):
    logger.info('Sending response err %s res %s' % (err,json.dumps(res, indent=2)) )
    return {
        'isBase64Encoded': False,
        'statusCode': status,
        'body': err if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Headers':'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods':'DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT',
            'Access-Control-Allow-Origin':'*'
        }
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
    logger.info("Received event: " + json.dumps(event, indent=2))
    
    operation = event['httpMethod']
    resource = event['resource']

    logger.debug('Operation %s - resource %s' % (operation,resource) )

    # Methods with no authorization required
    if operation == 'GET' and resource == '/leaderboard':
        logger.info('get_leaderboard')
        return get_leaderboard()

    # Authorization required
    username = get_username(event)
    logger.info("Cognito username: " + str(username))

    if username is None:
        return respond(err="Unauthorized", status=401)
    
    if operation == 'GET':
        if resource == '/challenges':
            logger.info('get_challenges')
            return get_challenges(username)
        elif resource == '/challenges/{id}/hint':
            logger.info('get_challenge_hint')
            return get_challenge_hint(username)
        else:
            logger.error('No matching GET resource')
            return respond(err=ValueError('Unknown resource "{}"'.format(resource)), status=400)

    elif operation == 'POST':
        if resource == '/challenges/{id}/answer':
            logger.info('post_challenge_answer')
            return post_challenge_answer(username)
        else:
            logger.error('No matching POST resource')
            return respond(err=ValueError('Unknown resource "{}"'.format(resource)), status=400)

    else:
        logger.error('No matching method')
        return respond(err=ValueError('Unsupported method "{}"'.format(operation)), status=400)

def get_challenges(username):
    return respond(res=[
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
    ])

def get_challenge_hint(username):
    return respond(res=
        {
            "hint" : "This is a hint for the challenge"
        }
    )
    
def get_leaderboard():

    leaderboard = dict()

    response = query_leaderboard()
    while True:
        for team in response['Items']:
            leaderboard[team['teamId']] = team['qualifyingPoints'] + team['pitchPoints'] + team['gamePoints'] + team['kahootPoints']
        
        if 'LastEvaluatedKey' in response:
            response = query_leaderboard(response['LastEvaluatedKey'])
        else:
            break
    
    return respond(res=[{ "position": index, "teamName": team, "score": int(leaderboard[team])} for index, team in enumerate(sorted(leaderboard, key=lambda t: leaderboard[t], reverse=True))])
    
def post_challenge_answer(username):
    return respond()


def get_username(event):
    try:
        return event['requestContext']['authorizer']['claims']['cognito:username']
    except Exception:
        return None

def query_leaderboard(startKey=None):
    if startKey:
        return teams_table.scan(
            Select='ALL_ATTRIBUTES',
            ExclusiveStartKey=startKey
        )
    else:
        return teams_table.scan(
            Select='ALL_ATTRIBUTES'
        )

def query_answers(startKey=None):

    return answers_table.query(
        IndexName='status-teamId-index',
        Select='SPECIFIC_ATTRIBUTES',
        Limit=100,
        ConsistentRead=False,
        ScanIndexForward=True,
        ExclusiveStartKey=startKey,
        ProjectionExpression='status, teamId, points',
        KeyConditionExpression=Key('status').eq('APPROVED')
    )

