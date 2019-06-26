import boto3
from boto3.dynamodb.conditions import Key, Attr
import json
import logging
import copy
import time

current_milli_time = lambda: int(round(time.time() * 1000))

## Logging setup
logger=logging.getLogger()
logger.setLevel(logging.INFO)

logger.info('Loading function')

dynamodb = boto3.resource('dynamodb')
teams_table = dynamodb.Table('datathon-teams')
challenges_table = dynamodb.Table('datathon-challenges')
answers_table = dynamodb.Table('datathon-answers')

# challenges cache
challenge_cache = dict()
cache_load_time = 0
CACHE_EXPIRATION = 10000

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
    if operation == 'GET':
        if resource == '/leaderboard':
            logger.info('get_leaderboard')
            return get_leaderboard()
        elif resource == '/answers':
            logger.info('get_answers')
            return get_answers()
    
    elif operation == 'POST':
        if resource == '/answers/{teamId}/{challengeid}':
            logger.info('post_answer_approve')
            return post_answer_approve(event['pathParameters'])

    elif operation == 'DELETE':
        if resource == '/answers/{teamId}/{challengeid}':
            logger.info('post_answer_reject')
            return post_answer_reject(event['pathParameters'])
    

    # Authorization required
    username = get_username(event['requestContext'])
    logger.info("Cognito username: " + str(username))

    if username is None:
        return respond(err="Unauthorized", status=401)
    
    if operation == 'GET':
        if resource == '/challenges':
            logger.info('get_challenges')
            return get_challenges(username)
        elif resource == '/challenges/{id}/hint':
            logger.info('get_challenge_hint')
            return get_challenge_hint(event['pathParameters'], username)
        else:
            logger.error('No matching GET resource')
            return respond(err='Unknown resource "{}"'.format(resource), status=400)

    elif operation == 'POST':
        if resource == '/challenges/{id}/answer':
            logger.info('post_challenge_answer')
            return post_challenge_answer(event['pathParameters'], event['body'], username)
        else: 
            logger.error('No matching POST resource')
            return respond(err='Unknown resource "{}"'.format(resource), status=400)
    
    else:
        logger.error('No matching method')
        return respond(err='Unsupported method "{}"'.format(operation), status=400)


#################
# HTTP method functions


def get_challenges(username):

    # Load challenges cache & add team data
    team_challenges = copy.deepcopy(get_challenge_cache())
    response = query_answers_by_team(username)
    while True:
        for answer in response['Items']:
            team_challenges[answer['challengeId']].update(
                {
                    "answer": answer['answer'] if 'answer' in answer else None,
                    "hinted": answer['hinted'],
                    "status": answer['status']
                }
            )
            if not answer['hinted']:
                del team_challenges[answer['challengeId']]['hint']
        
        if 'LastEvaluatedKey' in response:
            response = query_answers_by_team(username, response['LastEvaluatedKey'])
        else:
            break
    
    return respond(res=[team_challenges[chId] for chId in sorted(team_challenges, key=lambda t: t)])


def get_challenge_hint(params, teamId):

    if not 'id' in params:
        return respond(err='Missing challenge ID on path parameters', status=400)
    
    challengeId = params['id']
    challenges = get_challenge_cache()
    if not challengeId in challenges:
        return respond(err='Challenge ID not found', status=404)
    
    hint = challenges[challengeId]['hint']
    points = challenges[challengeId]['points']

    # mark challenge for team as hinted
    try:
        answers_table.update_item(
            Key={
                'teamId': teamId,
                'challengeId': challengeId
            },
            UpdateExpression='SET hinted = :true, #statusAttr = :unanswered, points = :points',
            ConditionExpression='(attribute_not_exists(#statusAttr) or #statusAttr = :unanswered) and (attribute_not_exists(hinted) or hinted = :false)',
            ExpressionAttributeNames={
                '#statusAttr': 'status'
            },
            ExpressionAttributeValues={
                ':unanswered': 'UNANSWERED',
                ':true': 'true',
                ':false': 'false',
                ':points': int(points)
            }
        )

    except Exception:
        return respond(err='Hint already requested or question already answered', status=400)
    
    logger.info("Team " + teamId + " got hint for challenge " + challengeId)

    return respond(res=
        {
            "hint" : hint
        }
    )
    

def get_leaderboard():

    leaderboard = dict()

    response = scan_leaderboard()
    while True:
        for team in response['Items']:
            leaderboard[team['teamId']] = team['qualifyingPoints'] + team['pitchPoints'] + team['gamePoints'] + team['kahootPoints']
        
        if 'LastEvaluatedKey' in response:
            response = scan_leaderboard(response['LastEvaluatedKey'])
        else:
            break
    
    return respond(res=[{ "position": index, "teamName": team, "score": int(leaderboard[team])} for index, team in enumerate(sorted(leaderboard, key=lambda t: leaderboard[t], reverse=True))])
    

def get_answers():

    answers = []

    response = query_answers_by_status('ANSWERED')
    while True:
        for answer in response['Items']:
            answers.append({
                "teamId": answer['teamId'],
                "challengeId": answer['challengeId'],
                "challengeTitle": get_challenge_cache()[answer['challengeId']]['title'],
                "answer": answer['answer']
            })
        
        if 'LastEvaluatedKey' in response:
            response = query_answers_by_status('ANSWERED', response['LastEvaluatedKey'])
        else:
            break
    
    return respond(res=answers)
    

def post_challenge_answer(params, body, teamId):

    if not 'id' in params:
        return respond(err='Missing challenge ID on path parameters', status=400)
    
    if not 'answer' in body:
        return respond(err='Missing answer on message body', status=400)
    
    answer = body['answer']
    challengeId = params['id']
    challenges = get_challenge_cache()
    if not challengeId in challenges:
        return respond(err='Challenge ID not found', status=404)
    
    points = challenges[challengeId]['points']

    # record answer for challenge
    try:
        answers_table.update_item(
            Key={
                'teamId': teamId,
                'challengeId': challengeId
            },
            UpdateExpression='SET #statusAttr = :answered, points = :points, answer = :answer',
            ConditionExpression='attribute_not_exists(#statusAttr) or #statusAttr = :unanswered',
            ExpressionAttributeNames={
                '#statusAttr': 'status'
            },
            ExpressionAttributeValues={
                ':answered': 'ANSWERED',
                ':unanswered': 'UNANSWERED',
                ':points': int(points),
                ':answer': answer
            }
        )

    except Exception as ex:
        logger.info(ex)
        return respond(err='Question already answered', status=400)
    
    logger.info("Team " + teamId + " answered challenge " + challengeId)

    return respond()


def post_answer_approve(params):

    if not 'teamId' in params or not 'challengeid' in params:
        return respond(err='Missing team ID or challenge ID on path parameters', status=400)
    
    teamId = params['teamId']
    challengeId = params['challengeid']

    points = update_approved_status(teamId, challengeId, 'APPROVED')
    if points < 0:
        return respond(err='Trying to approve an answer not in ANSWERED status', status=400)

    if not update_game_points(teamId, points):
        return respond(err='Error updating team ' + teamId + ' with ' + points + ' points', status=500)
    
    logger.info("Team " + teamId + " got " + str(points) + " points for challenge " + challengeId)

    return respond()


def post_answer_reject(params):

    if not 'teamId' in params or not 'challengeid' in params:
        return respond(err='Missing team ID or challenge ID on path parameters', status=400)
    
    teamId = params['teamId']
    challengeId = params['challengeid']

    if update_approved_status(teamId, challengeId, 'REJECTED') < 0:
        return respond(err='Trying to reject an answer not in ANSWERED status', status=400)
    
    logger.info("Team " + teamId + " got answer for challenge " + challengeId + " rejected")

    return respond()


#######################
# Helper functions

def get_username(context):
    try:
        return context['authorizer']['claims']['cognito:username']
    except Exception:
        return None

def get_challenge_cache():

    global challenge_cache, cache_load_time

    if not challenge_cache or current_milli_time() - cache_load_time > CACHE_EXPIRATION:

        # Load challenges cache
        response = scan_challenges()
        while True:
            for ch in response['Items']:
                challenge_cache[ch['challengeId']] = ch
                challenge_cache[ch['challengeId']].update(
                    {
                        "answer": None,
                        "hinted": False,
                        "status": "UNANSWERED",
                        "points": int(ch['points'])
                    }
                )
            if 'LastEvaluatedKey' in response:
                response = scan_challenges(response['LastEvaluatedKey'])
            else:
                break
        
        cache_load_time = current_milli_time()
    
    return challenge_cache


#######################
# DB helper functions


def scan_leaderboard(startKey=None):
    if startKey:
        return teams_table.scan(
            Select='ALL_ATTRIBUTES',
            ExclusiveStartKey=startKey
        )
    else:
        return teams_table.scan(
            Select='ALL_ATTRIBUTES'
        )


def scan_challenges(startKey=None):
    if startKey:
        return challenges_table.scan(
            Select='ALL_ATTRIBUTES',
            ExclusiveStartKey=startKey
        )
    else:
        return challenges_table.scan(
            Select='ALL_ATTRIBUTES'
        )
    

def query_answers_by_team(teamId, startKey=None):
    if startKey:
        return answers_table.query(
            Select='ALL_ATTRIBUTES',
            ExclusiveStartKey=startKey,
            KeyConditionExpression=Key('teamId').eq(teamId)
        )
    else:
        return answers_table.query(
            Select='ALL_ATTRIBUTES',
            KeyConditionExpression=Key('teamId').eq(teamId)
        )


def query_answers_by_status(status, startKey=None):
    if startKey:
        return answers_table.query(
            IndexName='status-index',
            Select='ALL_PROJECTED_ATTRIBUTES',
            ExclusiveStartKey=startKey,
            #ProjectionExpression='teamId, challengeId, #st',
            KeyConditionExpression="#st=:stVal",
            ExpressionAttributeNames={'#st': 'status'},
            ExpressionAttributeValues={ ":stVal": status}
        )
    else:
        return answers_table.query(
            IndexName='status-index',
            Select='ALL_PROJECTED_ATTRIBUTES',
            #ProjectionExpression='teamId, challengeId, #st',
            KeyConditionExpression="#st=:stVal",
            ExpressionAttributeNames={'#st': 'status'},
            ExpressionAttributeValues={ ":stVal": status}
        )


def update_game_points(teamId, points):

    # update team points
    try:
        teams_table.update_item(
            Key={
                'teamId': teamId
            },
            UpdateExpression='ADD gamePoints :points',
            ExpressionAttributeValues={
                ':points': points
            }
        )

    except Exception as ex:
        logger.error("Trying to update team " + teamId + " with " + points + " points: " + str(ex))
        return False
    
    return True


def update_approved_status(teamId, challengeId, status):

    # mark challenge for team as hinted
    try:
        response = answers_table.update_item(
            Key={
                'teamId': teamId,
                'challengeId': challengeId
            },
            UpdateExpression='SET #statusAttr = :newstatus',
            ConditionExpression='#statusAttr = :answered',
            ExpressionAttributeNames={
                '#statusAttr': 'status'
            },
            ExpressionAttributeValues={
                ':answered': 'ANSWERED',
                ':newstatus': status
            },
            ReturnValues='ALL_NEW'
        )

        if not 'Attributes' in response or not 'points' in response['Attributes']:
            return -1
        points = response['Attributes']['points']

        # hinted answers get half points
        if 'hinted' in response['Attributes'] and response['Attributes']['hinted'] == 'true':
            points /= 2

    except Exception as ex:
        logger.error("Trying to update team " + teamId + " answer for challenge " + challengeId + " with status " + status + ": " + str(ex))
        return -1
    
    return points