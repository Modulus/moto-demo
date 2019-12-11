import logging
import boto3
import botocore

logger = logging.getLogger("Helpers")


# TODO: Refactor this into one large general function
def group_exists(group_name, client):
    try:
        response = client.get_group(GroupName=group_name, MaxItems=2)
        if "Group" in response and "GroupName" in response["Group"] and response["Group"]["GroupName"] == group_name:
            logger.info("Group exists")
            return True
        else:
            logger.warning(f"Group {group_name} not found")
            return False
    except client.exceptions.NoSuchEntityException:
        logger.warning(f"Group {group_name} not found")
        return False


def user_exists(user_name, client):
    try:
        response = client.get_user(UserName=user_name)

        if "User" in response and "UserName" in response["User"] and response["User"]["UserName"] == user_name:
            logger.info("User exists")
            return True
        else:
            logger.warning(f"User {user_name} not found")
            return False
    except client.exceptions.NoSuchEntityException:
        logger.warning(f"Group {user_name} not found")
        return False


def policy_exists(policy_arn, policy_name, client):
    try:
        response = client.get_policy(PolicyArn=policy_arn)

        if "Policy" in response and "PolicyName" in response["Policy"] \
                and response["Policy"]["PolicyName"] == policy_name:
            logger.info("User exists")
            return True
        else:
            logger.warning(f"PolicyArn {policy_arn} with name: {policy_name} not found")
            return False
    except client.exceptions.NoSuchEntityException:
        logger.warning(f"PolicyArn {policy_arn} with name: {policy_name} not found")
        return False
