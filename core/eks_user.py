import boto3
import botocore
import argparse
import logging
import json
from core.helpers import group_exists, user_exists,policy_exists


# Initializing loggers and requisites
FORMAT = "%(asctime)-15s - %(levelname)s:%(name)s:%(message)s"
logging.basicConfig(level=logging.INFO, format=FORMAT)
logger = logging.getLogger("Main")

logger.info("Starting creating of eks user")


ARN_MININUM_LENGTH = 20

def main():
    parser = argparse.ArgumentParser(description="Create iam user for eks clusters on aws")
    parser.add_argument("--profile", type=str,  dest="profile", help="name of the aws profile in ~/.aws/credentials",
                        required=True)
    parser.add_argument("--user", type=str, dest="user_name", help="Username to create in aws iam")

    args = parser.parse_args()

    logger.info(f"Using profile {args.profile}")
    logger.info(f"User will have the name: {args.user_name}")

    # Create iam group and policies
    boto3.setup_default_session(profile_name=args.profile)

    logging.info("Eks user")

    user = EksUser(user_name=args.user_name, profile=args.profile)

    user_name = args.user_name
    
# Gets the account id of the user running this script
def get_account_id():
    return boto3.client('sts').get_caller_identity().get('Account')


class EksUser(object):
    def __init__(self, user_name = "", profile="default"):
        self.user_name = user_name
        self.profile = profile
        self.iam_client = boto3.client("iam")
        self.eks_policy_name = f"{user_name}-eks-policy"









    def get_expected_eks_policy_arn(self):
        account_id = get_account_id()
        if account_id and len(account_id) <= 0:
            raise ValueError("Could not extract account id, cannot continue")
        else:
            eks_policy_arn = f"arn:aws:iam::{account_id}:policy/{self.eks_policy_name}"
            logger.info(f"Expected arn: {eks_policy_arn}")
            return eks_policy_arn




    def create_user_policy(self, user_arn):
        eks_policy_arn = get_expected_eks_policy_arn()
        if policy_exists(policy_arn=eks_policy_arn, policy_name=eks_policy_name, client=iam):
            logger.warning("Policy already exists, will not create again")
            logger.info("Returning expected policy arn")
            return eks_policy_arn
        else:
            
            logger.info("Creating policy")
            try:
                logger.info(f"Setting iam policy and eks policies for user arn: {user_arn}")
                if user_arn and len(user_arn) > ARN_MININUM_LENGTH:
                    policyDict = { 
                    "Version" : "2012-10-17", 
                    "Statement" : [
                    {
                        "Sid": "VisualEditor0",
                        "Effect": "Allow",
                        "Action": [ 
                            "iam:ListAccessKeys",
                            "iam:ListAccountAliases",
                            "iam:ListGroups",
                            "iam:ListAttachedUserPolicies",
                            "iam:ListRoles",
                            "iam:ListRoleTags",
                            "iam:ListSSHPublicKeys",
                            "iam:ListUsers",
                            "iam:ListUserTags",
                            "iam:GetLoginProfile",
                            "iam:GetAccountSummary",
                            "iam:GetSSHPublicKey",
                            "iam:TagUser",
                            "iam:UntagUser",
                            "iam:CreateAccessKey",
                            "iam:DeleteAccessKey",
                            "iam:UpdateAccessKey",
                            "iam:UpdateSSHPublicKey",
                            "iam:UploadSSHPublicKey"
                        ],
                        "Resource": user_arn
                        }, {
                                "Sid": "VisualEditor1",
                                "Effect": "Allow",
                                "Action": [ 
                                    "eks:ListClusters",
                                    "eks:DescribeCluster",
                                    "eks:DescribeUpdate"
                                ],
                                "Resource": "*"
                            }
                        ]
                        }
                    logger.info("Applying the following policy")
                    logger.info(policyDict)
                    policy = json.dumps(policyDict, sort_keys=True)
                    result = iam.create_policy(
                        PolicyName=f"{eks_policy_name}",
                        Path="/",
                        PolicyDocument=policy)
                    return result
            except iam.exceptions.NoSuchEntityException:
                logger.warning(f"Group eksPolicy already created")
                return None
            except iam.exceptions.MalformedPolicyDocumentException:
                logger.error(f"Group eksPolicty failed to be created")
                return None


    def attach_user_to_eks_policy(self):
        arn = get_expected_eks_policy_arn()
        logger.info(f"Attaching policy {arn} to user {user_name}")
        iam.attach_user_policy(
            UserName=user_name,
            PolicyArn=arn
        )


    def create_user_and_attach_to_group(self):
        logger.info(f"Creating user {user_name} if needed")
        if user_exists(user_name=user_name, client=iam):
            logger.warning(f"User {user_name} already exists, skipping creation")
        else:
            logging.info(f"Creating eks user")
            response = iam.create_user(
                Path="/",
                UserName=user_name,
                Tags=[
                    {
                        "Key": "Automation",
                        "Value": "Boto3"
                    },
                    {
                        "Key": "Purpose",
                        "Value": "Eks Access"
                    }
                ]
            )
            # EO logic
        # Get newly created or existing user
        response = iam.get_user(
            UserName = f"{user_name}"
        )
        arn = response['User']['Arn']
        logging.info(f"Arn for new user: {arn}")
        logging.info(f"User {user_name} created")
        logging.info(f"Creating user policy with ami access to spesific user arn")
        policy_arn = create_user_policy(arn)
        logger.info(f"Created policy: {policy_arn}")

        response = iam.attach_user_policy(
            UserName=f"{user_name}",
            PolicyArn=f"{policy_arn}"
        )
        logger.info(f"Response: {response}")



# # Run the stuff
# create_user_and_attach_to_group()
# attach_user_to_eks_policy()

# logger.info("Finished!")

