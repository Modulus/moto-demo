from core.eks_user import EksUser
import boto3

from core.helpers import policy_exists

from moto import mock_sts
import mock

@mock_sts
def test_get_expected_policty_arn():
    user = EksUser(user_name="lusken", profile="somerandonaccount")

    arn = user.get_expected_eks_policy_arn()

    assert arn != None
    assert "lusken" in arn
    assert "arn:aws:iam::" in arn


@mock_sts
@mock.patch("core.helpers.policy_exists", side_effect=False)