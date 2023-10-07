import functools
import time

import boto3
from botocore.exceptions import ClientError


class AwsClient:
    def __init__(self, profile_name, boto_session) -> None:
        self._profile_name = profile_name
        self._boto_session = boto_session
        self._boto_client = boto_session.client("iam")

    @property
    def profile_name(self):
        return self._profile_name

    @classmethod
    def for_profile(cls, profile_name: str) -> "AwsClient":
        return AwsClient(
            profile_name, boto_session=boto3.session.Session(profile_name=profile_name, region="us-east-1")
        )

    def list_roles(self):
        for response in self._paginated_request(self._boto_client.list_roles):
            yield from response["Roles"]

    def get_role(self, role_name):
        return self._request(self._boto_client.get_role, RoleName=role_name)["Role"]

    def list_inline_policies(self, role_name):
        for response in self._paginated_request(self._boto_client.list_role_policies, RoleName=role_name):
            yield from response["PolicyNames"]

    def list_attached_policies(self, role_name):
        for response in self._request(self._boto_client.list_attached_role_policies, RoleName=role_name):
            yield from response["AttachedPolicies"]

    def get_inline_policy_document(self, role_name, policy_name):
        return self._request(self._boto_client.get_role_policy, RoleName=role_name, PolicyName=policy_name)[
            "PolicyDocument"
        ]

    def list_policy_versions(self, policy_arn):
        return self._request(self._boto_client.list_policy_versions, PolicyArn=policy_arn)["Versions"]

    def get_policy_document(self, policy_arn, version_id):
        return self._request(self._boto_client.get_policy_version, PolicyArn=policy_arn, VersionId=version_id)[
            "PolicyVersion"
        ]["Document"]

    def get_last_accessed_details(self, arn):
        response = self._request(
            functools.partial(
                self._boto_client.generate_service_last_accessed_details, Arn=arn, Granularity="ACTION_LEVEL"
            )
        )
        job_id = response["JobId"]
        while True:
            time.sleep(5)
            response = list(
                self._request(functools.partial(self._boto_client.get_service_last_accessed_details, JobId=job_id))
            )
            if response["JobStatus"] == "FAILED":
                raise Exception()
            if response["JobStatus"] == "COMPLETED":
                yield from self._paginated_request(
                    functools.partial(self._boto_client.get_service_last_accessed_details, JobId=job_id)
                )

    def _paginated_request(self, fun):
        response = self._request(fun)
        yield response
        marker = response.get("Marker")
        if marker:
            yield from self._paginated_request(functools.partial(fun, Marker=marker))

    def _request(self, fun):
        return self._retried_call(fun)

    def _retried_call(self, fun):
        while True:
            try:
                return fun()
            except ClientError as e:
                if e.response["Error"]["Code"] == "LimitExceededException":
                    time.sleep(5)
                else:
                    raise e


class IamReader:
    def __init__(self, client: AwsClient) -> None:
        self._client = client

    @classmethod
    def for_profile(cls, profile_name) -> "IamReader":
        return IamReader(client=AwsClient.for_profile(profile_name))

    def describe_role(self, role_name):
        role = self._client.get_role(role_name)
        inline_policy_names = self._client.list_inline_policies(role_name)
        inline_policy_documents = [self._client.get_inline_policy_document(role_name, pn) for pn in inline_policy_names]
        attached_policy_arns = [item["PolicyArn"] for item in self._client.list_attached_policies(role_name)]
        attached_policy_arns_and_latest_version_ids = [
            (arn, self._get_latest_version_id(arn)) for arn in attached_policy_arns
        ]
        attached_policy_documents = [
            self._client.get_policy_document(*args) for args in attached_policy_arns_and_latest_version_ids
        ]
        return {
            "RoleArn": role["Arn"],
            "RoleName": role_name,
            "InlinePolicyDocuments": inline_policy_documents,
            "AttachedPolicyDocuments": attached_policy_documents,
            "LastAccessedDetails": self._client.get_last_accessed_details(role["Arn"]),
        }

    def _get_latest_version_id(self, policy_arn):
        versions = self._client.list_policy_versions(policy_arn)
        sorted_versions = sorted(versions, key=lambda it: max(it["CreateDate"]), reverse=True)
        return sorted_versions[0]["VersionId"]
