"""Module test"""

import http.client
import random
import urllib.parse
import time
from datetime import datetime, timedelta
import json
from dateutil import tz
import boto3
import botocore.exceptions

class CrowdStrikeAPIError(Exception):
    """Crowdstrike API error"""


class Falcon:
    """Crowdstrike Falcon API class"""

    def __init__(
        self, ssm_cloud_path, client_id, client_secret, ssm_helper, bearer_token=None
    ):
        """Default constructor

        Args:
            ssm_cloud_path (str): AWS SSM Parameter Store path for the Crowdstrike cloud
            client_id (str): AWS SSM Parameter Store path for the Crowdstrike client_id
            client_secret (str): AWS SSM Parameter Store path for the Crowdstrike client_secret
            ssm_helper (SSMHelper): AWS SSM helper class
            bearer_token (str, optional): CrowdStrike API OAUTH2 Token. Defaults to None.
        """
        self.ssm_cloud_path = ssm_cloud_path
        self.client_id = client_id
        self.client_secret = client_secret
        self.user_agent = "crowdstrike-official-distributor-package/v1.0.0"
        self.cloud = None
        self.bearer_token = bearer_token
        # Since we are using SSM to store client_id and client_secret
        # we will use the SSM helper class to retrieve the values if
        # a method is called that requires them.
        # This reduces the logic needed in the script_handler
        self.ssm_helper = ssm_helper

    def _oauth(self):
        """Creates OAuth bearer token


        Returns:
            token (str): OAuth bearer token

        Raises:
            CrowdStrikeAPIError: If the API call fails
        """
        print("Requesting Authentication token from Crowdstrike backend.")

        falcon_cloud = (
            self.ssm_helper.get_parameter(self.ssm_cloud_path)
            .replace("https://", "")
            .replace("http://", "")
        )
        self.cloud = falcon_cloud
        falcon_client_id = self.ssm_helper.get_parameter(self.client_id)
        falcon_client_secret = self.ssm_helper.get_parameter(
            self.client_secret)

        params = urllib.parse.urlencode(
            {
                "client_id": falcon_client_id,
                "client_secret": falcon_client_secret,
            }
        )
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": self.user_agent,
        }
        conn = http.client.HTTPSConnection(self.cloud)
        conn.request("POST", "/oauth2/token", params, headers)
        res = conn.getresponse()

        if res.status != 201:
            raise CrowdStrikeAPIError(
                f"Received non success response {res.status} while fetching token. Error {res.reason}"
            )

        data = res.read()
        print("Successfully received OAuth token.")
        self.bearer_token = json.loads(data)["access_token"]

    def get_ccid(self):
        """Returns the Customer ID

        Returns:
            ccid (str): Customer ID

        Raises:
            CrowdStrikeAPIError: If the API call fails
        """
        print("Requesting Customer ID from Crowdstrike backend.")

        if self.bearer_token is None:
            self._oauth()

        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "User-Agent": self.user_agent,
        }

        conn = http.client.HTTPSConnection(self.cloud)
        conn.request("GET", "/sensors/queries/installers/ccid/v1", "", headers)
        res = conn.getresponse()

        if res.status != 200:
            raise CrowdStrikeAPIError(
                f"Received non success response {res.status} while fetching Customer ID. Error {res.reason}"
            )

        data = res.read()
        print("Successfully received Customer ID.")

        return json.loads(data)["resources"][0]

    def get_install_token(self):
        """Returns the Installation Token

        Returns:
            token (str): Installation Token

        Raises:
            CrowdStrikeAPIError: If the API call fails
        """
        print("Requesting Installation Token from Crowdstrike backend.")

        if self.bearer_token is None:
            self._oauth()

        conn = http.client.HTTPSConnection(self.cloud)

        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "User-Agent": self.user_agent,
        }

        conn.request(
            "GET",
            "/installation-tokens/queries/tokens/v1?filter=status:'valid'",
            "",
            headers,
        )
        install_token_query_resp = conn.getresponse()

        if install_token_query_resp.status != 200:
            if install_token_query_resp.status == 429:
                sleep_time = 20
                print(f"Too many requests, retrying in {sleep_time} seconds")
                time.sleep(sleep_time)
                return self.get_install_token()

            else:
                raise CrowdStrikeAPIError(
                    f"Received non success response {install_token_query_resp.status} while fetching token. Error {install_token_query_resp.reason}"
                )

        install_token_query_data = install_token_query_resp.read()
        resources = json.loads(install_token_query_data)["resources"]
        if len(resources) == 0:
            print("No Installation token found, skipping")
            return ""

        install_token_id = resources[0]
        url = f"/installation-tokens/entities/tokens/v1?ids={install_token_id}"
        conn.request("GET", url, "", headers)
        entities_resp = conn.getresponse()

        if entities_resp.status != 200:
            raise CrowdStrikeAPIError(
                f"Received non success response {entities_resp.status} while fetching token by id {install_token_id}. Error {entities_resp.reason}"
            )

        entities_resp_data = entities_resp.read()
        token = json.loads(entities_resp_data)["resources"][0]["value"]

        print("Successfully received Installation token")
        return token

    def get_presigned_url(self, api_filter):
        """Returns the presigned URL for the installer matching the filter

        Args:
            api_filter (str): Filter to use for the API call

        Returns:
            url (str): Presigned URL

        Raises:
            CrowdStrikeAPIError: If the API call fails
        """
        print(f"Getting the presigned URL for: {api_filter}")

        if self.bearer_token is None:
            self._oauth()

        conn = http.client.HTTPSConnection(self.cloud)
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "User-Agent": self.user_agent,
        }

        encoded_url = urllib.parse.quote(
            f"/sensors/combined/signed-urls/v1?offset=1&limit=1&filter={api_filter}",
            safe=":/?&=",
        )
        conn.request(
            "GET",
            encoded_url,
            "",
            headers=headers,
        )

        # Get the response
        response = conn.getresponse()

        if response.status != 200:
            raise CrowdStrikeAPIError(
                f"Received non success response {response.status} while fetching presigned URL. Error {response.reason}"
            )

        data = response.read().decode()

        resources = json.loads(data)["resources"]
        if len(resources) == 0:
            print(f"No installers found for filter {api_filter}")
            return None

        url = resources[0]["signed_url"]
        print(f"Successfully received presigned URL for: {api_filter}")
        conn.close()
        return url


def compile_instance_list(instances):
    """
    Compiles a list of Windows and Linux instances from the SSM instance information

    Args:
        instances (list): List of SSM instance information
    """
    window_instances = []
    linux_instances = []

    for instance in instances:
        if instance["PlatformType"] == "Windows":
            window_instances.append(instance["InstanceId"])
        elif instance["PlatformType"] == "Linux":
            linux_instances.append(instance["InstanceId"])
        else:
            print(f"Unknown platform type {instance['PlatformType']}")

    return {
        "windows_instances": window_instances,
        "linux_instances": linux_instances,
        "contains_windows_instances": any(window_instances),
        "contains_linux_instances": any(linux_instances),
    }


class SSMHelper:
    """A helper class for SSM"""

    def __init__(self, region, lock_path):
        self.client = boto3.client("ssm", region_name=region)
        self.lock_path = lock_path

    def put_parameter(
        self,
        name,
        value,
        description,
        parem_type="String",
        overwrite=True,
        max_retries=5,
    ):
        """Put a SSM parameter

        Args:
            name (str): Path to the SSM parameter
            value (str): Value of the SSM parameter
            description (str): Description of the SSM parameter
            param_type (str, optional): Type of the SSM parameter. Defaults to "String".
            overwrite (bool, optional): Whether to overwrite the SSM parameter. Defaults to True.
        """

        for retry in range(1, max_retries + 1):
            try:
                self.client.put_parameter(
                    Name=name,
                    Value=value,
                    Description=description,
                    Type=parem_type,  # type: ignore
                    Overwrite=overwrite,
                )
                return
            except self.client.exceptions.TooManyUpdates:
                print(f"Too many updates, waiting {retry} seconds")
                time.sleep(retry)
            except botocore.exceptions.ClientError as error:
                if error.response["Error"]["Code"] == "ThrottlingException":
                    print(f"Throttling exception, waiting {retry} seconds")
                    time.sleep(retry)
                else:
                    raise error

    def get_parameter(self, path):
        """Get a SSM parameter by path and return value.

        Args:
            path (str): Path to the SSM parameter
        """

        try:
            response = self.client.get_parameter(
                Name=path,
                WithDecryption=True,
            )
            return response["Parameter"]["Value"]
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "ThrottlingException":
                wait_time = 5
                print(f"Throttling exception, waiting {wait_time} seconds")
                time.sleep(wait_time)
                self.get_parameter(path)
            else:
                raise error

    def get_parameters_by_path(self, path):
        """Returns the parameters for the given path

        Args:
            client (boto3.client): Boto3 client for SSM
            path (str): Path to the SSM parameters

        Returns:
            dict: {
                "ParameterName": {
                    // Parameter information
                }
            }
        """
        try:
            paginator = self.client.get_paginator("get_parameters_by_path")

            response = {}

            for page in paginator.paginate(
                Path=path, WithDecryption=True, Recursive=True
            ):
                for parameter in page["Parameters"]:
                    response[parameter["Name"]] = parameter

            return response
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "ThrottlingException":
                wait_time = 5
                print(f"Throttling exception, waiting {wait_time} seconds")
                time.sleep(wait_time)
                self.get_parameter(path)
            else:
                raise error

    def create_refresh_lock(self, max_retries=5):
        """Creates the refresh lock parameter and retries if it fails

        Args:
            client (boto3.client): Boto3 client for SSM
            max_retries (int): Maximum number of retries (default: 5)

        Raises:
            Exception: If the lock cannot be created after the maximum number of retries

        Returns:
            bool: True if the lock was created. False if it already exists.
        """
        for retry in range(1, max_retries + 1):
            try:
                self.put_parameter(
                    name=self.lock_path,
                    value="true",
                    description="Refresh lock for CrowdStrike Distributor",
                    overwrite=False,
                )
                print(f"Successfully created refresh lock: {self.lock_path}")
                return True
            except self.client.exceptions.ParameterAlreadyExists:
                print(
                    f"Refresh lock parameter {self.lock_path} already exists")
                return False
            except Exception as err:  # pylint: disable=broad-except
                print(
                    f"Failed to create parameter {self.lock_path} with error {err}")
                print(f"Retry {retry}/{max_retries}")
                time.sleep(5)

        raise RuntimeError(
            "Unable to create lock, exceeded maximum number of retries.")

    def delete_refresh_lock(self, max_retries=5):
        """Deletes the refresh lock parameter and retries if it fails

        Args:
            client (boto3.client): Boto3 client for SSM
            max_retries (int): Maximum number of retries (default: 5)
        """
        for retry in range(1, max_retries + 1):
            try:
                self.client.delete_parameter(Name=self.lock_path)
                print(f"Successfully deleted refresh lock: {self.lock_path}")
                return True
            except self.client.exceptions.ParameterNotFound:
                print(f"Refresh lock parameter {self.lock_path} not found")
                return False
            except Exception as err:
                print(
                    f"Failed to delete parameter {self.lock_path} with error {err}")
                print(f"Retry {retry}/{max_retries}")
                time.sleep(5)
        print("Unable to delete lock, exceeded maximum number of retries.")


def validate_prefix_path(path):
    """Validates the prefix path for SSM parameters

    Args:
        path (str): Prefix path for SSM parameters

    Returns:
        str: A valid prefix path for SSM parameters

    Raises:
        ValueError: If the prefix path is invalid
    """
    if path == "":
        raise ValueError("Prefix path cannot be empty")
    if path[0] != "/":
        path = "/" + path

    if path[-1] == "/":
        path = path[:-1]

    return path


def is_datetime_old(modified_time, delta_minutes=20):
    """Checks if the datetime is older than delta_minutes

    Args:
        modified_time (datetime.datetime): time to check
        delta_minutes (int, optional): Number of minutes to check. Defaults to 20.

    Returns:
        bool: True if the datetime is older than 20 minutes, False otherwise
    """

    return modified_time < datetime.now(tz=tz.tzlocal()) - timedelta(
        minutes=delta_minutes
    )


def check_expired_presigned_url(platforms, params_in_path, ssm_param_path_prefix):
    """Returns true if any presigned_urls ssm parameters are missing or expired

    Args:
        platforms (dict): A dict of platforms and their filters
        params_in_path (dict): A dict of ssm parameters that exist withing the ssm_param_path_prefix path
        ssm_param_path_prefix (str): The path prefix for the ssm parameters
    """
    needs_refresh = False

    for filter_name, _ in platforms.items():
        ssm_path = f"{ssm_param_path_prefix}/{filter_name}/presigned_urls"

        if not params_in_path.get(ssm_path):
            print(f"SSM parameter {ssm_path} not found")
            needs_refresh = True
            break

        if is_datetime_old(params_in_path[ssm_path]["LastModifiedDate"], 1):
            print(f"SSM parameter {ssm_path} expired")
            needs_refresh = True
            break

    return needs_refresh


def handle_params_refresh(falcon, ssm_helper, options):
    """Handles the refresh of the ssm parameters and ensures required parameters are present


    Args:
        falcon (Falcon): Falcon class
        ssm_helper (SSMHelper): SSMHelper class
        options (dict): Options required to do the refresh
    """

    platforms = options["platforms"]
    ssm_param_path_prefix = options["ssm_param_path_prefix"]
    lock_param = options["lock_param"]
    ccid_param = options["ccid_param"]
    install_token_param = options["install_token_param"]
    falcon_ccid = None
    falcon_install_token = None

    # Get all values matching Prefix path
    params_in_path_prefix = ssm_helper.get_parameters_by_path(
        ssm_param_path_prefix)

    if params_in_path_prefix.get(ccid_param):
        print(f"Using CCID from {ccid_param}")
        falcon_ccid = params_in_path_prefix[ccid_param]["Value"]

    if params_in_path_prefix.get(install_token_param):
        print(f"Using install token from {install_token_param}")
        falcon_install_token = params_in_path_prefix[install_token_param]["Value"]

    presigned_urls_expired = check_expired_presigned_url(
        platforms, params_in_path_prefix, ssm_param_path_prefix
    )

    # Create a lock and refresh if:
    # - a presigned url is missing
    # - a presigned url is expired
    # - falcon_ccid is missing
    # - falcon_install_token is None
    while presigned_urls_expired or falcon_install_token is None or falcon_ccid is None:
        # Check if a refresh is already in progress
        if params_in_path_prefix.get(lock_param):
            # Check if lock is old. A old lock means the refresh failed and we need to try again
            if is_datetime_old(
                params_in_path_prefix[lock_param]["LastModifiedDate"],
                MAX_WAIT_TIME_MINUTES,
            ):
                print(
                    f"Deleting lock it's older than {MAX_WAIT_TIME_MINUTES} minutes")
                deleted = ssm_helper.delete_refresh_lock()

                if deleted:
                    del params_in_path_prefix[lock_param]
                    continue
        else:
            # Create refresh lock
            if ssm_helper.create_refresh_lock():
                print("We have the lock, updating all required ssm parameters")

                # Update falcon_ccid if missing
                if falcon_ccid is None:
                    falcon_ccid = falcon.get_ccid()
                    ssm_helper.put_parameter(
                        ccid_param, falcon_ccid, "CrowdStrike Customer CID"
                    )

                # Update falcon_install_token if missing
                if falcon_install_token is None:
                    falcon_install_token = falcon.get_install_token()
                    ssm_helper.put_parameter(
                        install_token_param,
                        falcon_install_token,
                        "CrowdStrike Install Token",
                    )

                if presigned_urls_expired:
                    for os_name, os_versions in platforms.items():
                        os_presigned_url_path = (
                            f"{ssm_param_path_prefix}/{os_name}/presigned_urls"
                        )

                        os_presigned_url_value = {}

                        for version, api_filter in os_versions.items():
                            os_presigned_url_value[version] = falcon.get_presigned_url(
                                api_filter
                            )

                        print(
                            f"Updating presigned URLs for {os_name} to {os_presigned_url_path}"
                        )
                        ssm_helper.put_parameter(
                            name=os_presigned_url_path,
                            value=json.dumps(os_presigned_url_value),
                            description=f"Presigned URLs for {os_name}",
                        )
                        print(f"Succesfully updated {os_presigned_url_path}")

                ssm_helper.delete_refresh_lock()
                presigned_urls_expired = False
                continue

        # Sleep and then refresh state
        print(
            f"A refresh is already in progress. Waiting {WAIT_TIME_SECONDS} seconds and trying again"
        )
        time.sleep(WAIT_TIME_SECONDS)
        params_in_path_prefix = ssm_helper.get_parameters_by_path(
            ssm_param_path_prefix)
        falcon_install_token = params_in_path_prefix.get(
            install_token_param, None)
        falcon_ccid = params_in_path_prefix.get(ccid_param, None)
        presigned_urls_expired = check_expired_presigned_url(
            platforms, params_in_path_prefix, ssm_param_path_prefix
        )


platform_filters = {
    "amzn_linux": {
        "1": "os:'Amazon Linux'+os_version:'1'",
        "2": "os:'Amazon Linux'+os_version:'2'",
        "2-arm64": "os:'Amazon Linux'+os_version:'2 - arm64'",
    },
    "rhel": {
        "6": "os:'*RHEL*'+os_version:'6'",
        "7": "os:'*RHEL*'+os_version:'7'",
        "8": "os:'*RHEL*'+os_version:'8'",
        "8-arm64": "os:'*RHEL*'+os_version:'8 - arm64'",
        "9": "os:'*RHEL*'+os_version:'9'",
        "9-arm64": "os:'*RHEL*'+os_version:'9 - arm64'",
    },
    "sles": {
        "11": "os:'*SLES*'+os_version:'11'",
        "12": "os:'*SLES*'+os_version:'12'",
        "15": "os:'*SLES*'+os_version:'15'",
    },
    "ubuntu": {
        "all": "os:'*Ubuntu'+os_version:'16/18/20/22'",
        "all-arm64": "os:'Ubuntu'+os_version:'18/20/22 - arm64'",
    },
    "windows": {"all": "os:'Windows'"},
    "debian": {"all": "os:'Debian'"},
}

WAIT_TIME_SECONDS = 5
MAX_WAIT_TIME_MINUTES = 1


def script_handler(events, _):
    """Handler for executeScript action

    Args:
        events (dict): Input for the action
        _ (dict): Context for the action

    Returns:
        dict: Output for the action
    """
    # Many automation documents may be running at the same time.
    # This whole solution is written in a way so that only one document
    # at a time will be refreshing the presigned URLs.
    # This is done by using a lock in SSM Parameter Store.
    # Whichever document gets the lock will be the one to refresh the URLs.
    # However, adding this sleep will help introduce some randomness
    # in the execution of the documents.
    # We don't want to sleep for a long time so instead we will use a
    # floating point number between 1 and 5.
    random_time = round(random.uniform(1, 5), 3)
    print(f"Sleeping for {random_time} seconds")
    time.sleep(random_time)

    instances = events["instances"]
    if len(instances) == 0:
        print("No instances passed to the action")
        return

    response = compile_instance_list(instances)
    falcon_cloud_param = events["falcon_cloud"]
    falcon_client_id_param = events["falcon_client_id"]
    falcon_client_secret_param = events["falcon_client_secret"]
    ssm_param_path_prefix = validate_prefix_path(
        events["ssm_param_path_prefix"])
    region = events["region"]

    # Initialize variables
    lock_param = f"{ssm_param_path_prefix}/refresh_lock"
    ssm_helper = SSMHelper(region=region, lock_path=lock_param)
    install_token_param = f"{ssm_param_path_prefix}/InstallToken"
    ccid_param = f"{ssm_param_path_prefix}/CCID"
    falcon_client = Falcon(
        falcon_cloud_param,
        falcon_client_id_param,
        falcon_client_secret_param,
        ssm_helper,
    )

    handle_params_refresh(
        falcon_client,
        ssm_helper,
        {
            "install_token_param": install_token_param,
            "ccid_param": ccid_param,
            "lock_param": lock_param,
            "platforms": platform_filters,
            "ssm_param_path_prefix": ssm_param_path_prefix,
        },
    )

    return response


# events1 = {
#     "falcon_cloud": "/CrowdStrike/Falcon/Cloud",
#     "falcon_client_id": "/CrowdStrike/Falcon/ClientId",
#     "falcon_client_secret": "/CrowdStrike/Falcon/ClientSecret",
#     "ssm_param_path_prefix": "/CrowdStrike/Falcon",
#     "region": "us-east-1",
#     "instances": [
#         {
#             "InstanceId": "i-0c9b5b2b7b5b2b7b5",
#             "PlatformType": "Windows",
#         },
#         {
#             "InstanceId": "i-0c9b5b2b7b5b2b7b5",
#             "PlatformType": "Linux",
#         },
#     ],
# }

# print(script_handler(events1, None))
