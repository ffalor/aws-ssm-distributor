"""Module test"""

import http.client
from lib2to3.pgen2.token import DOT
from re import T
import urllib.parse
import time
from datetime import datetime, timedelta
import json
from dateutil import tz
import boto3
from numpy import delete

# possible key paths
# prefix/windows/presigned_urls
# prefix/debian/presigned_urls
# prefix/amzn_linux/presigned_urls
# {
#     "1": "value",
#     "2": "value",
#     "2-arm64": "value",
# }
# prefix/sles/presigned_urls
# {
#     "11": "value",
#     "12": "value",
#     "15": "value"
# }
# prefix/ubuntu/presigned_urls
# {
#     "16/18/20/22": "value",
#     "18/20/22-arm64": "value",
# }
# prefix/rhel/presigned_urls
# {
#     "6": "value",
#     "7": "value",
#     "8": "value",
#     "8-arm64": "value",
#     "9": "value",
#     "9-arm64": "value",
# }


class CrowdStrikeAPIError(Exception):
    """Crowdstrike API error"""


class Falcon:
    """Crowdstrike Falcon API class"""

    def __init__(self, cloud, client_id, client_secret, bearer_token=None):
        self.cloud = cloud
        self.client_id = client_id
        self.client_secret = client_secret
        self.user_agent = "crowdstrike-official-distributor-package/v1.0.0"
        self.bearer_token = bearer_token

    def _oauth(self):
        """Creates OAuth bearer token


        Returns:
            token (str): OAuth bearer token

        Raises:
            CrowdStrikeAPIError: If the API call fails
        """
        print("Requesting Authentication token from Crowdstrike backend.")

        params = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
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
            raise CrowdStrikeAPIError(
                f"Received non success response {install_token_query_resp.status} while fetching token. Error {install_token_query_resp.reason}"
            )

        install_token_query_data = install_token_query_resp.read()
        resources = json.loads(install_token_query_data)["resources"]
        if len(resources) == 0:
            print("No Installation token found, skipping")
            return None

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
            f"/sensors/combined/signed-urls/v1?limit=1&filter={api_filter}",
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
        print("Successfully received presigned URL")
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

    def put_parameter(self, Name, Value, Description, ParamType="String", Overwrite=True):
        """Put a SSM parameter

        Args:
            Name (str): Path to the SSM parameter
            Value (str): Value of the SSM parameter
            Description (str): Description of the SSM parameter
            ParamType (str, optional): Type of the SSM parameter. Defaults to "String".
            Overwrite (bool, optional): Whether to overwrite the SSM parameter. Defaults to True.
        """
        self.client.put_parameter(
            Name=Name,
            Value=Value,
            Description=Description,
            Type=ParamType, # type: ignore
            Overwrite=Overwrite,
        )

    def get_parameter(self, path):
        """Get a SSM parameter by path and return value.

        Args:
            path (str): Path to the SSM parameter
        """

        response = self.client.get_parameter(
            Name=path,
            WithDecryption=True,
        )

        return response["Parameter"]["Value"]

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
        paginator = self.client.get_paginator("get_parameters_by_path")

        response = {}

        for page in paginator.paginate(Path=path, WithDecryption=True, Recursive=True):
            for parameter in page["Parameters"]:
                response[parameter["Name"]] = parameter

        return response

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
                    Name=self.lock_path,
                    Value="true",
                    Description="Refresh lock for CrowdStrike Distributor",
                    Overwrite=False,
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
                return
            except self.client.exceptions.ParameterNotFound:
                print(f"Refresh lock parameter {self.lock_path} not found")
                return
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


platform_filters = {
    #TODO: Add debian
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
    response = compile_instance_list(events["instances"])
    falcon_cloud_param_name = events["falcon_cloud"]
    falcon_client_id_param_name = events["falcon_client_id"]
    falcon_client_secret_param_name = events["falcon_client_secret"]
    ssm_param_path_prefix = validate_prefix_path(
        events["ssm_param_path_prefix"])
    region = events["region"]

    # Initialize variables
    lock_param_name = f"{ssm_param_path_prefix}/refresh_lock"
    ssm_helper = SSMHelper(region=region, lock_path=lock_param_name)
    falcon_cloud = None
    falcon_client_id = None
    falcon_client_secret = None
    falcon_ccid = None
    falcon_install_token = None
    install_token_param_name = f"{ssm_param_path_prefix}/InstallToken"
    ccid_param_name = f"{ssm_param_path_prefix}/CCID"

    # Get all values matching Prefix path
    params_in_path_prefix = ssm_helper.get_parameters_by_path(
        ssm_param_path_prefix)

    if params_in_path_prefix.get(ccid_param_name):
        print(f"Using CCID from {ccid_param_name}")
        falcon_ccid = params_in_path_prefix[ccid_param_name]["Value"]

    if params_in_path_prefix.get(install_token_param_name):
        print(f"Using install token from {install_token_param_name}")
        falcon_install_token = params_in_path_prefix[install_token_param_name]["Value"]

    need_refresh = check_expired_presigned_url(
        platform_filters, params_in_path_prefix, ssm_param_path_prefix
    )

    while need_refresh:
        # check if a refresh is already in progress
        if params_in_path_prefix.get(lock_param_name):
            # check if lock is old. A old lock means the refresh failed and we need to try again
            if is_datetime_old(
                params_in_path_prefix[lock_param_name]["LastModifiedDate"],
                MAX_WAIT_TIME_MINUTES,
            ):
                print(
                    f"Deleting lock it's older than {MAX_WAIT_TIME_MINUTES} minutes")
                ssm_helper.delete_refresh_lock()
                del params_in_path_prefix[lock_param_name]
                continue
        else:
            # Create refresh lock
            if ssm_helper.create_refresh_lock():
                print("We have the lock, updating all required ssm parameters")

                falcon_cloud = (
                    ssm_helper.get_parameter(falcon_cloud_param_name)
                    .replace("https://", "")
                    .replace("http://", "")
                )

                falcon_client_id = ssm_helper.get_parameter(
                    falcon_client_id_param_name)

                falcon_client_secret = ssm_helper.get_parameter(
                    falcon_client_secret_param_name)

                falcon = Falcon(
                    cloud=falcon_cloud,
                    client_id=falcon_client_id,
                    client_secret=falcon_client_secret,
                )

                # Create CCID and Install Token if they don't exist
                if not falcon_ccid or not falcon_install_token:
                    if not falcon_ccid:
                        falcon_ccid = falcon.get_ccid()

                        ssm_helper.put_parameter(
                            ccid_param_name,
                            falcon_ccid,
                            "CrowdStrike Customer CID"
                        )

                    if not falcon_install_token:
                        falcon_install_token = falcon.get_install_token()
                        if falcon_install_token:
                            ssm_helper.put_parameter(
                                install_token_param_name,
                                falcon_install_token,
                                "CrowdStrike Install Token"
                            )

                for os_name, os_versions in platform_filters.items():
                    os_presigned_url_path = (
                        f"{ssm_param_path_prefix}/{os_name}/presigned_urls"
                    )

                    os_presigned_url_value = {}

                    for version, api_filter in os_versions.items():
                        print(f"Getting presigned URL for {os_name} {version}")
                        os_presigned_url_value[version] = falcon.get_presigned_url(
                            api_filter
                        )

                    print(
                        f"Saving presigned URLs for {os_name} to {os_presigned_url_path}"
                    )
                    ssm_helper.put_parameter(
                        Name=os_presigned_url_path,
                        Value=json.dumps(os_presigned_url_value),
                        Description=f"Presigned URLs for {os_name}"
                    )

                ssm_helper.delete_refresh_lock()
                need_refresh = False
                continue

        # Check if we still need to refresh
        params_in_path_prefix = ssm_helper.get_parameters_by_path(
            ssm_param_path_prefix)
        need_refresh = check_expired_presigned_url(
            platform_filters, params_in_path_prefix, ssm_param_path_prefix
        )
        print(
            f"A refresh is already in progress. Waiting {WAIT_TIME_SECONDS} seconds and trying again"
        )
        time.sleep(WAIT_TIME_SECONDS)

    response["falcon_cloud"] = falcon_cloud
    response["falcon_ccid"] = falcon_ccid
    response["falcon_install_token"] = falcon_install_token

    return response


events1 = {
    "falcon_cloud": "/CrowdStrike/Falcon/Cloud",
    "falcon_client_id": "/CrowdStrike/Falcon/ClientId",
    "falcon_client_secret": "/CrowdStrike/Falcon/ClientSecret",
    "ssm_param_path_prefix": "/CrowdStrike/Falcon",
    "region": "us-east-1",
    "instances": [
        {
            "InstanceId": "i-0c9b5b2b7b5b2b7b5",
            "PlatformType": "Windows",
        },
        {
            "InstanceId": "i-0c9b5b2b7b5b2b7b5",
            "PlatformType": "Linux",
        },
    ],
}

print(script_handler(events1, None))
