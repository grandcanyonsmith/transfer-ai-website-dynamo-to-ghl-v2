import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple, Callable

import requests
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from boto3.dynamodb.conditions import Key
from botocore.config import Config

# ----------------------------------------
# Logging Configuration
# ----------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------------------------------
# Configuration & Constants
# ----------------------------------------
REGION_NAME = os.environ.get("REGION_NAME", "us-west-2")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "AI-temp-website-for-leads")
GHL_SECRET_NAME = os.environ.get("GHL_SECRET_NAME", "GHLAccessKey")
COMPANY_ID = os.environ.get("COMPANY_ID", "Cbjwl9dRdmiskYlzh8Oo")
SNAPSHOT_ID = "fZUMQrMLzC6PSAlSCZAQ"
SNAPSHOT_TO_FUNNEL_NAME = {"fZUMQrMLzC6PSAlSCZAQ": "gusten-sun-landing-page-light"}

USERPILOT_URL = "https://analytex.userpilot.io/v1/track"
USERPILOT_AUTH_TOKEN = "2e59172379d42c17"  # Update if needed

ZAPIER_WEBHOOK_URL = "https://hooks.zapier.com/hooks/catch/1202885/2y60ngv/"
GHL_BASE_URL = "https://services.leadconnectorhq.com"

# Validate critical environment variables
if not DYNAMODB_TABLE or not GHL_SECRET_NAME or not COMPANY_ID:
    logger.error("One or more required environment variables are missing.")
    raise RuntimeError("Missing required environment variables.")


# ----------------------------------------
# Custom Exceptions
# ----------------------------------------
class SecretRetrievalError(Exception):
    pass

class LocationNotFoundError(Exception):
    pass

class AccessTokenError(Exception):
    pass

class FunnelNotFoundError(Exception):
    pass

class DynamoItemNotFoundError(Exception):
    pass

class UserpilotEventError(Exception):
    pass


# ----------------------------------------
# Utility Functions
# ----------------------------------------
def retry_with_exponential_backoff(max_retries: int = 5, initial_delay: float = 2.0):
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            delay = initial_delay
            for attempt in range(1, max_retries + 1):
                logger.info(f"[retry_with_exponential_backoff] Attempt {attempt} with delay {delay}s.")
                try:
                    result = func(*args, **kwargs)
                    logger.info(f"[retry_with_exponential_backoff] Success on attempt {attempt}.")
                    return result
                except requests.RequestException as e:
                    status_code = e.response.status_code if e.response is not None else None
                    if status_code == 429:
                        logger.warning(f"[retry_with_exponential_backoff] 429 Too Many Requests. Retrying after {delay}s...")
                    else:
                        logger.warning(f"[retry_with_exponential_backoff] Error (Attempt {attempt}): {e}")
                    if attempt == max_retries:
                        logger.error("[retry_with_exponential_backoff] Max retries reached. Giving up.")
                        raise
                    time.sleep(delay)
                    delay *= 2
        return wrapper
    return decorator


def parse_stripe_event(event: Dict[str, Any]) -> Tuple[str, str, str]:
    logger.info("[parse_stripe_event] Parsing Stripe event.")
    try:
        body = event.get("body")
        if body:
            event_data = json.loads(body)
            data_object = event_data.get("data", {}).get("object", {})
        else:
            data_object = event.get("object", {}) or event

        customer_id = data_object.get("customer", "")
        ai_website_id = data_object.get("metadata", {}).get("ai_website_id", "")
        customer_email = data_object.get("customer_details", {}).get("email", "")

        logger.info(f"[parse_stripe_event] Extracted customer_id: {customer_id}, ai_website_id: {ai_website_id}, email: {customer_email}")
        return customer_id, ai_website_id, customer_email
    except Exception as e:
        logger.error(f"[parse_stripe_event] Error parsing event: {e}")
        raise ValueError(f"Error parsing event: {e}")


class SecretsManager:
    def __init__(self, region_name: str):
        self.client = boto3.client("secretsmanager", region_name=region_name)
    
    def get_secret(self, secret_name: str) -> str:
        logger.info(f"[get_secret] Retrieving secret: {secret_name}")
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            secret = response["SecretString"]
            logger.info("[get_secret] Secret retrieved successfully.")
            return secret
        except (ClientError, BotoCoreError) as e:
            logger.error(f"[get_secret] Unable to retrieve secret {secret_name}: {e}")
            raise SecretRetrievalError(f"Unable to retrieve secret {secret_name}: {e}")


class DynamoDBManager:
    def __init__(self, table_name: str, region_name: str):
        logger.info(f"[DynamoDBManager] Initializing for table: {table_name}")
        boto_config = Config(retries={"max_attempts": 10, "mode": "standard"})
        dynamodb_resource = boto3.resource("dynamodb", region_name=region_name, config=boto_config)
        self.table = dynamodb_resource.Table(table_name)

    def fetch_item_by_id(self, ai_website_id: str) -> Dict[str, Any]:
        logger.info(f"[DynamoDBManager] Fetching item by ai_website_id: {ai_website_id}")
        try:
            response = self.table.query(
                IndexName="id-index", KeyConditionExpression=Key("id").eq(ai_website_id)
            )
            items = response.get("Items", [])
            if not items:
                logger.warning("[DynamoDBManager] No item found.")
                raise DynamoItemNotFoundError(f"No item found with ai_website_id: {ai_website_id}")
            logger.info(f"[DynamoDBManager] Item found: {items[0]}")
            return items[0]
        except ClientError as e:
            logger.error(f"[DynamoDBManager] Error fetching item: {e}")
            raise DynamoItemNotFoundError(f"Error fetching item: {e}")


class GoHighLevelClient:
    def __init__(self, company_id: str, access_key: str):
        logger.info(f"[GoHighLevelClient] Initializing for company_id: {company_id}")
        self.company_id = company_id
        self.access_key = access_key
        self.session = requests.Session()

    def __del__(self):
        logger.debug("[GoHighLevelClient] Closing session.")
        self.session.close()

    @retry_with_exponential_backoff(max_retries=5, initial_delay=2.0)
    def get_location_access_token(self, location_id: str) -> str:
        logger.info(f"[GoHighLevelClient] Getting location access token for location_id: {location_id}")
        url = f"{GHL_BASE_URL}/oauth/locationToken"
        payload = {"companyId": self.company_id, "locationId": location_id}
        headers = {
            "Version": "2021-07-28",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.access_key}",
        }

        response = self.session.post(url, data=payload, headers=headers, timeout=60)
        response.raise_for_status()
        response_data = response.json()
        access_token = response_data.get("access_token", "")
        if not access_token:
            logger.error("[GoHighLevelClient] Access token not found in response.")
            raise AccessTokenError("No access token retrieved from GHL")
        return access_token

    def get_funnels(self, location_id: str, access_token: str) -> list:
        logger.info(f"[GoHighLevelClient] Retrieving funnels for location_id: {location_id}")
        url = f"{GHL_BASE_URL}/funnels/funnel/list"
        params = {"locationId": location_id}
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Version": "2021-07-28",
        }
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=60)
            response.raise_for_status()
            data = response.json()
            funnels = data.get("funnels", [])
            logger.info(f"[GoHighLevelClient] Retrieved {len(funnels)} funnels.")
            return funnels
        except requests.RequestException as e:
            logger.error(f"[GoHighLevelClient] Failed to get funnels: {e}")
            return []

    def check_funnel_exists(self, location_id: str, snapshot_id: str, funnel_name: str) -> bool:
        logger.info(f"[GoHighLevelClient] Checking if funnel '{funnel_name}' exists for location_id: {location_id}")
        access_token = self.get_location_access_token(location_id)
        funnels = self.get_funnels(location_id, access_token)
        if not funnels:
            logger.warning("[GoHighLevelClient] No funnels retrieved.")
            return False

        origin_ids = {
            "gusten-sun-landing-page-light": "9teLRqcJvNNffHsv3nZJ",
            "gusten-sun-dark": "q6mhTPSoAcx44KLjRZlp",
            "prelaunch-optin-sequence": "xuzX7pHHyQmCCiIdz9lP",
        }
        origin_id = origin_ids.get(funnel_name)
        if not origin_id:
            logger.error(f"[GoHighLevelClient] Origin ID not found for funnel '{funnel_name}'.")
            return False

        for funnel in funnels:
            if funnel.get("originId") == origin_id:
                logger.info(f"[GoHighLevelClient] Funnel with origin ID '{origin_id}' exists.")
                return True
        logger.info(f"[GoHighLevelClient] Funnel with origin ID '{origin_id}' does not exist.")
        return False

    def import_snapshot(self, location_id: str, snapshot_id: str) -> None:
        logger.info(f"[GoHighLevelClient] Importing snapshot '{snapshot_id}' for location_id: {location_id}")
        payload = {"locationId": location_id, "snapshotId": snapshot_id}
        try:
            response = self.session.post(ZAPIER_WEBHOOK_URL, json=payload, timeout=60)
            response.raise_for_status()
            logger.info("[GoHighLevelClient] Snapshot import triggered successfully.")
        except requests.RequestException as e:
            logger.error(f"[GoHighLevelClient] Failed to trigger snapshot import: {e}")


class CustomValueManager:
    def __init__(self, location_id: str, access_token: str):
        logger.info(f"[CustomValueManager] Initializing for location_id: {location_id}")
        self.location_id = location_id
        self.access_token = access_token
        self.headers = {
            "Version": "2021-07-28",
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.session = requests.Session()

    def __del__(self):
        logger.debug("[CustomValueManager] Closing session.")
        self.session.close()

    def get_all_custom_values(self) -> list:
        logger.info("[CustomValueManager] Retrieving all custom values.")
        url = f"{GHL_BASE_URL}/locations/{self.location_id}/customValues"
        custom_values = []
        params = {"limit": 100}
        try:
            while url:
                response = self.session.get(url, headers=self.headers, params=params, timeout=60)
                response.raise_for_status()
                data = response.json()
                new_values = data.get("customValues", [])
                custom_values.extend(new_values)
                url = data.get("nextPageUrl")
            logger.info(f"[CustomValueManager] Total custom values retrieved: {len(custom_values)}")
            return custom_values
        except requests.RequestException as e:
            logger.error(f"[CustomValueManager] Failed to get custom values: {e}")
            return []

    def update(self, custom_value_id: str, name: str, value: str) -> None:
        logger.info(f"[CustomValueManager] Updating custom value '{name}' (ID: {custom_value_id}) with value: {value}")
        url = f"{GHL_BASE_URL}/locations/{self.location_id}/customValues/{custom_value_id}"
        payload = {"name": name, "value": value}
        try:
            response = self.session.put(url, json=payload, headers=self.headers, timeout=10)
            response.raise_for_status()
            logger.info(f"[CustomValueManager] Custom value '{name}' updated successfully.")
        except requests.RequestException as e:
            logger.error(f"[CustomValueManager] Failed to update custom value '{name}': {e}")

    def create(self, name: str, value: str) -> None:
        logger.info(f"[CustomValueManager] Creating custom value '{name}' with value: {value}")
        url = f"{GHL_BASE_URL}/locations/{self.location_id}/customValues"
        payload = {"name": name, "value": value}
        try:
            response = self.session.post(url, json=payload, headers=self.headers, timeout=60)
            if response.status_code == 400 and "already exists" in response.text:
                logger.info(f"[CustomValueManager] Custom value '{name}' already exists. Attempting update.")
                self.update_existing_custom_value(name, value)
            else:
                response.raise_for_status()
                logger.info(f"[CustomValueManager] Custom value '{name}' created successfully.")
        except requests.RequestException as e:
            logger.error(f"[CustomValueManager] Failed to create custom value '{name}': {e}")

    def update_existing_custom_value(self, name: str, value: str) -> None:
        all_custom_values = self.get_all_custom_values()
        expected_field_key = f"{{{{ custom_values.{name} }}}}"
        for cv in all_custom_values:
            if cv.get("fieldKey") == expected_field_key:
                self.update(cv["id"], name, value)
                return
        logger.warning(f"[CustomValueManager] Existing custom value '{name}' not found for update.")


@retry_with_exponential_backoff(max_retries=5, initial_delay=2.0)
def get_location_id(company_id: str, customer_id: str, secret: str) -> str:
    logger.info(f"[get_location_id] Retrieving location_id for company_id: {company_id}, customer_id: {customer_id}")
    url = f"{GHL_BASE_URL}/saas-api/public-api/locations"
    headers = {
        "Authorization": f"Bearer {secret}",
        "Version": "2021-04-15",
        "channel": "OAUTH",
        "source": "INTEGRATION",
    }
    params = {"customerId": customer_id, "companyId": company_id}

    response = requests.get(url, headers=headers, params=params, timeout=60)
    response.raise_for_status()
    data = response.json()
    location_ids = data.get("data", [])
    if not location_ids:
        logger.warning("[get_location_id] No location IDs returned.")
        raise LocationNotFoundError("No location_id found for customer.")
    location_id = location_ids[0]
    logger.info(f"[get_location_id] Retrieved location_id: {location_id}")
    return location_id


@retry_with_exponential_backoff(max_retries=5, initial_delay=2.0)
def get_location_access_token(company_id: str, location_id: str, access_key: str) -> str:
    logger.info(f"[get_location_access_token] Retrieving access token for company_id: {company_id}, location_id: {location_id}")
    url = f"{GHL_BASE_URL}/oauth/locationToken"
    payload = {"companyId": company_id, "locationId": location_id}
    headers = {
        "Version": "2021-07-28",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Authorization": f"Bearer {access_key}",
    }

    response = requests.post(url, data=payload, headers=headers, timeout=60)
    response.raise_for_status()
    response_data = response.json()
    token = response_data.get("access_token", "")
    if not token:
        logger.error("[get_location_access_token] No access token retrieved.")
        raise AccessTokenError("No location access token retrieved from GHL")
    logger.info("[get_location_access_token] Access token retrieved.")
    return token


def process_custom_values(custom_value_manager: CustomValueManager, field_keys_values: Dict[str, str]) -> None:
    logger.info("[process_custom_values] Processing custom values.")
    all_custom_values = custom_value_manager.get_all_custom_values() or []
    custom_values_dict = {cv["name"]: cv for cv in all_custom_values if "name" in cv and "id" in cv}

    for field_key, new_value in field_keys_values.items():
        new_value_str = str(new_value)
        logger.debug(f"[process_custom_values] Processing field '{field_key}': {new_value_str}")
        if field_key in custom_values_dict:
            cv_id = custom_values_dict[field_key]["id"]
            custom_value_manager.update(cv_id, field_key, new_value_str)
        else:
            custom_value_manager.create(field_key, new_value_str)

    logger.info("[process_custom_values] All custom values processed.")


def send_event_to_userpilot(email: str, location_id: str, ai_website_id: str) -> None:
    logger.info(f"[send_event_to_userpilot] Sending event for email: {email}, location_id: {location_id}")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Token {USERPILOT_AUTH_TOKEN}",
        "X-API-Version": "2020-09-22",
    }

    data = {
        "user_id": email,
        "event_name": "signed_up_through_free_ai_website",
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "ai_website_id": ai_website_id,
        },
        "company": {
            "id": location_id
        }
    }

    try:
        response = requests.post(USERPILOT_URL, json=data, headers=headers, timeout=30)
        response.raise_for_status()
        logger.info("[send_event_to_userpilot] Event sent successfully.")
    except requests.RequestException as e:
        logger.error(f"[send_event_to_userpilot] Error sending event to Userpilot: {e}")


def error_response(message: str, status_code: int = 500) -> Dict[str, Any]:
    logger.error(f"[error_response] Returning error: {message} (status_code={status_code})")
    return {"statusCode": status_code, "body": json.dumps({"error": message})}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("[lambda_handler] Event received.")
    time.sleep(1)
    secrets_manager = SecretsManager(REGION_NAME)
    dynamodb_manager = DynamoDBManager(DYNAMODB_TABLE, REGION_NAME)

    try:
        customer_id, ai_website_id, customer_email = parse_stripe_event(event)

        if not customer_id or not ai_website_id:
            logger.info("[lambda_handler] Missing ai_website_id or customer_id. No action required.")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "No ai_website_id or customer_id; no action required."}),
            }

        access_key = secrets_manager.get_secret(GHL_SECRET_NAME)
        if not access_key:
            return error_response("No access key retrieved", 500)

        location_id = get_location_id(COMPANY_ID, customer_id, access_key)

        if customer_email and location_id and ai_website_id:
            send_event_to_userpilot(customer_email, location_id, ai_website_id)

        funnel_name = SNAPSHOT_TO_FUNNEL_NAME.get(SNAPSHOT_ID)
        if not funnel_name:
            return error_response("No funnel name found for snapshot", 500)

        ghl_client = GoHighLevelClient(COMPANY_ID, access_key)
        funnel_exists = ghl_client.check_funnel_exists(location_id, SNAPSHOT_ID, funnel_name)
        if not funnel_exists:
            logger.info(f"[lambda_handler] Funnel '{funnel_name}' not found. Importing snapshot.")
            ghl_client.import_snapshot(location_id, SNAPSHOT_ID)

        location_access_token = get_location_access_token(COMPANY_ID, location_id, access_key)

        item = dynamodb_manager.fetch_item_by_id(ai_website_id)

        field_keys_values = {k: str(v) for k, v in item.items()}
        custom_value_manager = CustomValueManager(location_id, location_access_token)
        process_custom_values(custom_value_manager, field_keys_values)

        logger.info("[lambda_handler] Data processed and custom values updated successfully.")
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Data processed and custom values updated successfully.",
                "field_keys_values": field_keys_values,
                "userpilot_tracking": {
                    "email": customer_email,
                    "location_id": location_id,
                    "ai_website_id": ai_website_id,
                },
            }),
        }

    except ValueError as ve:
        logger.error(f"[lambda_handler] Validation error: {ve}")
        return error_response(str(ve), 400)
    except LocationNotFoundError as le:
        logger.error(f"[lambda_handler] {le}")
        return error_response(str(le), 404)
    except DynamoItemNotFoundError as de:
        logger.error(f"[lambda_handler] {de}")
        return error_response(str(de), 404)
    except SecretRetrievalError as se:
        logger.error(f"[lambda_handler] {se}")
        return error_response("Failed to retrieve secret.", 500)
    except AccessTokenError as ae:
        logger.error(f"[lambda_handler] {ae}")
        return error_response("Failed to retrieve GHL access token.", 500)
    except Exception as e:
        logger.exception(f"[lambda_handler] Unhandled exception: {e}")
        return error_response("An unhandled error occurred.")
