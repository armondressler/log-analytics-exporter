"""
Author: armon.dressler@swisscom.com   
"""

import asyncio
from   difflib import unified_diff
import json
from   json.decoder import JSONDecodeError
import re
import traceback

import azure.functions as func
from azure.identity import DefaultAzureCredential
import aiohttp
        

CONFIG_FILE_PATH = "/data/config.json"
MANAGED_IDENTITY_TOKEN_ENDPOINT = "https://api.loganalytics.io/.default"

class Datapoint:
    """
    A Datapoint collates prometheus metric strings as a result of a LAW query.
    In case of fatal errors during execution of the query, the error attribute gets set.
    In case of minor errors which only affect a single metric/label tuple, a warning gets added to the output.
    A list (not dict) of labels can be provided. The resulting metric use this label as the label key and the value
    found in the LAW query response und said key as the label value. This requires the query to have column names which
    are valid prometheus label keys. 
    """
    def __init__(self, law_id, law_query, prometheus_metric_name, prometheus_type=None,
                 prometheus_help=None, labels: list = None, static_labels: dict = None):
        self.law_id: str = law_id
        self.law_query: str = law_query
        self.prometheus_metric_name: str = prometheus_metric_name
        self.prometheus_type: str = prometheus_type or ""
        self.prometheus_help: str = prometheus_help or ""
        self.prometheus_labels: dict = {label_key: "" for label_key in labels} if labels else {}
        self.prometheus_static_labels: dict = static_labels or {}
        self.discarded_prometheus_labels: list = []
        self.law_query_response: str = ""
        self.output: list = []
        self._error: str = ""

    def add_metric_entry(self, metric_value: str, labels: dict):
        """
        Adds a single line in form of a prometheus metric + possible labels + the metric value to the output
        """
        if not self.validate_metric_value(metric_value):
            self.add_warning_entry(f"Got a non float metric value: {metric_value}, discarded entry with labels: [{labels}]")
            return
        if labels:
            label_string = ",".join((key + '=' + '"' + value + '"' for key,value in sorted(labels.items(), key=lambda item: item[0])))
            self.output.append(f"{self.prometheus_metric_name}{{{label_string}}} {metric_value}")
        else:
            self.output.append(f"{self.prometheus_metric_name} {metric_value}")

    def add_warning_entry(self, message):
        self.output.append(f"#Warning: {message}")
    
    def prepend_help_and_type_info(self):
        self.output = [f"#HELP {self.prometheus_help}",f"#TYPE {self.prometheus_type}"] + self.output

    def validate_metric_value(self, metric_value: str):
        try:
            float(metric_value)
            return True
        except ValueError:
            return False
    
    async def update_values(self, aiohttp_session: object):
        """
        launches the query to the LAW API, parses and validates the returned data 
        and updates the output by adding metric entries
        """
        response = await self.query_law(aiohttp_session)
        if response:
            try:
                self.law_query_response = response
            except JSONDecodeError as err:
                self.error = f"Got invalid JSON structure from LAW API for query [{self.law_query}]: {response.raw}"
                return self
            return await self.parse_law_query_response()

    async def query_law(self, aiohttp_session: object):
        uri = f"https://api.loganalytics.io/v1/workspaces/{self.law_id}/query"
        params = {"query": self.law_query}
        try:
            async with aiohttp_session.get(uri, params=params) as response:
                if response.status != 200:
                    self.error = f"Bad response (code: {response.status}) from LAW API with ID {self.law_id}: {response.text()}"
                    return
                try:
                    response_body = await response.json()
                except aiohttp.client_exceptions.ContentTypeError as err:
                    self.error = f"Bad JSON from LAW API with ID {self.law_id}: {response.text()}"
                    return
        except aiohttp.client_exceptions.ClientConnectorError as err:
            self.error = f"Failed to connect to LAW API with ID {self.law_id}: {err}"
            return
        return response_body

    async def parse_law_query_response(self):
        """
        Iterate over reponse to Log Analytics Workspace query and validate
        In case of an invalid reponse (e.g. unexpected format), set the datapoint error attr and return
        Fill the output attribute of the datapoint with one or multiple properly formatted prometheus metric strings
        """
        for table in self.law_query_response.get("tables", {}):
            if "name" not in table.keys() or table.get("name") != "PrimaryResult":
                self.error = f"No PrimaryResult found in LAW response: {str(table)}"
                return self

            all_column_names = []
            for column in table.get("columns"):
                column_name = column.get("name")
                all_column_names.append(column_name)
                if not ((column_name in self.prometheus_labels or \
                        column_name == "metric")) and \
                        re.match(r"^[a-zA-Z_:][a-zA-Z0-9_:]+$", column_name):
                    self.add_warning_entry(f"Discarded LAW query response column: {column_name}, " + \
                        "reformat the LAW query to only show valid columns to prevent this warning. " + \
                        f"Based on the configuration, any label key not in [{', '.join(self.prometheus_labels)}] was filtered from the output.")
                    self.discarded_prometheus_labels.append(column_name)

            if "metric" not in all_column_names:
                self.error = "Could not find column with name: 'metric' to read metric values from. Valid columns: " + \
                                    f"{', '.join(all_column_names)}; Discarded columns: {', '.join(self.discarded_prometheus_labels)}"
                return self
            
            for query_result_row in table.get("rows"):
                row_dict = {column_name: row_value for column_name, row_value in zip(all_column_names, query_result_row) 
                            if column_name not in self.discarded_prometheus_labels}
                metric_value = row_dict.get("metric")
                labels_dict = {column_name: column_value for column_name, column_value in row_dict.items() if column_name != "metric"}
                labels_dict.update(self.prometheus_static_labels)
                self.add_metric_entry(metric_value, labels_dict)
        return self

    @property
    def error(self):
        if not self._error:
            return None
        ret_val = f"#[{self.prometheus_metric_name}] {self._error[:266]}"
        if len(self._error) > 265:
            ret_val += "... (truncated)"
        return ret_val
    
    @error.setter
    def error(self, error_message):
        self._error = error_message

    def get_metric_with_labels(self):
        return self.prometheus_metric_name

    def __str__(self):
        if self.error:
            return self.error
        else:
            self.prepend_help_and_type_info()
            return "\n".join(self.output)


def get_configuration(config_file_path: str):
    try:
        with open(config_file_path, "r") as config_file:
            config_dict = json.load(config_file)
    except (JSONDecodeError, FileNotFoundError) as err:
        raise ValueError(f"Failed to read configuration from {config_file_path}: {err}")
    return config_dict

def update_configuration(config_json: dict, config_file_path: str):
    validate_configuration(config_json)
    try:
        with open(config_file_path) as old_config_file:
            old_config_contents = json.dumps(json.load(old_config_file), indent=2, separators=(',', ': ')).splitlines()
    except FileNotFoundError:
        old_config_contents = []
    new_config_contents = json.dumps(config_json, sort_keys=True, indent=2, separators=(',', ': ')).splitlines()
    config_diff = unified_diff(old_config_contents, new_config_contents, fromfile="existing config", tofile="new config", n=0, lineterm="")
    if config_diff:
        try:
            with open(config_file_path, "w") as config_file:
                json.dump(config_json, config_file, sort_keys=True, indent=2, separators=(',', ': '))
        except OSError as err:
            raise OSError(f"Failed to write new log-analytics-exporter configuration to {config_file_path}, " + \
                "see https://docs.microsoft.com/en-us/cli/azure/webapp/config/storage-account?view=azure-cli-latest#az_webapp_config_storage_account_add " + \
                f"for information on how to add a file share mount to the function: {err}")
    return config_diff

def validate_configuration(config_json: dict):
    if not isinstance(config_json, dict):
        raise ValueError("Configuration does not contain a dictionary.")
    for law_id, datapoint_config_list in config_json.items():
        if len(law_id) != 36:
            raise ValueError(f"Log Analytics Workspace ID has bad length ({len(law_id)} .")
        if not isinstance(datapoint_config_list, list):
            raise ValueError(f"Config section for Log Analytics Workspace ID {law_id} is not a list.")
        for index, datapoint_config in enumerate(datapoint_config_list):
            if not isinstance(datapoint_config, dict):
                raise ValueError(f"Config section inside Log Analytics Workspace ID {law_id} is not a dictionary.")
            for required_attribute in ("metric", "query"):
                if required_attribute not in datapoint_config.keys():
                    raise ValueError(f"Required attribute {required_attribute} is not present within item number {index} in config section for Log Analytics Workspace ID {law_id} .")
            if datapoint_config.get("labels"):
                if not isinstance(datapoint_config.get("labels"), list):
                    raise ValueError(f"Config attribute 'labels' for item number {index} (metric: {datapoint_config.get('metric')}) in config section for Log Analytics Workspace ID {law_id} is not a list.")
                elif not all([re.match(r"^[a-zA-Z_][a-zA-Z0-9_]+$",label_name) for label_name in datapoint_config.get("labels")]):
                    raise ValueError(f"Config attribute 'labels' for item number {index} (metric: {datapoint_config.get('metric')}) in config section for Log Analytics Workspace ID {law_id} contains an invalid label, " + \
                        "see https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels for additional information.")
            if datapoint_config.get("static_labels"):
                if not isinstance(datapoint_config.get("static_labels"), dict):
                    raise ValueError(f"Config attribute 'labels' for item number {index} (metric: {datapoint_config.get('metric')}) in config section for Log Analytics Workspace ID {law_id} is not a dictionary.")
                elif not all([re.match(r"^[a-zA-Z_][a-zA-Z0-9_]+$", label_name) for label_name in datapoint_config.get("static_labels").keys()]):
                    raise ValueError(f"Config attribute 'static_labels' for item number {index} (metric: {datapoint_config.get('metric')}) in config section for Log Analytics Workspace ID {law_id} contains an invalid label, " + \
                        "see https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels for additional information.")
            valid_type_hints = ("counter", "gauge", "histogram", "summary", "untyped")
            if datapoint_config.get("type") and str(datapoint_config.get("type")) not in valid_type_hints:
                raise ValueError(f"Config attribute 'type' for item number {index} (metric: {datapoint_config.get('metric')}) in config section for Log Analytics Workspace ID {law_id} " + \
                                 f"is invalid. Allowed values are: {', '.join(valid_type_hints)}.")
            if not re.match(r"^[a-zA-Z_:][a-zA-Z0-9_:]+$", datapoint_config.get("metric")):
                raise ValueError(f"Config attribute 'metric' for item number {index} (metric: {datapoint_config.get('metric')}) in config section for Log Analytics Workspace ID {law_id} has invalid format. " + \
                     "See https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels for additional information.")


def yield_datapoints(law_id: str, datapoints: list):
    for datapoint in datapoints:
        datapoint_obj =  Datapoint(law_id,
                                   datapoint.get("query"),
                                   datapoint.get("metric"),
                                   datapoint.get("type"),
                                   datapoint.get("help"),
                                   datapoint.get("labels"),
                                   datapoint.get("static_labels"))
        yield datapoint_obj

def fetch_msi_token(token_endpoint):
    creds = DefaultAzureCredential()
    law_tokenobject = creds.get_token(token_endpoint)
    token = law_tokenobject.token
    return token

async def collate_metrics():
    metric_list = []
    datapoint_list = []
    task_list = []
    token = fetch_msi_token(MANAGED_IDENTITY_TOKEN_ENDPOINT)
    config_dict = get_configuration(CONFIG_FILE_PATH)
    for law_id, datapoints_config_list in config_dict.items():
        for datapoint in yield_datapoints(law_id, datapoints_config_list):
            datapoint_list.append(datapoint)
    async with aiohttp.ClientSession(headers={'Authorization': f"Bearer {token}", "Content-Type": "application/json"}) as session:
        for datapoint in datapoint_list:
            task_list.append(asyncio.ensure_future(datapoint.update_values(session)))
        datapoint_list = await asyncio.gather(*task_list)
    metric_list = [ str(datapoint) for datapoint in datapoint_list ]
    if not metric_list:
        return f"#No metrics due to empty CONFIG env var"
    return "\n".join(metric_list)
        
def main(req: func.HttpRequest) -> func.HttpResponse:
    request_path = req.route_params.get("path")
    if request_path == "metrics":
        if req.method.lower() != "get":
            return func.HttpResponse(status_code=405)
        try:
            metrics_string = asyncio.run(collate_metrics())
        #this is hardly best practice, but Azure Insights doesnt even show me log data, so the exception trace is my only hope
        except Exception as err:
            return func.HttpResponse(f"Fatal error during execution: {traceback.format_exc()}", status_code=500, mimetype="text/plain")
        return func.HttpResponse(f"{metrics_string}", status_code=200, mimetype="text/plain")
    elif request_path == "config":
        if req.method.lower() != "post":
            return func.HttpResponse(status_code=405)
        try:
            config_data = req.get_json()
        except ValueError:
            return func.HttpResponse(f"Invalid JSON found in body", status_code=400, mimetype="text/plain")
        try:
            config_diff = "\n".join(list(update_configuration(config_data, CONFIG_FILE_PATH)))
        except ValueError as err:
            return func.HttpResponse(f"Failed to write invalid configuration: {err}", status_code=400, mimetype="text/plain")
        except OSError as err:
            return func.HttpResponse(f"{err}", status_code=500, mimetype="text/plain")
        
        response = json.dumps({"changed":bool(config_diff),
                               "diff":f"{config_diff}",
                               "info":f"Wrote new configuration to {CONFIG_FILE_PATH}" if config_diff else "No changes applied to existing configuration."},
                               sort_keys=True, indent=2, separators=(',', ': '))
        return func.HttpResponse(response, status_code=201, mimetype="application/json")
