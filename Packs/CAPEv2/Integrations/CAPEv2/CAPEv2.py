import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import tarfile
import os


class Client(BaseClient):
    def __init__(self, base_url, *args, **kwarg):
        super().__init__(base_url, *args, **kwarg)

    # Override the default handler with this one?
    def simple_error_handler(self, res):
        if res.status_code == 403:
            return_error(f"Rate limit reached: [{res.status_code}] - {res.text}")
        if res.status_code > 500:
            return_error(f"Gateway error: [{res.status_code}] - {res.text}")
        else:
            return_error(f"Error in API call [{res.status_code}] - {res.text}")


def test_module(client: Client) -> str:

    r = client._http_request(
        "GET", "api/cuckoo/status/", error_handler=client.simple_error_handler
    )

    return "ok"


def submit_file(client: Client, **args) -> CommandResults:

    file_path = demisto.getFilePath(args.get("entry-id")).get("path")
    with open(file_path, "rb") as f:
        # TODO: Add in optional file name
        files = {
            "file": f,
            "machine": (None, args.get("vm-name")),
        }

        r = client._http_request(
            "POST",
            "api/tasks/create/file/",
            files=files,
            error_handler=client.simple_error_handler,
        )

    formatted_data = r.get("data")
    formatted_data["url"] = r.get("url")

    results = CommandResults(
        outputs_prefix="CAPE.submissions",
        outputs_key_field="data",
        outputs=formatted_data,
    )

    return results


def submit_url(client: Client, **args) -> CommandResults:

    url = args.get("url")

    files = {
        "url": (None, url),
    }

    r = client._http_request(
        "POST",
        "api/tasks/create/url/",
        files=files,
        error_handler=client.simple_error_handler,
    )

    formatted_data = r.get("data")
    formatted_data["url"] = r.get("url")

    results = CommandResults(
        outputs_prefix="CAPE.submissions",
        outputs_key_field="data",
        outputs=formatted_data,
    )

    return results


def view_sample(client: Client, **args) -> CommandResults:
    """
    :param client:
    :param args:
        - id_type is md5, sha1, sha256, id
        - id is the hash or sample id
    :return:
    """
    id_type = args.get("id_type")
    id = args.get("id")

    r = client._http_request(
        "GET",
        f"api/files/view/{id_type}/{id}/",
        error_handler=client.simple_error_handler,
    )

    results = CommandResults(
        outputs_prefix="CAPE.submissions",
        outputs_key_field="data",
        outputs=r.get("data"),
    )

    return results


def basic_task_search(client: Client, **args) -> CommandResults:
    """
    :param client:
    :param args:
        - id_type is md5, sha1, sha256
        - id is the hash of the sample
    :return:
    """

    id_type = args.get("id_type").lower()
    id = args.get("id")

    r = client._http_request(
        "GET",
        f"api/tasks/search/{id_type}/{id}/",
        error_handler=client.simple_error_handler,
    )

    results = CommandResults(
        outputs_prefix="CAPE.submissions",
        outputs_key_field="data",
        outputs=r.get("data", r),
    )

    return results


def extended_task_search(client: Client, **args) -> CommandResults:
    """
    :param client:
    :param args:
        Searchable Options List:
        id : Task id
        name : Name of target file name
        type : Name of file type
        string : Match a string in the static analysis section
        ssdeep : Match an ssdeep hash
        crc32 : Match a CRC32 hash
        file : Match a file in the behavioral analysis summary
        command : Match an executed command
        resolvedapi : Match an API that a sample resolved
        key : Match a registry key in the behavioral analysis summary
        mutex : Match a mutex in the behavioral analysis summary
        domain : Match a resolved domain
        ip : Match a contacted IP Address
        signature : Match a Cuckoo signature description
        signame : Match a Cuckoo signature name
        detections: Match samples associated with malware family
        url : Match a URL target task (submitted URL task)
        imphash : Match an import hash
        iconhash: Match the exact hash of the icon associated with the PE
        iconfuzzy: Match a hash designed to match on similar-looking icons
        surialert : Match a suricata alert signature
        surihttp : Match suricata HTTP data
        suritls : Match suricata TLS data
        clamav : Match a Clam AV signature
        yaraname : Match a Yara signature name
        virustotal : Match a virustotal AV Signature
        comment : Match a comment posted to a specific task
        md5 : Targets with a specific MD5 hash
        sha1 : Targets with a specific SHA1 hash
        sha256 : Targets with a specific SHA256 hash
        sha512 : Targets with a specific SHA512 hash
        TTP: TTP number
    :return:
    """

    options = [
        "id",
        "name",
        "type",
        "string",
        "ssdeep",
        "crc32",
        "file",
        "command",
        "resolvedapi",
        "key",
        "mutex",
        "domain",
        "ip",
        "signature",
        "signame",
        "detections",
        "url",
        "imphash",
        "iconhash",
        "iconfuzzy",
        "surialert",
        "surihttp",
        "suritls",
        "clamav",
        "yaraname",
        "virustotal",
        "comment",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "TTP",
    ]

    query = {k: v for k, v in args.items() if k in options}

    r = client._http_request(
        "POST",
        "api/tasks/extendedsearch/",
        params=query,
        error_handler=client.simple_error_handler,
    )

    results = CommandResults(
        outputs_prefix="CAPE.submissions", outputs_key_field="data", outputs=r
    )

    return results


def task_lists(client: Client, **args) -> CommandResults:
    # curl https://www.capesandbox.com/api/tasks/list/
    # curl https://www.capesandbox.com/api/tasks/list/[limit]/ (specify a limit of tasks to return)
    # curl https://www.capesandbox.com/api/tasks/list/[limit]/[offset]/ (specify a limit of tasks to return, offset by a specific amount)
    # Accepts as params status to check for status and/or option to search by option LIKE

    limit = args.get("limit")
    offset = args.get("offset")

    uri = "api/tasks/list/"
    if limit:
        uri += f"{limit}/"
    if limit and offset:
        uri += f"{offset}/"
    if offset and not limit:
        return_error("Must provide limit when providing offset")

    r = client._http_request("GET", uri, error_handler=client.simple_error_handler)

    results = CommandResults(
        outputs_prefix="CAPE.submissions",
        outputs_key_field="data",
        outputs=r.get("data"),
    )

    return results


def task_view(client: Client, **args) -> CommandResults:
    task_id = args.get("task_id")

    r = client._http_request(
        "GET", f"api/tasks/view/{task_id}/", error_handler=client.simple_error_handler
    )

    results = CommandResults(
        outputs_prefix="CAPE.submissions",
        outputs_key_field="data",
        outputs=r.get("data"),
    )

    return results


def download_sample(client: Client, **args) -> CommandResults:
    id = args.get("id")
    id_type = args.get("id_type").lower()

    r = client._http_request(
        "GET",
        f"/api/files/get/{id_type}/{id}/",
        resp_type="content",
        error_handler=client.simple_error_handler,
    )

    return fileResult(f'Sample-{id}.bin', r)


def sample_config(client: Client, **args) -> CommandResults:
    task_id = args.get("task_id")

    r = client._http_request(
        "GET",
        f"api/tasks/get/config/{task_id}/",
        error_handler=client.simple_error_handler,
    )

    results = CommandResults(
        outputs_prefix="CAPE.submissions",
        outputs_key_field="data",
        outputs=r.get("configs", r),
    )

    return results


def pcap_file(client: Client, **args) -> fileResult:

    task_id = args.get("task_id")

    r = client._http_request(
        "GET",
        f"/api/tasks/get/pcap/{task_id}/",
        resp_type="content",
        error_handler=client.simple_error_handler,
    )

    return fileResult(f"cape-pcap-{task_id}.pcap", r)


def surifiles(client: Client, **args) -> CommandResults:
    task_id = args.get("task_id")
    resp = client._http_request(
        "GET",
        f"/api/tasks/get/surifile/{task_id}/",
        error_handler=client.simple_error_handler,
    )

    results = CommandResults(
        outputs_prefix="CAPE.surifiles", outputs_key_field="", outputs=resp
    )

    return results


def get_task_iocs(client: Client, **args) -> CommandResults:
    task_id = args.get("task_id")
    detailed = args.get("detailed")

    uri = f"/api/tasks/get/iocs/{task_id}"
    if detailed:
        uri += f"/{detailed}/"
    resp = client._http_request(
        "GET",
        f"/api/tasks/get/iocs/{task_id}/detailed/",
        error_handler=client.simple_error_handler,
    )
    tabled_data = tableToMarkdown(
        "IOC_TABLE",
        {
            "Detections": resp.get("detections", " "),
            "Malware Score": resp.get("malscore", " "),
        },
    )

    results = CommandResults(
        outputs_prefix="CAPE.iocs",
        outputs_key_field="data",
        outputs=resp.get("data"),
        raw_response=resp,
        readable_output=tabled_data,
    )

    return results


def get_task_status(client: Client, **args) -> CommandResults:
    task_id = args.get("task_id")
    resp = client._http_request(
        "GET",
        f"/api/tasks/status/{task_id}/",
        error_handler=client.simple_error_handler,
    )

    if "data" in resp:
        results = CommandResults(
            outputs_prefix="CAPE.TaskStatus",
            outputs_key_field="data",
            outputs={"task_id": task_id, "status": resp.get(["data"])},
            raw_response=resp,
            readable_output=tableToMarkdown("Status", {"Status": resp["data"]}),
        )
    else:
        return_error(f"Error occurred: {json.loads(resp)}")

    return results


def get_task_dropped_files(client: Client, **args):
    task_id = args.get("task_id")
    resp = client._http_request(
        "GET",
        f"/api/tasks/get/dropped/{task_id}/",
        resp_type="requests",
        error_handler=client.simple_error_handler,
    )

    if resp.headers['Content-Type'] == 'application/octet-stream;':
        return fileResult(f"cape-dropped-{task_id}.tar.bz2", resp.content)
    else:
        return f'Task {task_id} did not have any dropped files'


def get_task_screenshots(client: Client, **args) -> list:
    """
    API returns a bz2 containing all screenshots. Function extracts and iterates over all files and returns them to war room
    :param client:
    :param args:
    :return:
    """
    task_id = args.get("task_id")
    resp = client._http_request(
        "GET",
        f"/api/tasks/get/screenshot/{task_id}/",
        resp_type="content",
        error_handler=client.simple_error_handler,
    )
    with open(f"{task_id}-screenshots.tar.bz2", "wb") as f:
        f.write(resp)

    with tarfile.open(f"{task_id}-screenshots.tar.bz2", "r:bz2") as tar:
        tar.extractall()

    file_results = []
    for filename in os.listdir(os.getcwd()):
        if filename.endswith(".jpg") or filename.endswith(".jpeg"):
            with open(filename, "rb") as f:
                # file_results.append(fileResult(filename, f.read()))
                file_results.append(CommandResults())
        else:
            continue

    return file_results


def get_virtual_machine_list(client: Client, **args) -> CommandResults:
    resp = client._http_request("GET", "/api/machines/list/")
    if "data" in resp:
        results = CommandResults(
            outputs_prefix="CAPE.VM-list",
            outputs_key_field="",
            outputs=resp,
            raw_response=resp,
            readable_output=tableToMarkdown("Available VM's", resp["data"]),
        )
    else:
        return_error("Error occurred " + json.loads(resp))
    return results


def get_vm_view(client: Client, **args):
    vm_name = args.get("vm_name")
    resp = client._http_request("GET", f"/api/machines/view/{vm_name}")
    if "data" in resp:
        results = CommandResults(
            outputs_prefix="CAPE.VM-view",
            outputs_key_field="",
            outputs=resp,
            raw_response=resp,
            readable_output=tableToMarkdown("VM View", resp["data"]),
        )
    else:
        return_error("Error occurred " + json.loads(resp))
    return results


def main():
    params = demisto.params()
    args = demisto.args()
    client = Client(params.get("base_url"), verify=params.get("Verify SSL"))

    commands = {
        "test-module": test_module,
        "cape-submit-file": submit_file,
        "cape-submit-url": submit_url,
        "cape-view-sample": view_sample,
        "cape-basic-task-search": basic_task_search,
        "cape-ext-task-search": extended_task_search,
        "cape-task-lists": task_lists,
        "cape-task-view": task_view,
        "cape-download-sample": download_sample,
        "cape-get-sample-config": sample_config,
        "cape-get-pcap": pcap_file,
        "cape-get-surifiles": surifiles,
        "cape-task-iocs": get_task_iocs,
        "cape-task-status": get_task_status,
        "cape-get-dropped-files": get_task_dropped_files,
        "cape-get-screenshots": get_task_screenshots,
        "cape-vm-list": get_virtual_machine_list,
        "cape-vm-view": get_vm_view,
    }

    command = demisto.command()
    if command in commands:
        return_results(commands[command](client, **args))
    else:
        return_error(f"Command {command} is not available in this integration")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    # TODO - Cleanup CommandResults in each function
    main()
