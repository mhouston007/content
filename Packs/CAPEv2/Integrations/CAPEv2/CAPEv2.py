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
            return_error(f'Rate limit reached: [{res.status_code}] - {res.text}')
        if res.status_code > 500:
            return_error(f'Gateway error: [{res.status_code}] - {res.text}')
        else:
            return_error(f'Error in API call [{res.status_code}] - {res.text}')



def test_module(client: Client) -> str:

    r = client._http_request('GET', 'api/cuckoo/status/', error_handler=client.simple_error_handler)

    return 'ok'


# Working
def submit_file(client: Client, **args) -> CommandResults:

    file_path = demisto.getFilePath(args.get('entry-id')).get('path')
    with open(file_path, 'rb') as f:
        # TODO: Add in optional file name
        files = {
            'file': f,
            'machine': (None, args.get('vm-name')),
        }

        r = client._http_request('POST', 'api/tasks/create/file/', files=files, error_handler=client.simple_error_handler)

    formatted_data = r.get('data')
    formatted_data['url'] = r.get('url')

    results = CommandResults(
        outputs_prefix='CAPE.submissions',
        outputs_key_field='data',
        outputs=formatted_data
    )

    return results


# Need to setup own instance to config the VT key on the server in order to test
# def vt_download_analyze(client: Client, **args) -> CommandResults:
#
#     # Use a param instead of an arg for the api key?
#     vt_key = args.get('VT_API_Key')
#     hash = args.get('hash')
#     vm_name = args.get('VM_Name')
#
#     files = {
#         'vtdl': (None, hash),
#         'machine': (None, vm_name),
#         'apikey': (None, vt_key),
#     }
#
#     r = client._http_request('POST', 'api/tasks/create/vtdl/', files=files)
#
#     results = CommandResults(
#         outputs_prefix='CAPE.submissions',
#         outputs_key_field='data',
#         outputs=r
#     )
#
#     return results


# Working
def submit_url(client: Client, **args) -> CommandResults:

    url = args.get('url')

    files = {
        'url': (None, url),
    }

    r = client._http_request('POST', 'api/tasks/create/url/', files=files, error_handler=client.simple_error_handler)

    formatted_data = r.get('data')
    formatted_data['url'] = r.get('url')

    results = CommandResults(
        outputs_prefix='CAPE.submissions',
        outputs_key_field='data',
        outputs=formatted_data
    )

    return results

# Working
def view_sample(client: Client, **args) -> CommandResults:
    '''
    :param client:
    :param args:
        - id_type is md5, sha1, sha256, id
        - id is the hash or sample id
    :return:
    '''
    id_type = args.get('id_type')
    id = args.get('id')

    r = client._http_request('GET', f'api/files/view/{id_type}/{id}/', error_handler=client.simple_error_handler)

    results = CommandResults(
        outputs_prefix='CAPE.submissions',
        outputs_key_field='data',
        outputs=r.get('data')
    )

    return results


# Working
def basic_task_search(client: Client, **args) -> CommandResults:
    '''
    :param client:
    :param args:
        - id_type is md5, sha1, sha256
        - id is the hash of the sample
    :return:
    '''

    id_type = args.get('id_type').lower()
    id = args.get('id')

    r = client._http_request('GET', f'api/tasks/search/{id_type}/{id}/', error_handler=client.simple_error_handler)

    results = CommandResults(
        outputs_prefix='CAPE.submissions',
        outputs_key_field='data',
        outputs=r.get('data', r)
    )

    return results


# TODO
# Finish and test
def extended_task_search(client: Client, **args) -> CommandResults:
    '''
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
    '''

    options = ["id","name","type","string","ssdeep","crc32","file","command","resolvedapi","key","mutex","domain",
               "ip","signature","signame","detections","url","imphash","iconhash","iconfuzzy","surialert","surihttp",
               "suritls","clamav","yaraname","virustotal","comment","md5","sha1","sha256","sha512","TTP"]

    query = {k:v for k,v in args.items() if k in options}

    # response = requests.post('https://www.capesandbox.com/api/tasks/extendedsearch/', data=data)
    r = client._http_request('POST', 'api/tasks/extendedsearch/', params=query, error_handler=client.simple_error_handler)

    results = CommandResults(
        outputs_prefix='CAPE.submissions',
        outputs_key_field='data',
        outputs=r
    )

    return results


# Working
def task_lists(client: Client, **args) -> CommandResults:
    # curl https://www.capesandbox.com/api/tasks/list/
    # curl https://www.capesandbox.com/api/tasks/list/[limit]/ (specify a limit of tasks to return)
    # curl https://www.capesandbox.com/api/tasks/list/[limit]/[offset]/ (specify a limit of tasks to return, offset by a specific amount)
    # Accepts as params status to check for status and/or option to search by option LIKE

    limit = args.get('limit')
    offset = args.get('offset')

    uri = 'api/tasks/list/'
    if limit:
        uri += f'{limit}/'
    if limit and offset:
        uri += f'{offset}/'
    if offset and not limit:
        return_error('Must provide limit when providing offset')

    r = client._http_request('GET', uri, error_handler=client.simple_error_handler)

    results = CommandResults(
        outputs_prefix='CAPE.submissions',
        outputs_key_field='data',
        outputs=r.get('data')
    )

    return results


# Working
def task_view(client: Client, **args) -> CommandResults:
    # curl https://www.capesandbox.com/api/tasks/view/[task id]/

    task_id = args.get('task_id')

    r = client._http_request('GET', f'api/tasks/view/{task_id}/', error_handler=client.simple_error_handler)

    results = CommandResults(
        outputs_prefix='CAPE.submissions',
        outputs_key_field='data',
        outputs=r.get('data')
    )

    return results


# Gateway error
def download_sample(client: Client, **args) -> CommandResults:
    id = args.get('id')
    id_type = args.get('id_type')

    print(f'https://www.capesandbox.com/api/files/get/{id_type}/{id}/')

    r = client._http_request('GET', f'https://www.capesandbox.com/api/files/get/{id_type}/{id}/', resp_type='content',
                             error_handler=client.simple_error_handler)

    print(r)

    # return fileResult(f'SAMPLE-{id}.bin', r)
    return None

# Working
def sample_config(client: Client, **args) -> CommandResults:
    task_id = args.get('task_id')

    r = client._http_request('GET', f'api/tasks/get/config/{task_id}/', error_handler=client.simple_error_handler)

    results = CommandResults(
        outputs_prefix='CAPE.submissions',
        outputs_key_field='data',
        outputs=r.get('configs', r)
    )

    return results


# Test, keep getting bad gateway error
def payload_files(client: Client, **args) -> fileResult:
    task_id = args.get('task_id')

    r = client._http_request('GET', f'api/tasks/get/payloadfiles/{task_id}/', resp_type='content',
                            error_handler=client.simple_error_handler)

    return fileResult(f'cape-payload-{task_id}', r)


# Need to test and find a PID with a dump file
def procmemory_dump(client: Client, **args) -> CommandResults:
    '''
    Doesn't want to pull the file, give 200 response but JSON contains error message
    Can download from: https://capesandbox.com/file/procdump/65532/5c632fe667d4f8c4c4ae5aa7df34a0c7f816a149b8b917d1a3da57ff7dace9df/
    :param client:
    :param args:
    :return:
    '''
    task_id = args.get('task_id')
    pid = args.get('pid')

    uri = f'api/tasks/get/procmemory/{task_id}/'
    if pid:
        uri += f'{pid}/'

    r = client._http_request('GET', uri, resp_type='content',
                            error_handler=client.simple_error_handler)

    return fileResult(f'cape-procmemory-dump-{task_id}', r)


# Test, keep getting bad gateway error
def procdump_files(client: Client, **args) -> fileResult:
    task_id = args.get('task_id')

    r = client._http_request('GET', f'api/tasks/get/procdumpfiles/{task_id}/', resp_type='content',
                            error_handler=client.simple_error_handler)

    return fileResult(f'cape-procdump-{task_id}', r)


# Working
def pcap_file(client: Client, **args) -> fileResult:

    task_id = args.get('task_id')

    r = client._http_request('GET', f'/api/tasks/get/pcap/{task_id}/', resp_type='content', error_handler=client.simple_error_handler)

    return fileResult(f'cape-pcap-{task_id}.pcap', r)


def surifiles(client: Client, **args) -> CommandResults:
    task_id = demisto.getArg("task_id")
    resp = client._http_request('GET', f'/api/tasks/get/surifile/{task_id}/',
                                error_handler=client.simple_error_handler)

    results = CommandResults(
        outputs_prefix='CAPE.surifiles',
        outputs_key_field='',
        outputs=resp
    )

    return results


def get_task_iocs(client: Client, **args) -> CommandResults:
    # curl https://www.capesandbox.com/api/tasks/get/iocs/[task id]/
    # curl https://www.capesandbox.com/api/tasks/get/iocs/[task id]/detailed/
    task_id = demisto.getArg("task_id")
    resp = client._http_request('GET', f'/api/tasks/get/iocs/{task_id}/detailed/', error_handler=client.simple_error_handler)
    tabled_data = tableToMarkdown(
        "IOC_TABLE",
        {
            "Detections":resp.get("detections"," "),
            "Malware Score":resp.get("malscore"," ")
        }
    )

    results = CommandResults(
        outputs_prefix='CAPE.iocs',
        outputs_key_field='data',
        outputs=resp.get('data'),
        raw_response=resp,
        readable_output=tabled_data
    )

    return results

    # Map this to CommandResults
    # demisto.results({
    #     "ContentsFormat":formats["markdown"], # readable_output
    #     "HumanReadable":tabled_data, # readable_output
    #     "ReadableContentsFormat": formats['markdown'],
    #     "IgnoreAutoExtract":True,
    #     "Type":entryTypes["note"],
    #     "Contents":resp # outputs
    # })


def get_task_status(client: Client, **args) -> CommandResults:
    #curl https://www.capesandbox.com/api/tasks/status/[task id]/
    task_id = demisto.getArg("task_id")
    resp = client._http_request('GET', f'/api/tasks/status/{task_id}/', error_handler=client.simple_error_handler)

    if "data" in resp:
        results = CommandResults(
            outputs_prefix='CAPE.TaskStatus',
            outputs_key_field='data',
            outputs={
                "task_id":task_id,
                "status":resp.get(["data"])
            },
            raw_response=resp,
            readable_output=tableToMarkdown("Status",{"Status":resp["data"]})
        )

        # Map to CommandResults
        # demisto.results({
        #     "ContentsFormat":formats["markdown"],
        #     "HumanReadable":tableToMarkdown("Status",{"Status":resp["data"]}),
        #     "ReadableContentsFormat": formats['markdown'],
        #     "IgnoreAutoExtract":True,
        #     "Type":entryTypes["note"],
        #     "EntryContext":{"Cape.TaskStatus":{
        #         "task_id":task_id,
        #         "status":resp["data"]
        #     }},
        #     "Contents":resp
        # })
    else:
        return_error(f'Error occurred: {json.loads(resp)}')

    return results


# TESTING
# Not working - seems to be issue with the CAPE server itself
def get_task_dropped_files(client: Client, **args) -> fileResult:
    #curl https://www.capesandbox.com/api/tasks/get/dropped/[task id]/
    task_id = demisto.getArg("task_id")
    # return fileResult("cape-dropped-" + task_id +".tar.bz2", client._http_request('GET', "/api/tasks/get/dropped/"+task_id+"/",resp_type="response").text)
    resp = client._http_request('GET', f'/api/tasks/get/dropped/{task_id}/', resp_type='content', error_handler=client.simple_error_handler)
    # return_results(resp)
    return fileResult(f'cape-dropped-{task_id}.tar.bz2', resp)


# Works
def get_task_screenshots(client: Client, **args) -> list:
    '''
    API returns a bz2 containing all screenshots. Function extracts and iterates over all files and returns them to war room
    :param client:
    :param args:
    :return:
    '''
    task_id = demisto.getArg("task_id")
    resp = client._http_request('GET', f'/api/tasks/get/screenshot/{task_id}/',
                                                       resp_type="content", error_handler=client.simple_error_handler)
    with open(f'{task_id}-screenshots.tar.bz2', 'wb') as f:
        f.write(resp)

    with tarfile.open(f'{task_id}-screenshots.tar.bz2', 'r:bz2') as tar:
        tar.extractall()

    file_results = []
    for filename in os.listdir(os.getcwd()):
        if filename.endswith(".jpg") or filename.endswith(".jpeg"):
            with open(filename, 'rb') as f:
                file_results.append(fileResult(filename, f.read()))
        else:
            continue

    return file_results

# TESTING
def get_virtual_machine_list(client: Client, **args):
    #curl https://www.capesandbox.com/api/machines/list/
    resp = client._http_request('GET', "/api/machines/list/")
    if "data" in resp:
        demisto.results({
            "ContentsFormat":formats["markdown"],
            "HumanReadable":tableToMarkdown("Available VM's",resp["data"]),
            "ReadableContentsFormat": formats['markdown'],
            "IgnoreAutoExtract":True,
            "Type":entryTypes["note"],
            "Contents":resp
        })
    else:
        demisto.results("Error occurred " + json.loads(resp))
    return resp


# TESTING
def get_vm_view(client: Client, **args):
    #curl https://www.capesandbox.com/api/machines/view/[vm-name]/
    vm_name = demisto.getArg("vm_name")
    resp = client._http_request('GET', "/api/machines/view/"+vm_name)
    if "data" in resp:
        demisto.results({
            "ContentsFormat":formats["markdown"],
            "HumanReadable":tableToMarkdown("VM View",resp["data"]),
            "ReadableContentsFormat": formats['markdown'],
            "IgnoreAutoExtract":True,
            "Type":entryTypes["note"],
            "Contents":resp
        })
    else:
        demisto.results("Error occurred " + json.loads(resp))
    return resp


# TESTING
def get_task_report(client: Client, **args) -> None:
    #curl https://www.capesandbox.com/api/tasks/get/report/[task id]/[format]/
    #Note: Format can be json/maec/maec5/metadata/all.
    task_id = demisto.getArg("task_id")
    report_format = demisto.getArg("report_format")
    url = "[Click this link to download the report](https://www.capesandbox.com/api/tasks/get/report/"+task_id+"/"+report_format+"/)"
    # print(url)
    # demisto.results({
    #     "Type":entryTypes["note"],
    #     "ContentsFormat":formats["markdown"],
    #     "HumanReadable":url,
    #     "IgnoreAutoExtract":True,
    #     "Contents":url
    # })
    # resp = client._http_request('GET', url, resp_type='response')
    import requests
    resp = requests.get(url, verify=False)
    print(len(resp.content))
    # return_results(fileResult('test', resp))


# Test
# def task_status(client: Client, **args) -> CommandResults:
#     task_id = args.get('task_id')
#
#     r = client._http_request('GET', f'api/tasks/status/{task_id}/')
#
#     results = CommandResults(
#         outputs_prefix='CAPE.submissions',
#         outputs_key_field='data',
#         outputs=r
#     )
#
#     return results
#
#
# # Test
# def task_report(client: Client, **args) -> CommandResults:
#     # curl https://www.capesandbox.com/api/tasks/get/report/[task id]/
#     # curl https://www.capesandbox.com/api/tasks/get/report/[task id]/[format]/
#     # Note: Format can be json/maec/maec5/metadata/all.
#     # Says it can return a tar.gz, would that be all?
#     task_id = args.get('task_id')
#     format = args.get('format')
#
#     uri = f'api/tasks/get/report/{task_id}/'
#     if format:
#         uri += f'{format}/'
#
#     r = client._http_request('GET', uri)
#
#     results = CommandResults(
#         outputs_prefix='CAPE.submissions',
#         outputs_key_field='data',
#         outputs=r
#     )
#
#     return results
#
#
# # Test
# def task_iocs(client: Client, **args) -> CommandResults:
#     # curl https://www.capesandbox.com/api/tasks/get/iocs/[task id]/
#     # curl https://www.capesandbox.com/api/tasks/get/iocs/[task id]/detailed/
#     task_id = args.get('task_id')
#     detailed: str = args.get('detailed')
#
#     uri = f'api/tasks/status/{task_id}/'
#     if detailed:
#         uri += f'{detailed}/'
#
#     r = client._http_request('GET', uri)
#
#     results = CommandResults(
#         outputs_prefix='CAPE.submissions',
#         outputs_key_field='data',
#         outputs=r
#     )
#
#     return results
#
#
# #
# def task_screenshots(client: Client, **args) -> CommandResults:
#     task_id = args.get('task_id')
#
#     r = client._http_request('GET', f'api/tasks/status/{task_id}/')
#
#     results = CommandResults(
#         outputs_prefix='CAPE.submissions',
#         outputs_key_field='data',
#         outputs=r
#     )
#
#     return results


def main():
    params = demisto.params()
    args = demisto.args()
    client = Client(
        params.get('base_url'),
        verify = params.get('Verify SSL')
    )

    commands = {
        'test-module': test_module,
        'cape-submit-file': submit_file,
        # 'cape-vt-download-analyze': vt_download_analyze,
        'cape-submit-url': submit_url,
        'cape-view-sample': view_sample,
        'cape-basic-task-search': basic_task_search,
        'cape-ext-task-search': extended_task_search,
        'cape-task-lists': task_lists,
        'cape-task-view': task_view,
        'cape-download-sample': download_sample,
        'cape-get-sample-config': sample_config,
        'cape-get-payload-files': payload_files,
        'cape-get-procmemory-dump': procmemory_dump,
        'cape-get-procdump-files': procdump_files,
        'cape-get-pcap': pcap_file,
        'cape-get-surifiles': surifiles,
        'cape-task-iocs': get_task_iocs,
        'cape-task-status': get_task_status,
        'cape-get-dropped-files': get_task_dropped_files,
        'cape-get-screenshots': get_task_screenshots,
        'cape-vm-list': get_virtual_machine_list,
        'cape-vm-view': get_vm_view,
        'cape-get-report': get_task_report
    }

    command = demisto.command()
    if command in commands:
        return_results(commands[command](client, **args))
    else:
        return_error(f'Command {command} is not available in this integration')


if __name__ in ['__main__','__builtin__','builtins']:
    # TODO - Cleanup CommandResults in each function
    main()