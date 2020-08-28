import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    pass


# Test
def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    client._http_request()

    return 'ok'


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
        'cape-get-sample-config': sample_config,
        'cape-get-payload-files': payload_files,
        'cape-get-procdump-files': procdump_files
    }

    command = demisto.command()
    if command in commands:
        return_results(commands[command](client, **args))
    else:
        return_error(f'Command {command} is not available in this integration')


if __name__ in ['__main__','__builtin__','builtins']:
    # TODO - Cleanup CommandResults in each function
    main()
