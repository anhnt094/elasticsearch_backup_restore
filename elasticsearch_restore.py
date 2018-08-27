import json
import os
import re
import requests
import yaml

from MyLogger import MyLogger
from requests.auth import HTTPBasicAuth


restore_path = '/etc/elasticsearch/scripts/restore_elasticsearch.log'
config_dir = '/etc/elasticsearch/scripts'
my_log = MyLogger(restore_path)


def load_config(config_file_path):
    with open(config_file_path, 'r') as stream:
        data = yaml.load(stream)
    return data


def check_snapshot(hostport, repo_name, snapshot_name, use_searchguard):
    if use_searchguard:
        data = load_config('{}/credentials.yaml'.format(config_dir))
        user = data['user']
        password = data['password']
        url = 'https://{}/_snapshot/{}/{}' \
            .format(hostport, repo_name, snapshot_name)
        querystring = {
            'pretty': ''
        }
        response = requests.request("GET", url, params=querystring, verify=False,
                                    auth=HTTPBasicAuth(user, password))

    else:
        url = 'http://{}/_snapshot/{}/{}'\
            .format(hostport, repo_name, snapshot_name)
        querystring = {
            'pretty': ''
        }
        response = requests.request("GET", url, params=querystring, verify=False)
    return response.text


def delete_snapshot(hostport, repo_name, snapshot_name):
    url = 'https://admin:admin@{}/_snapshot/{}/{}'\
        .format(hostport, repo_name, snapshot_name)
    querystring = {
        'pretty': ''
    }
    response = requests.request("DELETE", url, params=querystring, verify=False)
    print(response.text)


def restore_indice(hostport, repo_name, snapshot_name, indice_name, use_searchguard):
    try:
        my_log.info('Restoring indice: {} ...'.format(indice_name))
        if snapshot_name:
            if use_searchguard:
                data = load_config('{}/credentials.yaml'.format(config_dir))
                user = data['user']
                password = data['password']
                url = 'https://{}/_snapshot/{}/{}/_restore?wait_for_completion=true' \
                    .format(hostport, repo_name, snapshot_name)
                querystring = {
                    'pretty': ''
                }
                headers = {
                    'content-type': "application/json"
                }
                payload = {
                    "indices": indice_name,
                    "ignore_unavailable": False,
                    "include_global_state": False,
                    # "rename_pattern": "(.+)",
                    # "rename_replacement": snapshot_name + "_restored_$1"}
                }
                response = requests.request("POST",
                                            url,
                                            headers=headers,
                                            data=json.dumps(payload),
                                            params=querystring,
                                            verify=False,
                                            auth=HTTPBasicAuth(user, password))

            else:
                url = 'http://{}/_snapshot/{}/{}/_restore?wait_for_completion=true' \
                    .format(hostport, repo_name, snapshot_name)
                querystring = {
                    'pretty': ''
                }
                headers = {
                    'content-type': "application/json"
                }
                payload = {
                    "indices": indice_name,
                    "ignore_unavailable": False,
                    "include_global_state": False
                }
                response = requests.request("POST",
                                            url,
                                            headers=headers,
                                            data=json.dumps(payload),
                                            params=querystring,
                                            verify=False)

            if response.status_code == 200:
                my_log.info('Restore indice done! Indice name: {}'.format(indice_name))
                print('Restore indice done! Indice name: {}'.format(indice_name))
            else:
                my_log.error('Restore indice failed!  Detail:\n{}'
                             .format(response.text))
                print('Restore indice failed!  Detail:\n{}'.format(response.text))

    except Exception:
        my_log.error('Restore indice failed! Something went wrong.')


def get_all_indice_names_in_snapshot(hostport, repo_name, snapshot_name, use_searchguard):
    data = check_snapshot(hostport, repo_name, snapshot_name, use_searchguard)
    data = json.loads(data)
    return data['snapshots'][0]['indices']


def get_all_indice_names_on_cluster(hostport, use_searchguard):
    if use_searchguard:
        data = load_config('{}/credentials.yaml'.format(config_dir))
        user = data['user']
        password = data['password']
        url = 'https://{}/_cat/indices' \
            .format(hostport)
        response = requests.request("GET",
                                    url,
                                    verify=False,
                                    auth=HTTPBasicAuth(user, password))

    else:
        url = 'http://{}/_cat/indices' \
            .format(hostport)
        response = requests.request("GET",
                                    url,
                                    verify=False)
    data = response.text
    result = []
    for line in data.splitlines():
        result.append(line.split()[2])
    return result


def delete_indice(hostport, indice_name, use_searchguard):
    try:
        my_log.info('Deleting old indice: {} ...'.format(indice_name))
        print('Deleting old indice: {} ...'.format(indice_name))

        if use_searchguard:
            data = load_config('{}/credentials.yaml'.format(config_dir))
            user = data['user']
            password = data['password']
            url = 'https://{}/{}' \
                .format(hostport, indice_name)

            response = requests.request("DELETE",
                                        url,
                                        verify=False,
                                        auth=HTTPBasicAuth(user, password))

        else:
            url = 'http://{}/{}' \
                .format(hostport, indice_name)
            response = requests.request("DELETE",
                                        url,
                                        verify=False)

        if response.status_code == 200:
            my_log.info('Old indice was be deleted: {}'.format(indice_name))
            print('Old indice was be deleted: {}'.format(indice_name))

        else:
            my_log.error('Delete indice failed! Detail:\n{}'
                         .format(response.text))
            print('Delete indice failed! Detail:\n{}'.format(response.text))

        return response.text

    except Exception:
        my_log.error('Delete indice failed! Something went wrong.')

def rename_indice(hostport, indice_name):
    url = 'https://admin:admin@{}/_reindex' \
        .format(hostport)
    headers = {
        'content-type': "application/json"
    }
    new_name = re.findall('restored_(.+)', indice_name)[0]
    print('Renaming ' + new_name + '...')
    payload = {
        "source": {
            "index": indice_name
        },
        "dest": {
            "index": new_name
        }
    }
    response = requests.request("POST",
                                url,
                                headers=headers,
                                data=json.dumps(payload),
                                verify=False)
    return response.text


def main():
    # Ignore warnings:
    import warnings
    warnings.simplefilter("ignore")

    config_file_path = '{}/elasticsearch_backup_config.yaml'.format(config_dir)
    config = load_config(config_file_path)

    hostport = config['HOSTPORT']
    repo_name = config['REPO']
    use_searchguard = config['USE_SEARCHGUARD']
    os.environ['NO_PROXY'] = hostport

    snapshot_name = 'snapshot-2018-08-27'

    indices = get_all_indice_names_in_snapshot(hostport, repo_name, snapshot_name, use_searchguard)
    my_log.info('-' * 60)
    my_log.info('Start restoring snapshot: {} ...'.format(snapshot_name))
    my_log.info('-' * 60)
    print('Start restoring snapshot: {} ...'.format(snapshot_name))

    for indice in indices:
        delete_indice(hostport, indice, use_searchguard)
        restore_indice(hostport, repo_name, snapshot_name, indice, use_searchguard)


if __name__ == '__main__':
    main()

