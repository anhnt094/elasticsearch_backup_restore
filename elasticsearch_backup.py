import json
import os
import requests
import sys
import yaml

from MyLogger import MyLogger

from _datetime import datetime
from requests.auth import HTTPBasicAuth


backup_log_path = '/etc/elasticsearch/scripts/backup_elasticsearch.log'
config_dir = '/etc/elasticsearch/scripts/'
my_log = MyLogger(backup_log_path)


def load_config(config_file_path):
    with open(config_file_path, 'r') as stream:
        data = yaml.load(stream)
    return data


def take_snapshot(hostport, repo_name, snapshot_name, use_searchguard):
    querystring = {
        'pretty': ''
    }
    headers = {
        'content-type': "application/json"
    }
    payload = {
        #"indices": "filebeat-*",
        "ignore_unavailable": True,
        "include_global_state": False
    }

    try:
        my_log.info('Taking snapshot: {} ...'.format(snapshot_name))
        if use_searchguard:
            data = load_config('{}/credentials.yaml'.format(config_dir))
            user = data['user']
            password = data['password']
            url = 'https://{}/_snapshot/{}/{}?wait_for_completion=true' \
                .format(hostport, repo_name, snapshot_name)
            querystring = {
                'pretty': ''
            }

            response = requests.request("PUT",
                                        url,
                                        headers=headers,
                                        data=json.dumps(payload),
                                        params=querystring,
                                        verify=False,
                                        auth=HTTPBasicAuth(user, password))

        else:
            url = 'http://{}/_snapshot/{}/{}?wait_for_completion=true'\
                .format(hostport, repo_name, snapshot_name)

            response = requests.request("PUT",
                                        url,
                                        headers=headers,
                                        data=json.dumps(payload),
                                        params=querystring,
                                        verify=False)
        if response.status_code == 200:
            my_log.info('Take snapshot done! Snapshot name: {}'.format(snapshot_name))
            print('Take snapshot done! Snapshot name: {}'.format(snapshot_name))
        else:
            my_log.error('Take snapshot failed! '
                         'The snapshot has not been created yet. Detail:\n{}'
                         .format(response.text))
            print('Take snapshot failed! '
                         'The snapshot has not been created yet. Detail:\n{}'
                         .format(response.text))

    except Exception:
        my_log.error('Take snapshot failed! Something went wrong.')


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
    print(response.text)


def get_all_snapshot_names(hostport, repo_name, use_searchguard):
    if use_searchguard:
        data = load_config('{}/credentials.yaml'.format(config_dir))
        user = data['user']
        password = data['password']
        url = 'https://{}/_snapshot/{}/_all'\
            .format(hostport, repo_name)
        querystring = {
            'pretty': ''
        }
        response = requests.request("GET", url, params=querystring, verify=False,
                                    auth=HTTPBasicAuth(user, password))
    else:
        url = 'http://{}/_snapshot/{}/_all' \
            .format(hostport, repo_name)
        querystring = {
            'pretty': ''
        }
        response = requests.request("GET", url, params=querystring, verify=False)

    data = json.loads(response.text)

    result = []

    for snapshot in data['snapshots']:
        result.append(snapshot['snapshot'])

    return result


def delete_snapshot(hostport, repo_name, snapshot_name, use_searchguard):
    querystring = {
        'pretty': ''
    }

    try:
        my_log.info('Deleting snapshot: {} ...'.format(snapshot_name))
        if use_searchguard:
            data = load_config('{}/credentials.yaml'.format(config_dir))
            user = data['user']
            password = data['password']
            url = 'https://{}/_snapshot/{}/{}' \
                .format(hostport, repo_name, snapshot_name)
            querystring = {
                'pretty': ''
            }
            response = requests.request("DELETE", url, params=querystring, verify=False,
                                        auth=HTTPBasicAuth(user, password))
        else:
            url = 'http://{}/_snapshot/{}/{}'\
                .format(hostport, repo_name, snapshot_name)
            response = requests.request("DELETE", url, params=querystring, verify=False)

        if response.status_code == 200:
            my_log.info('Snapshot was be deleted: {}'.format(snapshot_name))
            print('Snapshot was be deleted: {}'.format(snapshot_name))
        else:
            my_log.error('Delete snapshot failed! Detail:\n{}'
                         .format(response.text))
            print('Delete snapshot failed! Detail:\n{}'
                         .format(response.text))

    except Exception:
        my_log.error('Delete snapshot failed ! Something went wrong.')


def rotate_snapshot(hostport, repo_name, limit, use_searchguard):
    snapshots = get_all_snapshot_names(hostport, repo_name, use_searchguard)

    if len(snapshots) - limit > 0:
        my_log.info('Rotating snapshot...')
        for snapshot in snapshots[:len(snapshots) - limit]:
            delete_snapshot(hostport, repo_name, snapshot, use_searchguard)


def main():
    # Ignore warnings:
    import warnings
    warnings.simplefilter("ignore")

    args = sys.argv
    config_file_path = '{}/elasticsearch_backup_config.yaml'.format(config_dir)
    config = load_config(config_file_path)

    hostport = config['HOSTPORT']
    repo_name = config['REPO']
    limit = config['LIMIT']  # So ngay rotate snapshot
    use_searchguard = config['USE_SEARCHGUARD']

    os.environ['NO_PROXY'] = hostport
    if len(args) == 1:
        snapshot_name = 'snapshot-' + str(datetime.date(datetime.now()))
        take_snapshot(hostport, repo_name, snapshot_name, use_searchguard)
        rotate_snapshot(hostport, repo_name, limit, use_searchguard)

    else:
        if '--list-all-snapshots' in args:
            print(get_all_snapshot_names(hostport, repo_name, use_searchguard))
        elif '--check-one-snapshot' in args:
            if len(args) < 3:
                print('Missing snapshot name !')
                sys.exit(1)
            else:
                check_snapshot(hostport, repo_name, args[2], use_searchguard)
        elif '--delete-one-snapshot' in args:
            if len(args) < 3:
                print('Missing snapshot name !')
                sys.exit(1)
            else:
                delete_snapshot(hostport, repo_name, args[2], use_searchguard)
        elif '--take-snapshot' in args:
            if len(args) < 3:
                print('Missing snapshot name !')
                sys.exit(1)
            else:
                take_snapshot(hostport, repo_name, args[2], use_searchguard)
        else:
            print('Invalid argument !')

if __name__ == '__main__':
    main()

