import os, json, sys
sys.path.insert(0, os.path.abspath('.'))
os.environ['TECHSCAN_DISABLE_DB'] = '1'
os.environ['TECHSCAN_LOG_LEVEL'] = 'DEBUG'
from app import create_app

app = create_app()
client = app.test_client()

steps = []

# helper

def step(name, func):
    try:
        res = func()
        steps.append({'step': name, 'ok': True, 'res': res})
    except Exception as e:
        steps.append({'step': name, 'ok': False, 'error': str(e)})

step('diag_initial', lambda: client.get('/api/domain_groups/_diag').json)

NEW_GROUP = 'zzz_flow_test'

step('add_group', lambda: client.post('/api/domain_groups', json={'group': NEW_GROUP}).json)
step('assign_domain', lambda: client.post(f'/api/domain_groups/{NEW_GROUP}/assign', json={'domain':'example.com'}).json)
step('remove_domain', lambda: client.post(f'/api/domain_groups/{NEW_GROUP}/remove', json={'domain':'example.com'}).json)
step('delete_group', lambda: client.delete(f'/api/domain_groups/{NEW_GROUP}').json)
step('diag_final', lambda: client.get('/api/domain_groups/_diag').json)

print(json.dumps(steps, indent=2))
