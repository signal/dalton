default_group = {
    'options': {
        'description': 'default group applied to all instances',
        'prune': True,
    },
    'rules': [
        'tcp port 0-65535 default',
        'udp port 0-65535 sg-123456',
        'icmp port 8 0.0.0.0/0',
        'tcp port 22 203.0.113.1',
    ]
}

load_balancer_group = {
    'options': {
        'description': 'custom application server instances',
        'prune': False
    },
    'rules': [
        'tcp port 80, 443 0.0.0.0/0'
    ]
}
