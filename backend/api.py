from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from collections import defaultdict, deque
import time
import heapq

app = Flask(__name__)
CORS(app)

class Event:
    def __init__(self, eid, user, device, activity, ts):
        self.id = eid
        self.user = user
        self.device = device
        self.activity = activity
        self.ts = ts
        self.suspicious = False
        self.flags = []

class Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = defaultdict(list)
    
    def add_node(self, e):
        self.nodes[e.id] = e
    
    def add_edge(self, f, t, c):
        if f in self.nodes and t in self.nodes:
            self.edges[f].append((t, c))
    
    def neighbors(self, n):
        return self.edges.get(n, [])

g = Graph()
events = []

@app.route('/api/health', methods=['GET'])
def health():
    return {'status': 'ok'}

@app.route('/api/load-dataset', methods=['POST'])
def load():
    global g, events
    g = Graph()
    events = []
    
    data = [
        ('E001', 'alex', 'PC01', 'Login', '2024-01-15 08:30:00'),
        ('E002', 'alex', 'PC01', 'Accessed confidential file', '2024-01-15 08:45:00'),
        ('E003', 'alex', 'PC01', 'USB Device Connected', '2024-01-15 09:00:00'),
        ('E004', 'alex', 'PC01', 'File copy operation', '2024-01-15 09:15:00'),
        ('E005', 'alex', 'PC01', 'Network transfer', '2024-01-15 09:30:00'),
        ('E006', 'sam', 'PC02', 'Login', '2024-01-15 07:00:00'),
        ('E007', 'sam', 'PC02', 'Email sent', '2024-01-15 07:30:00'),
        ('E008', 'bob', 'PC03', 'Login', '2024-01-15 22:00:00'),
        ('E009', 'bob', 'PC03', 'USB Device Connected', '2024-01-15 22:15:00'),
        ('E010', 'bob', 'PC03', 'File copy operation', '2024-01-15 22:30:00'),
    ]
    
    for eid, user, device, activity, ts_str in data:
        e = Event(eid, user, device, activity, datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S'))
        if 'usb' in activity.lower():
            e.suspicious = True
            e.flags.append('USB')
        if 'copy' in activity.lower():
            e.suspicious = True
            e.flags.append('Copy')
        g.add_node(e)
        events.append(e)
    
    events.sort(key=lambda x: x.ts)
    for i, e1 in enumerate(events):
        for e2 in events[i+1:]:
            if (e1.user == e2.user or e1.device == e2.device):
                g.add_edge(e1.id, e2.id, 1.0)
    
    return {'success': True, 'total_events': len(events), 'total_edges': sum(len(v) for v in g.edges.values()), 'events': [{'id': e.id, 'user': e.user, 'device': e.device, 'activity': e.activity, 'timestamp': e.ts.isoformat(), 'suspicious': e.suspicious, 'flags': e.flags} for e in events]}

def bfs_search(start, goal):
    t0 = time.time()
    visited = set()
    q = deque([(start, [start])])
    explored = 0
    while q:
        n, p = q.popleft()
        explored += 1
        if n in visited:
            continue
        visited.add(n)
        if n == goal:
            return {'found': True, 'path': p, 'explored': explored, 'time': time.time() - t0}
        for nb, _ in g.neighbors(n):
            if nb not in visited:
                q.append((nb, p + [nb]))
    return {'found': False, 'path': [], 'explored': explored, 'time': time.time() - t0}

def dfs_search(start, goal):
    t0 = time.time()
    visited = set()
    s = [(start, [start])]
    explored = 0
    while s:
        n, p = s.pop()
        explored += 1
        if n in visited:
            continue
        visited.add(n)
        if n == goal:
            return {'found': True, 'path': p, 'explored': explored, 'time': time.time() - t0}
        for nb, _ in g.neighbors(n):
            if nb not in visited:
                s.append((nb, p + [nb]))
    return {'found': False, 'path': [], 'explored': explored, 'time': time.time() - t0}

def ucs_search(start, goal):
    t0 = time.time()
    visited = set()
    pq = [(0, start, [start])]
    explored = 0
    while pq:
        cost, n, p = heapq.heappop(pq)
        explored += 1
        if n in visited:
            continue
        visited.add(n)
        if n == goal:
            return {'found': True, 'path': p, 'cost': cost, 'explored': explored, 'time': time.time() - t0}
        for nb, ec in g.neighbors(n):
            if nb not in visited:
                heapq.heappush(pq, (cost + ec, nb, p + [nb]))
    return {'found': False, 'path': [], 'cost': 0, 'explored': explored, 'time': time.time() - t0}

@app.route('/api/search', methods=['POST'])
def search():
    req = request.json
    start = req.get('start_id')
    goal = req.get('goal_id')
    algo = req.get('algorithm', 'bfs')
    
    if not g.nodes:
        return {'error': 'No data'}
    if start not in g.nodes or goal not in g.nodes:
        return {'error': 'Bad IDs'}
    
    if algo == 'bfs':
        r = bfs_search(start, goal)
    elif algo == 'dfs':
        r = dfs_search(start, goal)
    else:
        r = ucs_search(start, goal)
    
    details = []
    for eid in r['path']:
        if eid in g.nodes:
            e = g.nodes[eid]
            details.append({'id': e.id, 'user': e.user, 'device': e.device, 'activity': e.activity, 'timestamp': e.ts.isoformat()})
    
    return {'algorithm': algo, 'found': r['found'], 'path': r['path'], 'path_details': details, 'path_length': len(r['path']) - 1, 'total_cost': r.get('cost', len(r['path']) - 1), 'explored_nodes': r['explored'], 'execution_time_ms': round(r['time'] * 1000, 2)}

@app.route('/api/compare-algorithms', methods=['POST'])
def compare():
    req = request.json
    start = req.get('start_id')
    goal = req.get('goal_id')
    
    if not g.nodes:
        return {'error': 'No data'}
    
    rb = bfs_search(start, goal)
    rd = dfs_search(start, goal)
    ru = ucs_search(start, goal)
    
    return {'comparison': {
        'bfs': {'found': rb['found'], 'path_length': len(rb['path']) - 1, 'total_cost': len(rb['path']) - 1, 'explored_nodes': rb['explored'], 'execution_time_ms': round(rb['time'] * 1000, 2)},
        'dfs': {'found': rd['found'], 'path_length': len(rd['path']) - 1, 'total_cost': len(rd['path']) - 1, 'explored_nodes': rd['explored'], 'execution_time_ms': round(rd['time'] * 1000, 2)},
        'ucs': {'found': ru['found'], 'path_length': len(ru['path']) - 1, 'total_cost': ru.get('cost', len(ru['path']) - 1), 'explored_nodes': ru['explored'], 'execution_time_ms': round(ru['time'] * 1000, 2)}
    }}

if __name__ == '__main__':
    app.run()
