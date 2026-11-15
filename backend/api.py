from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from datetime import datetime
from collections import defaultdict, deque
import hashlib
import json
import os
import time
import heapq

app = Flask(__name__)
CORS(app)

class ForensicEvent:
    def __init__(self, event_id, user, device, activity, timestamp, details=None):
        self.event_id = event_id
        self.user = user
        self.device = device
        self.activity = activity
        self.timestamp = timestamp
        self.details = details or {}
        self.suspicious = False
        self.flags = []

class EvidenceGraph:
    def __init__(self):
        self.nodes = {}
        self.edges = defaultdict(list)

    def add_event(self, event):
        self.nodes[event.event_id] = event

    def add_edge(self, from_id, to_id, cost):
        if from_id in self.nodes and to_id in self.nodes:
            self.edges[from_id].append((to_id, cost))

    def get_neighbors(self, node_id):
        return self.edges.get(node_id, [])

class SearchAlgorithms:
    @staticmethod
    def bfs(graph, start_id, goal_id):
        start_time = time.time()
        visited = set()
        queue = deque([(start_id, [start_id])])
        explored = 0

        while queue:
            node, path = queue.popleft()
            explored += 1
            if node in visited:
                continue
            visited.add(node)
            if node == goal_id:
                return {'found': True, 'path': path, 'path_length': len(path) - 1, 'total_cost': len(path) - 1, 'explored_nodes': explored, 'execution_time': time.time() - start_time}
            for neighbor, _ in graph.get_neighbors(node):
                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor]))
        return {'found': False, 'path': [], 'path_length': 0, 'total_cost': 0, 'explored_nodes': explored, 'execution_time': time.time() - start_time}

    @staticmethod
    def dfs(graph, start_id, goal_id):
        start_time = time.time()
        visited = set()
        stack = [(start_id, [start_id])]
        explored = 0

        while stack:
            node, path = stack.pop()
            explored += 1
            if node in visited:
                continue
            visited.add(node)
            if node == goal_id:
                return {'found': True, 'path': path, 'path_length': len(path) - 1, 'total_cost': len(path) - 1, 'explored_nodes': explored, 'execution_time': time.time() - start_time}
            for neighbor, _ in graph.get_neighbors(node):
                if neighbor not in visited:
                    stack.append((neighbor, path + [neighbor]))
        return {'found': False, 'path': [], 'path_length': 0, 'total_cost': 0, 'explored_nodes': explored, 'execution_time': time.time() - start_time}

    @staticmethod
    def ucs(graph, start_id, goal_id):
        start_time = time.time()
        visited = set()
        pq = [(0, start_id, [start_id])]
        explored = 0

        while pq:
            cost, node, path = heapq.heappop(pq)
            explored += 1
            if node in visited:
                continue
            visited.add(node)
            if node == goal_id:
                return {'found': True, 'path': path, 'path_length': len(path) - 1, 'total_cost': cost, 'explored_nodes': explored, 'execution_time': time.time() - start_time}
            for neighbor, edge_cost in graph.get_neighbors(node):
                if neighbor not in visited:
                    heapq.heappush(pq, (cost + edge_cost, neighbor, path + [neighbor]))
        return {'found': False, 'path': [], 'path_length': 0, 'total_cost': 0, 'explored_nodes': explored, 'execution_time': time.time() - start_time}

graph = EvidenceGraph()
all_events = []

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/api/load-dataset', methods=['POST'])
def load_dataset():
    global graph, all_events
    graph = EvidenceGraph()
    all_events = []

    dataset = [
        {'id': 'E001', 'user': 'alex', 'device': 'PC01', 'activity': 'Login', 'time': '2024-01-15 08:30:00', 'size_mb': 0},
        {'id': 'E002', 'user': 'alex', 'device': 'PC01', 'activity': 'Accessed confidential file', 'time': '2024-01-15 08:45:00', 'size_mb': 0},
        {'id': 'E003', 'user': 'alex', 'device': 'PC01', 'activity': 'USB Device Connected', 'time': '2024-01-15 09:00:00', 'size_mb': 0},
        {'id': 'E004', 'user': 'alex', 'device': 'PC01', 'activity': 'File copy operation', 'time': '2024-01-15 09:15:00', 'size_mb': 250},
        {'id': 'E005', 'user': 'alex', 'device': 'PC01', 'activity': 'Network transfer', 'time': '2024-01-15 09:30:00', 'size_mb': 245},
        {'id': 'E006', 'user': 'sam', 'device': 'PC02', 'activity': 'Login', 'time': '2024-01-15 07:00:00', 'size_mb': 0},
        {'id': 'E007', 'user': 'sam', 'device': 'PC02', 'activity': 'Email sent', 'time': '2024-01-15 07:30:00', 'size_mb': 5},
        {'id': 'E008', 'user': 'bob', 'device': 'PC03', 'activity': 'Login', 'time': '2024-01-15 22:00:00', 'size_mb': 0},
        {'id': 'E009', 'user': 'bob', 'device': 'PC03', 'activity': 'USB Device Connected', 'time': '2024-01-15 22:15:00', 'size_mb': 0},
        {'id': 'E010', 'user': 'bob', 'device': 'PC03', 'activity': 'File copy operation', 'time': '2024-01-15 22:30:00', 'size_mb': 180},
    ]

    for rec in dataset:
        ts = datetime.strptime(rec['time'], '%Y-%m-%d %H:%M:%S')
        evt = ForensicEvent(rec['id'], rec['user'], rec['device'], rec['activity'], ts, {'size_mb': rec['size_mb']})
        if 'usb' in rec['activity'].lower():
            evt.flags.append('Removable device')
            evt.suspicious = True
        if 'copy' in rec['activity'].lower():
            evt.flags.append('File copy')
            evt.suspicious = True
        if rec['size_mb'] > 100:
            evt.flags.append(f'Large: {rec["size_mb"]} MB')
            evt.suspicious = True
        graph.add_event(evt)
        all_events.append(evt)

    sorted_events = sorted(all_events, key=lambda e: e.timestamp)
    for i, from_evt in enumerate(sorted_events):
        for to_evt in sorted_events[i+1:]:
            td = (to_evt.timestamp - from_evt.timestamp).total_seconds() / 3600
            if td <= 24 and (from_evt.user == to_evt.user or from_evt.device == to_evt.device):
                cost = 1 + td * 0.1
                if from_evt.user == to_evt.user:
                    cost -= 2
                if from_evt.device == to_evt.device:
                    cost -= 1.5
                graph.add_edge(from_evt.event_id, to_evt.event_id, max(0.1, cost))

    return jsonify({
        'success': True,
        'total_events': len(all_events),
        'total_edges': sum(len(edges) for edges in graph.edges.values()),
        'events': [{'id': e.event_id, 'user': e.user, 'device': e.device, 'activity': e.activity, 'timestamp': e.timestamp.isoformat(), 'suspicious': e.suspicious, 'flags': e.flags} for e in all_events]
    })

@app.route('/api/search', methods=['POST'])
def search():
    req = request.json
    start = req.get('start_id')
    goal = req.get('goal_id')
    algo = req.get('algorithm', 'bfs').lower()

    if not graph.nodes:
        return jsonify({'error': 'Load dataset first'}), 400
    if start not in graph.nodes or goal not in graph.nodes:
        return jsonify({'error': 'Invalid event'}), 400

    if algo == 'bfs':
        res = SearchAlgorithms.bfs(graph, start, goal)
    elif algo == 'dfs':
        res = SearchAlgorithms.dfs(graph, start, goal)
    elif algo == 'ucs':
        res = SearchAlgorithms.ucs(graph, start, goal)
    else:
        return jsonify({'error': 'Unknown algorithm'}), 400

    path_details = []
    for eid in res['path']:
        if eid in graph.nodes:
            e = graph.nodes[eid]
            path_details.append({'id': e.event_id, 'user': e.user, 'device': e.device, 'activity': e.activity, 'timestamp': e.timestamp.isoformat()})

    return jsonify({
        'algorithm': algo,
        'found': res['found'],
        'path': res['path'],
        'path_details': path_details,
        'path_length': res['path_length'],
        'total_cost': round(res['total_cost'], 2),
        'explored_nodes': res['explored_nodes'],
        'execution_time_ms': round(res['execution_time'] * 1000, 2)
    })

@app.route('/api/compare-algorithms', methods=['POST'])
def compare():
    req = request.json
    start = req.get('start_id')
    goal = req.get('goal_id')

    if not graph.nodes:
        return jsonify({'error': 'Load dataset first'}), 400

    r1 = SearchAlgorithms.bfs(graph, start, goal)
    r2 = SearchAlgorithms.dfs(graph, start, goal)
    r3 = SearchAlgorithms.ucs(graph, start, goal)

    return jsonify({'comparison': {
        'bfs': {'found': r1['found'], 'path_length': r1['path_length'], 'total_cost': round(r1['total_cost'], 2), 'explored_nodes': r1['explored_nodes'], 'execution_time_ms': round(r1['execution_time'] * 1000, 2)},
        'dfs': {'found': r2['found'], 'path_length': r2['path_length'], 'total_cost': round(r2['total_cost'], 2), 'explored_nodes': r2['explored_nodes'], 'execution_time_ms': round(r2['execution_time'] * 1000, 2)},
        'ucs': {'found': r3['found'], 'path_length': r3['path_length'], 'total_cost': round(r3['total_cost'], 2), 'explored_nodes': r3['explored_nodes'], 'execution_time_ms': round(r3['execution_time'] * 1000, 2)}
    }})

if __name__ == '__main__':
    app.run(debug=True)
