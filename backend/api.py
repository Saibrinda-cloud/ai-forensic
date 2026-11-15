from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from datetime import datetime
from collections import defaultdict
import hashlib
import json
import os

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
        self.all_events = []

    def add_event(self, event):
        self.nodes[event.event_id] = event
        self.all_events.append(event)

    def add_edge(self, from_id, to_id, cost):
        if from_id in self.nodes and to_id in self.nodes:
            self.edges[from_id].append((to_id, cost))

    def calculate_edge_cost(self, from_event, to_event):
        base_cost = 1.0
        time_diff = (to_event.timestamp - from_event.timestamp).total_seconds() / 3600
        time_penalty = min(time_diff * 0.1, 5.0)
        relationship_penalty = 5.0
        if from_event.user == to_event.user:
            relationship_penalty -= 2.0
        if from_event.device == to_event.device:
            relationship_penalty -= 1.5
        return base_cost + time_penalty + relationship_penalty

graph = EvidenceGraph()
all_events = []

@app.route('/', methods=['GET'])
def serve_index():
    try:
        return send_file(os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html'))
    except Exception as e:
        return jsonify({'error': str(e)}), 404

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

    for record in dataset:
        timestamp = datetime.strptime(record['time'], '%Y-%m-%d %H:%M:%S')
        event = ForensicEvent(record['id'], record['user'], record['device'], record['activity'], timestamp, {'size_mb': record['size_mb']})
        graph.add_event(event)
        all_events.append(event)

    sorted_events = sorted(all_events, key=lambda e: e.timestamp)
    for i, from_event in enumerate(sorted_events):
        for to_event in sorted_events[i+1:]:
            time_diff = (to_event.timestamp - from_event.timestamp).total_seconds() / 3600
            if time_diff <= 24:
                if from_event.user == to_event.user or from_event.device == to_event.device:
                    cost = graph.calculate_edge_cost(from_event, to_event)
                    graph.add_edge(from_event.event_id, to_event.event_id, cost)

    dataset_hash = hashlib.sha256(json.dumps(dataset, default=str).encode()).hexdigest()

    return jsonify({
        'success': True,
        'total_events': len(all_events),
        'total_edges': sum(len(edges) for edges in graph.edges.values()),
        'dataset_hash': dataset_hash,
        'events': [{'id': e.event_id, 'user': e.user, 'device': e.device, 'activity': e.activity, 'timestamp': e.timestamp.isoformat(), 'suspicious': e.suspicious, 'flags': e.flags} for e in all_events]
    })

@app.route('/api/events', methods=['GET'])
def get_events():
    return jsonify({'events': [{'id': e.event_id, 'user': e.user, 'device': e.device, 'activity': e.activity, 'timestamp': e.timestamp.isoformat(), 'suspicious': e.suspicious, 'flags': e.flags} for e in all_events]})

def dfs_search(start_id, goal_id, graph, visited=None, path=None, cost=0):
    if visited is None:
        visited = set()
    if path is None:
        path = []

    if start_id in visited:
        return None

    visited.add(start_id)
    path.append(start_id)

    if start_id == goal_id:
        return {'path': path, 'cost': cost, 'nodes_explored': len(visited)}

    if start_id in graph.edges:
        for next_id, edge_cost in graph.edges[start_id]:
            result = dfs_search(next_id, goal_id, graph, visited.copy(), path.copy(), cost + edge_cost)
            if result:
                return result

    return None

def dijkstra_search(start_id, goal_id, graph):
    import heapq
    distances = {node_id: float('inf') for node_id in graph.nodes}
    distances[start_id] = 0
    previous = {node_id: None for node_id in graph.nodes}
    pq = [(0, start_id)]
    visited = set()
    nodes_explored = 0

    while pq:
        current_cost, current_id = heapq.heappop(pq)

        if current_id in visited:
            continue

        visited.add(current_id)
        nodes_explored += 1

        if current_id == goal_id:
            path = []
            node = goal_id
            while node is not None:
                path.append(node)
                node = previous[node]
            return {'path': path[::-1], 'cost': current_cost, 'nodes_explored': nodes_explored}

        if current_id in graph.edges:
            for next_id, edge_cost in graph.edges[current_id]:
                new_cost = current_cost + edge_cost
                if new_cost < distances[next_id]:
                    distances[next_id] = new_cost
                    previous[next_id] = current_id
                    heapq.heappush(pq, (new_cost, next_id))

    return None

@app.route('/api/search-path', methods=['POST'])
def search_path():
    data = request.json
    start_id = data.get('start_id')
    goal_id = data.get('goal_id')
    algorithm = data.get('algorithm', 'DFS')

    if not start_id or not goal_id:
        return jsonify({'error': 'Missing start_id or goal_id'}), 400

    if start_id not in graph.nodes or goal_id not in graph.nodes:
        return jsonify({'error': 'Invalid event ID'}), 400

    import time
    start_time = time.time()

    if algorithm == 'DFS':
        result = dfs_search(start_id, goal_id, graph)
    elif algorithm == 'Dijkstra':
        result = dijkstra_search(start_id, goal_id, graph)
    else:
        return jsonify({'error': 'Unknown algorithm'}), 400

    execution_time = (time.time() - start_time) * 1000

    if result:
        path_details = [{'id': event_id, 'user': graph.nodes[event_id].user, 'activity': graph.nodes[event_id].activity, 'timestamp': graph.nodes[event_id].timestamp.isoformat()} for event_id in result['path']]
        return jsonify({
            'success': True,
            'path_found': True,
            'path': result['path'],
            'path_details': path_details,
            'path_length': len(result['path']),
            'total_cost': round(result['cost'], 2),
            'nodes_explored': result['nodes_explored'],
            'execution_time': round(execution_time, 2),
            'algorithm': algorithm
        })
    else:
        return jsonify({
            'success': True,
            'path_found': False,
            'path': [],
            'path_length': 0,
            'total_cost': 0,
            'nodes_explored': 0,
            'execution_time': round(execution_time, 2),
            'algorithm': algorithm
        })
