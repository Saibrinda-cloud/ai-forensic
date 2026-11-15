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

    def get_neighbors(self, node_id):
        return self.edges.get(node_id, [])

class SuspiciousActivityDetector:
    @staticmethod
    def detect_unusual_login(event):
        if 'login' in event.activity.lower():
            hour = event.timestamp.hour
            if hour < 9 or hour > 17:
                event.flags.append("Unusual login time")
                event.suspicious = True
                return True
        return False

    @staticmethod
    def detect_usb_connection(event):
        if 'usb' in event.activity.lower() or 'removable' in event.activity.lower():
            event.flags.append("Removable device connection")
            event.suspicious = True
            return True
        return False

    @staticmethod
    def detect_file_copy(event):
        if 'copy' in event.activity.lower() or 'copy' in str(event.details).lower():
            event.flags.append("File copy operation")
            event.suspicious = True
            return True
        return False

    @staticmethod
    def detect_large_transfer(event):
        if event.details.get('size_mb', 0) > 100:
            event.flags.append(f"Large transfer: {event.details.get('size_mb')} MB")
            event.suspicious = True
            return True
        return False

    @staticmethod
    def analyze_all_events(events):
        for event in events:
            SuspiciousActivityDetector.detect_unusual_login(event)
            SuspiciousActivityDetector.detect_usb_connection(event)
            SuspiciousActivityDetector.detect_file_copy(event)
            SuspiciousActivityDetector.detect_large_transfer(event)
        return events

class SearchAlgorithms:
    @staticmethod
    def bfs(graph, start_id, goal_id):
        start_time = time.time()
        visited = set()
        queue = deque([(start_id, [start_id])])
        explored_nodes = 0

        while queue:
            current_id, path = queue.popleft()
            explored_nodes += 1

            if current_id in visited:
                continue
            visited.add(current_id)

            if current_id == goal_id:
                execution_time = time.time() - start_time
                cost = sum(1 for _ in path) - 1
                return {'found': True, 'path': path, 'path_length': len(path) - 1, 'total_cost': float(len(path) - 1), 'explored_nodes': explored_nodes, 'execution_time': execution_time}

            for neighbor_id, _ in graph.get_neighbors(current_id):
                if neighbor_id not in visited:
                    queue.append((neighbor_id, path + [neighbor_id]))

        execution_time = time.time() - start_time
        return {'found': False, 'path': [], 'path_length': 0, 'total_cost': 0, 'explored_nodes': explored_nodes, 'execution_time': execution_time}

    @staticmethod
    def dfs(graph, start_id, goal_id):
        start_time = time.time()
        visited = set()
        stack = [(start_id, [start_id])]
        explored_nodes = 0

        while stack:
            current_id, path = stack.pop()
            explored_nodes += 1

            if current_id in visited:
                continue
            visited.add(current_id)

            if current_id == goal_id:
                execution_time = time.time() - start_time
                return {'found': True, 'path': path, 'path_length': len(path) - 1, 'total_cost': float(len(path) - 1), 'explored_nodes': explored_nodes, 'execution_time': execution_time}

            for neighbor_id, _ in graph.get_neighbors(current_id):
                if neighbor_id not in visited:
                    stack.append((neighbor_id, path + [neighbor_id]))

        execution_time = time.time() - start_time
        return {'found': False, 'path': [], 'path_length': 0, 'total_cost': 0, 'explored_nodes': explored_nodes, 'execution_time': execution_time}

    @staticmethod
    def ucs(graph, start_id, goal_id):
        start_time = time.time()
        visited = set()
        pq = [(0, start_id, [start_id])]
        explored_nodes = 0

        while pq:
            current_cost, current_id, path = heapq.heappop(pq)
            explored_nodes += 1

            if current_id in visited:
                continue
            visited.add(current_id)

            if current_id == goal_id:
                execution_time = time.time() - start_time
                return {'found': True, 'path': path, 'path_length': len(path) - 1, 'total_cost': round(current_cost, 2), 'explored_nodes': explored_nodes, 'execution_time': execution_time}

            for neighbor_id, edge_cost in graph.get_neighbors(current_id):
                if neighbor_id not in visited:
                    new_cost = current_cost + edge_cost
                    heapq.heappush(pq, (new_cost, neighbor_id, path + [neighbor_id]))

        execution_time = time.time() - start_time
        return {'found': False, 'path': [], 'path_length': 0, 'total_cost': 0, 'explored_nodes': explored_nodes, 'execution_time': execution_time}

graph = EvidenceGraph()
all_events = []

@app.route('/', methods=['GET'])
def index():
    return send_file(os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html'))

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

    all_events = SuspiciousActivityDetector.analyze_all_events(all_events)

    dataset_hash = hashlib.sha256(json.dumps(dataset, default=str).encode()).hexdigest()

    return jsonify({
        'success': True,
        'total_events': len(all_events),
        'total_edges': sum(len(edges) for edges in graph.edges.values()),
        'dataset_hash': dataset_hash,
        'events': [{'id': e.event_id, 'user': e.user, 'device': e.device, 'activity': e.activity, 'timestamp': e.timestamp.isoformat(), 'suspicious': e.suspicious, 'flags': e.flags} for e in all_events]
    })

@app.route('/api/search', methods=['POST'])
def search():
    data = request.json
    start_id = data.get('start_id')
    goal_id = data.get('goal_id')
    algorithm = data.get('algorithm', 'bfs').lower()

    if not graph.nodes:
        return jsonify({'error': 'Dataset not loaded'}), 400

    if start_id not in graph.nodes or goal_id not in graph.nodes:
        return jsonify({'error': 'Invalid event ID'}), 400

    if algorithm == 'bfs':
        result = SearchAlgorithms.bfs(graph, start_id, goal_id)
    elif algorithm == 'dfs':
        result = SearchAlgorithms.dfs(graph, start_id, goal_id)
    elif algorithm == 'ucs':
        result = SearchAlgorithms.ucs(graph, start_id, goal_id)
    else:
        return jsonify({'error': 'Unknown algorithm'}), 400

    path_details = []
    if result['found']:
        for event_id in result['path']:
            event = graph.nodes[event_id]
            path_details.append({'id': event.event_id, 'user': event.user, 'device': event.device, 'activity': event.activity, 'timestamp': event.timestamp.isoformat()})

    return jsonify({
        'algorithm': algorithm,
        'found': result['found'],
        'path': result['path'],
        'path_details': path_details,
        'path_length': result['path_length'],
        'total_cost': round(result['total_cost'], 2),
        'explored_nodes': result['explored_nodes'],
        'execution_time_ms': round(result['execution_time'] * 1000, 2)
    })

@app.route('/api/compare-algorithms', methods=['POST'])
def compare_algorithms():
    data = request.json
    start_id = data.get('start_id')
    goal_id = data.get('goal_id')

    if not graph.nodes:
        return jsonify({'error': 'Dataset not loaded'}), 400

    results = {
        'bfs': SearchAlgorithms.bfs(graph, start_id, goal_id),
        'dfs': SearchAlgorithms.dfs(graph, start_id, goal_id),
        'ucs': SearchAlgorithms.ucs(graph, start_id, goal_id)
    }

    return jsonify({
        'comparison': {
            'bfs': {'found': results['bfs']['found'], 'path_length': results['bfs']['path_length'], 'total_cost': round(results['bfs']['total_cost'], 2), 'explored_nodes': results['bfs']['explored_nodes'], 'execution_time_ms': round(results['bfs']['execution_time'] * 1000, 2)},
            'dfs': {'found': results['dfs']['found'], 'path_length': results['dfs']['path_length'], 'total_cost': round(results['dfs']['total_cost'], 2), 'explored_nodes': results['dfs']['explored_nodes'], 'execution_time_ms': round(results['dfs']['execution_time'] * 1000, 2)},
            'ucs': {'found': results['ucs']['found'], 'path_length': results['ucs']['path_length'], 'total_cost': round(results['ucs']['total_cost'], 2), 'explored_nodes': results['ucs']['explored_nodes'], 'execution_time_ms': round(results['ucs']['execution_time'] * 1000, 2)}
        }
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
