# MOCK Firestore integration for local testing
import datetime

class FirestoreMock:
    def __init__(self):
        self.history = {}
        
    def log_event(self, actor: str, action: str):
        if actor not in self.history:
            self.history[actor] = []
        self.history[actor].append({"action": action, "timestamp": datetime.datetime.now().isoformat()})
        
    def check_suspicious_history(self, actor: str) -> bool:
        # Mock logic: if actor has previous history, flag as enriched/suspicious
        return actor in self.history and len(self.history[actor]) > 0

db = FirestoreMock()
