"""
SOCentinel — Investigation Memory.
Vector similarity search via Qdrant + sentence-transformers.
Falls back gracefully if Qdrant is unavailable.
"""

import uuid

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    ENCODER_AVAILABLE = True
except ImportError:
    ENCODER_AVAILABLE = False

import os
from dotenv import load_dotenv

load_dotenv()

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION = "investigation_memory"
VECTOR_SIZE = 384


class InvestigationMemory:
    """Store and retrieve investigation findings with vector similarity."""

    def __init__(self):
        self.ready = False
        if not QDRANT_AVAILABLE or not ENCODER_AVAILABLE:
            print("[memory] Qdrant or sentence-transformers not installed")
            return
        try:
            self.client = QdrantClient(url=QDRANT_URL, timeout=5)
            self.encoder = SentenceTransformer("all-MiniLM-L6-v2")
            self._ensure_collection()
            self.ready = True
        except Exception as e:
            print(f"[memory] Qdrant unavailable: {e}")

    def _ensure_collection(self):
        """Create collection if it doesn't exist."""
        collections = [c.name for c in self.client.get_collections().collections]
        if COLLECTION not in collections:
            self.client.create_collection(
                collection_name=COLLECTION,
                vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
            )
            print(f"[memory] Created collection: {COLLECTION}")

    def store(self, case_id: str, alert_category: str, mitre_techniques: list,
              outcome: str, resolution: str, lessons: str):
        """Encode summary and upsert to Qdrant."""
        if not self.ready:
            return
        summary = (
            f"Case {case_id}: {alert_category}. "
            f"Techniques: {', '.join(mitre_techniques)}. "
            f"Outcome: {outcome}. Resolution: {resolution}. "
            f"Lessons: {lessons}"
        )
        vector = self.encoder.encode(summary).tolist()
        point = PointStruct(
            id=str(uuid.uuid4()),
            vector=vector,
            payload={
                "case_id": case_id,
                "alert_category": alert_category,
                "mitre_techniques": mitre_techniques,
                "outcome": outcome,
                "resolution": resolution,
                "lessons": lessons,
                "summary": summary,
            },
        )
        self.client.upsert(collection_name=COLLECTION, points=[point])

    def search_similar(self, alert_category: str, mitre_techniques: list, top_k: int = 3) -> list:
        """Find past investigations similar to current alert context."""
        if not self.ready:
            return []
        query_text = f"{alert_category}. Techniques: {', '.join(mitre_techniques)}"
        vector = self.encoder.encode(query_text).tolist()
        try:
            results = self.client.query_points(
                collection_name=COLLECTION,
                query=vector,
                limit=top_k,
            ).points
            return [
                {"score": r.score, **r.payload}
                for r in results
            ]
        except Exception as e:
            print(f"[memory] Search failed: {e}")
            return []
