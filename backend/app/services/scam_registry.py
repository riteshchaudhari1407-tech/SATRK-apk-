import json
import os
import tempfile
import logging
from typing import Dict, Any, List

logger = logging.getLogger("satrk.scam_registry")

class ScamRegistry:
    """
    ScamRegistry provides a local JSON persistence layer for crowdsourced reports.
    Implements atomic writes to prevent corruption.
    Max risk_boost capped at 50.
    """
    
    def __init__(self, filepath: str = "data/scam_registry.json"):
        self.filepath = filepath
        self.data: Dict[str, Dict[str, Any]] = {}
        self._ensure_file()
        self._load()

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        if not os.path.exists(self.filepath):
            with open(self.filepath, "w") as f:
                json.dump({}, f)

    def _load(self):
        try:
            with open(self.filepath, "r") as f:
                self.data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load scam registry from {self.filepath}: {e}")
            self.data = {}

    def _save(self):
        """Atomic write to prevent corruption during concurrent requests."""
        try:
            fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(self.filepath), suffix=".tmp")
            with os.fdopen(fd, 'w') as f:
                json.dump(self.data, f, indent=2)
            os.replace(temp_path, self.filepath)
        except Exception as e:
            logger.error(f"Failed to save scam registry to {self.filepath}: {e}")
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    def report_identifier(self, identifier: str, id_type: str, note: str) -> None:
        """
        Log a new report.
        """
        identifier = identifier.strip().lower()
        if identifier not in self.data:
            self.data[identifier] = {
                "type": id_type,
                "reports_count": 0,
                "notes": []
            }
        
        self.data[identifier]["reports_count"] += 1
        if note:
            self.data[identifier]["notes"].append(note)
            # Keep only the last 10 notes to save space
            if len(self.data[identifier]["notes"]) > 10:
                self.data[identifier]["notes"] = self.data[identifier]["notes"][-10:]
                
        self._save()
        logger.info(f"Reported identifier {identifier} of type {id_type}")

    def check_identifier(self, identifier: str) -> Dict[str, Any]:
        """
        Check if an identifier has been reported.
        Cap the returned risk_boost at a maximum of 50 points.
        """
        identifier = identifier.strip().lower()
        if identifier in self.data:
            entry = self.data[identifier]
            count = entry.get("reports_count", 0)
            
            # 10 points per report, capped at 50
            risk_boost = min(count * 10, 50)
            
            return {
                "reported": True,
                "risk_boost": risk_boost,
                "reports_count": count,
                "type": entry.get("type"),
                "reason": f"Identifier ({entry.get('type')}) reported {count} times in crowdsourced scam registry."
            }
            
        return {
            "reported": False,
            "risk_boost": 0,
            "reason": ""
        }
