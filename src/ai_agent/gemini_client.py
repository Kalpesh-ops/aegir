import os
import json
import logging
import sqlite3
import hashlib
from pathlib import Path
from typing import List, Dict

from dotenv import load_dotenv
import google.generativeai as genai
from google.generativeai.types import helper_types

from src.database.supabase_client import get_global_cached_report, store_global_cached_report

# Handle prompt import safely
try:
    from .prompts import SYSTEM_PROMPT
except ImportError:
    from prompts import SYSTEM_PROMPT

load_dotenv()

logger = logging.getLogger(__name__)

CACHE_DB = Path("data/ai_cache.db")

class GeminiAgent:
    def __init__(self):
        self.preferred_models = [
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-flash-latest",
            "gemini-pro-latest",
        ]

        self.model = None
        self.current_model_name = None
        
        # Always init the cache/db first
        self._init_cache()
        
        # Try to initialize the model if a key exists (from DB or .env)
        self.try_initialize_model()

    def _init_cache(self):
        """Initializes the local SQLite cache for AI reports and settings."""
        CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(CACHE_DB)
        
        # Existing reports table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ai_reports (
                signature TEXT PRIMARY KEY,
                report_text TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # NEW: Settings table for BYOK
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                config_key TEXT PRIMARY KEY,
                config_value TEXT
            )
        """)
        conn.commit()
        conn.close()

    def get_user_api_key(self) -> str:
        """Retrieves the user's API key from local DB, falling back to .env"""
        try:
            conn = sqlite3.connect(CACHE_DB)
            cursor = conn.cursor()
            cursor.execute("SELECT config_value FROM settings WHERE config_key = 'google_api_key'")
            row = cursor.fetchone()
            conn.close()
            
            if row and row[0]:
                return row[0]
        except Exception as e:
            logger.warning(f"Error reading API key from DB: {e}")
            
        # Fallback for local development
        return os.getenv("GOOGLE_API_KEY")

    def save_user_api_key(self, api_key: str):
        """Saves the user's API key to the local SQLite DB and re-initializes the model."""
        try:
            conn = sqlite3.connect(CACHE_DB)
            conn.execute(
                "INSERT OR REPLACE INTO settings (config_key, config_value) VALUES (?, ?)",
                ('google_api_key', api_key)
            )
            conn.commit()
            conn.close()
            
            # Immediately try to apply the new key
            self.try_initialize_model()
            return True
        except Exception as e:
            logger.error(f"Failed to save API key: {e}")
            return False

    def try_initialize_model(self):
        """Attempts to configure genai and initialize the model."""
        api_key = self.get_user_api_key()
        
        if not api_key:
            logger.info("No Gemini API key found. Waiting for user to provide one.")
            self.model = None
            return False

        try:
            genai.configure(api_key=api_key)
            for model_name in self.preferred_models:
                try:
                    self.model = genai.GenerativeModel(model_name)
                    self.current_model_name = model_name
                    logger.info(f"Initialized Gemini model: {self.current_model_name}")
                    return True
                except Exception as e:
                    logger.warning(f"Could not init {model_name}: {e}")
            
            logger.error("Could not initialize any Gemini models with the provided key.")
            self.model = None
            return False
            
        except Exception as e:
            logger.error(f"Failed to configure Gemini API: {e}")
            self.model = None
            return False

    def _generate_signature(self, ports: List[Dict], cves: List[Dict]) -> str:
        """Generates a privacy-safe SHA-256 hash of the vulnerability profile."""
        profile = []
        for p in ports:
            port_num = p.get("portid") or p.get("port") or p.get("port_number", "0")
            service = p.get("service", "unknown")
            product = p.get("product", "unknown")
            profile.append(f"{port_num}:{service}:{product}")
            
        cve_list = [c.get("cve_id", "") for c in cves if c.get("cve_id")]
        
        profile.sort()
        cve_list.sort()
        
        signature_data = f"PORTS:{'|'.join(profile)}||CVES:{'|'.join(cve_list)}"
        return hashlib.sha256(signature_data.encode('utf-8')).hexdigest()

    def _get_cached_report(self, signature: str) -> str:
        """Retrieves a report from the local cache."""
        try:
            conn = sqlite3.connect(CACHE_DB)
            cursor = conn.cursor()
            cursor.execute("SELECT report_text FROM ai_reports WHERE signature = ?", (signature,))
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else None
        except Exception as e:
            logger.warning(f"Cache read error: {e}")
            return None

    def _cache_report(self, signature: str, report_text: str):
        """Saves a generated report to the local cache."""
        try:
            conn = sqlite3.connect(CACHE_DB)
            conn.execute(
                "INSERT OR REPLACE INTO ai_reports (signature, report_text) VALUES (?, ?)",
                (signature, report_text)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Cache write error: {e}")

    def analyze_scan(self, ports: List[Dict], cves: List[Dict]) -> str:
        """Analyzes scan results cascading through the 3-Tier Cache."""
        signature = self._generate_signature(ports, cves)
        logger.info(f"Scan Signature Generated: {signature[:8]}...")

        # Tier 1: Check Local SQLite Cache
        cached_report = self._get_cached_report(signature)
        if cached_report:
            logger.info("[✓] AI Report retrieved from LOCAL cache")
            return cached_report

        # Tier 2: Check Global Supabase Cache
        global_report = get_global_cached_report(signature)
        if global_report:
            logger.info("[✓] AI Report retrieved from GLOBAL cache")
            self._cache_report(signature, global_report) # Save locally
            return global_report

        # Tier 3: Fallback to Gemini API
        # CRITICAL BYOK CHECK: Ensure model is initialized before hitting API
        if not self.model:
            # Try one more time in case they just added it
            if not self.try_initialize_model():
                logger.error("Scan analysis aborted: No valid Gemini API Key.")
                return "Error: Gemini API Key is missing or invalid. Please configure your API key in the application settings."

        logger.info(f"Signature not found globally. Sending data to {self.current_model_name}...")
        
        payload = {"ports": ports, "cve_findings": cves}
        scan_json_str = json.dumps(payload, indent=2)
        prompt = f"{SYSTEM_PROMPT}\n\nHere is the scan data: \n\n{scan_json_str}"

        try:
            response = self.model.generate_content(
                prompt,
                request_options=helper_types.RequestOptions(timeout=60)
            )
            report_text = response.text
            
            self._cache_report(signature, report_text)
            store_global_cached_report(signature, report_text)
            
            logger.info("[✓] AI analysis complete and cached globally")
            return report_text
            
        except Exception as e:
            logger.error(f"Gemini API Error: {e}")
            return f"Error: Could not generate AI analysis. {str(e)}"