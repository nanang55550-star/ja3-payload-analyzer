"""
Utility functions untuk JA3 Payload Analyzer
Author: @nanang55550-star
Version: 1.0.0
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, Any
import logging


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Setup logger dengan format standar
    
    Args:
        name: Nama logger
        level: Level logging
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


def hash_payload(payload: str) -> str:
    """
    Buat hash dari payload untuk tracking
    
    Args:
        payload: String payload
        
    Returns:
        SHA256 hash (16 karakter pertama)
    """
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def format_alert(result: Dict) -> str:
    """
    Format hasil analisis jadi alert yang mudah dibaca
    
    Args:
        result: Dictionary hasil analisis
        
    Returns:
        String alert terformat
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Pilih icon berdasarkan risk level
    icons = {
        'CRITICAL': '💀',
        'HIGH': '🔥',
        'MEDIUM': '⚠️',
        'LOW': '✅'
    }
    icon = icons.get(result['risk_level'], '❓')
    
    alert = f"""
{icon}═══════════════════════════════════════════════════════════
{icon}  JA3 PAYLOAD ALERT - {result['risk_level']}
{icon}═══════════════════════════════════════════════════════════
  Time: {timestamp}
  Risk Level: {result['risk_level']} (Score: {result['risk_score']})
  JA3 Hash: {result.get('ja3_hash', 'N/A')}
  Payload Hash: {result.get('payload_hash', 'N/A')}
  Recommendation: {result['recommendation']}
"""
    
    if result['matched_patterns']:
        alert += f"{icon}─────────────────────────────────────────────────────\n"
        alert += f"{icon}  Matched Patterns:\n"
        for match in result['matched_patterns']:
            alert += f"{icon}    • {match['type']}: {match['pattern'][:50]}...\n"
    
    alert += f"{icon}═══════════════════════════════════════════════════════════"
    
    return alert


def save_to_file(data: Any, filename: str):
    """
    Simpan data ke file JSON
    
    Args:
        data: Data to save
        filename: Output filename
    """
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print(f"✅ Data saved to {filename}")


def load_from_file(filename: str) -> Any:
    """
    Load data dari file JSON
    
    Args:
        filename: Input filename
        
    Returns:
        Loaded data
    """
    with open(filename, 'r') as f:
        return json.load(f)


def validate_payload(payload: str) -> bool:
    """
    Validasi payload (cek kosong, dll)
    
    Args:
        payload: String payload
        
    Returns:
        True jika valid
    """
    return bool(payload and payload.strip())


def get_timestamp() -> str:
    """Dapatkan timestamp sekarang"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def print_banner():
    """Print banner keren"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║  ██╗ █████╗ ██████╗     ██████╗  █████╗ ██╗   ██╗██╗      ║
    ║  ██║██╔══██╗██╔══██╗    ██╔══██╗██╔══██╗╚██╗ ██╔╝██║      ║
    ║  ██║███████║██████╔╝    ██████╔╝███████║ ╚████╔╝ ██║      ║
    ║  ██║██╔══██║██╔══██╗    ██╔═══╝ ██╔══██║  ╚██╔╝  ╚═╝      ║
    ║  ██║██║  ██║██║  ██║    ██║     ██║  ██║   ██║   ██╗      ║
    ║  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝      ║
    ║                                                           ║
    ║           PAYLOAD ANALYZER - by @nanang55550-star        ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)
