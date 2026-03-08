#!/usr/bin/env python3
"""
JA3 Payload Analyzer - Core Engine
Author: @nanang55550-star
Version: 1.0.0
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

from core.utils import setup_logger


class PayloadAnalyzer:
    """
    Payload Analyzer Engine
    Mendeteksi anomali berdasarkan signature patterns
    """
    
    # Threshold risk scoring
    RISK_THRESHOLDS = {
        'LOW': 0,
        'MEDIUM': 20,
        'HIGH': 40,
        'CRITICAL': 70
    }
    
    # Daftar JA3 mencurigakan
    SUSPICIOUS_JA3 = [
        'b32309a26951912be7dba376398abc3b',  # Python requests
        '3039129e12019446d0a777651a376512',  # curl
        'f5973d463d12d46e38abc36713840612',  # Go HTTP
        '4637b4269d123d46e29abc3671239012',  # Java
        '132b490d1d2938164b391786576d1209',  # Burp Suite
    ]
    
    def __init__(self, signatures_path: Optional[str] = None):
        """
        Inisialisasi analyzer
        
        Args:
            signatures_path: Path ke folder signatures (opsional)
        """
        self.logger = setup_logger('payload_analyzer')
        self.signatures = self._load_signatures(signatures_path)
        self.stats = {
            'total_analyzed': 0,
            'anomalies_detected': 0,
            'critical_alerts': 0
        }
        self.logger.info(f"Payload Analyzer initialized with {self._total_patterns()} patterns")
    
    def _total_patterns(self) -> int:
        """Hitung total patterns"""
        return sum(len(v) for v in self.signatures.values())
    
    def _load_signatures(self, custom_path: Optional[str] = None) -> Dict:
        """
        Load signature patterns dari file
        
        Args:
            custom_path: Path kustom ke folder signatures
            
        Returns:
            Dictionary berisi patterns per kategori
        """
        sigs = {
            'cobol': [],
            'sql': [],
            'legacy': []
        }
        
        # Tentukan path
        if custom_path:
            base_path = Path(custom_path)
        else:
            base_path = Path(__file__).parent.parent / 'signatures'
        
        try:
            # Load COBOL patterns
            cobol_file = base_path / 'cobol_patterns.txt'
            if cobol_file.exists():
                with open(cobol_file, 'r') as f:
                    sigs['cobol'] = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(sigs['cobol'])} COBOL patterns")
            
            # Load SQL patterns
            sql_file = base_path / 'sql_patterns.txt'
            if sql_file.exists():
                with open(sql_file, 'r') as f:
                    sigs['sql'] = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(sigs['sql'])} SQL patterns")
            
            # Load legacy patterns
            legacy_file = base_path / 'legacy_patterns.txt'
            if legacy_file.exists():
                with open(legacy_file, 'r') as f:
                    sigs['legacy'] = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(sigs['legacy'])} Legacy patterns")
                
        except Exception as e:
            self.logger.error(f"Error loading signatures: {e}")
            
        return sigs
    
    def analyze(self, payload: str, ja3_hash: Optional[str] = None) -> Dict:
        """
        Analisis payload dan JA3 fingerprint
        
        Args:
            payload: String payload yang dikirim
            ja3_hash: JA3 fingerprint (opsional)
            
        Returns:
            Dictionary hasil analisis
        """
        self.stats['total_analyzed'] += 1
        
        result = {
            'anomaly': False,
            'risk_level': 'LOW',
            'risk_score': 0,
            'matched_patterns': [],
            'recommendation': 'ALLOW',
            'ja3_hash': ja3_hash,
            'payload_hash': self._hash_payload(payload)
        }
        
        # Cek COBOL patterns
        for pattern in self.signatures['cobol']:
            if re.search(pattern, payload, re.IGNORECASE):
                result['matched_patterns'].append({
                    'type': 'COBOL',
                    'pattern': pattern,
                    'severity': 'HIGH',
                    'score': 30
                })
                result['anomaly'] = True
                result['risk_score'] += 30
        
        # Cek SQL patterns
        for pattern in self.signatures['sql']:
            if re.search(pattern, payload, re.IGNORECASE):
                result['matched_patterns'].append({
                    'type': 'SQL_INJECTION',
                    'pattern': pattern,
                    'severity': 'CRITICAL',
                    'score': 50
                })
                result['anomaly'] = True
                result['risk_score'] += 50
        
        # Cek legacy patterns
        for pattern in self.signatures['legacy']:
            if re.search(pattern, payload, re.IGNORECASE):
                result['matched_patterns'].append({
                    'type': 'LEGACY',
                    'pattern': pattern,
                    'severity': 'MEDIUM',
                    'score': 20
                })
                result['anomaly'] = True
                result['risk_score'] += 20
        
        # Tentukan risk level berdasarkan score dan JA3
        if result['anomaly']:
            self.stats['anomalies_detected'] += 1
            
            # Tambah score jika JA3 mencurigakan
            if ja3_hash and ja3_hash in self.SUSPICIOUS_JA3:
                result['risk_score'] += 40
                result['matched_patterns'].append({
                    'type': 'SUSPICIOUS_JA3',
                    'pattern': ja3_hash[:16],
                    'severity': 'CRITICAL',
                    'score': 40
                })
            
            # Tentukan level
            if result['risk_score'] >= self.RISK_THRESHOLDS['CRITICAL']:
                result['risk_level'] = 'CRITICAL'
                result['recommendation'] = 'BLOCK'
                self.stats['critical_alerts'] += 1
            elif result['risk_score'] >= self.RISK_THRESHOLDS['HIGH']:
                result['risk_level'] = 'HIGH'
                result['recommendation'] = 'REVIEW'
            elif result['risk_score'] >= self.RISK_THRESHOLDS['MEDIUM']:
                result['risk_level'] = 'MEDIUM'
                result['recommendation'] = 'LOG'
        
        # Log hasil
        if result['anomaly']:
            self.logger.warning(
                f"Anomaly detected - Risk: {result['risk_level']} - "
                f"Score: {result['risk_score']} - "
                f"Matches: {len(result['matched_patterns'])}"
            )
        
        return result
    
    def _hash_payload(self, payload: str) -> str:
        """Buat hash dari payload"""
        import hashlib
        return hashlib.sha256(payload.encode()).hexdigest()[:16]
    
    def add_custom_pattern(self, category: str, pattern: str):
        """
        Tambah pattern kustom
        
        Args:
            category: Kategori (cobol/sql/legacy)
            pattern: Regex pattern
        """
        if category in self.signatures:
            self.signatures[category].append(pattern)
            self.logger.info(f"Added custom pattern to {category}: {pattern}")
        else:
            self.logger.error(f"Invalid category: {category}")
    
    def get_stats(self) -> Dict:
        """Dapatkan statistik analyzer"""
        return {
            'total_patterns': self._total_patterns(),
            'patterns_by_category': {
                k: len(v) for k, v in self.signatures.items()
            },
            'analysis_stats': self.stats.copy()
        }
    
    def reset_stats(self):
        """Reset statistik analyzer"""
        self.stats = {
            'total_analyzed': 0,
            'anomalies_detected': 0,
            'critical_alerts': 0
        }
        self.logger.info("Stats reset")


def main():
    """Function untuk testing"""
    analyzer = PayloadAnalyzer()
    
    # Test cases
    test_cases = [
        {
            'name': 'COBOL Transaction',
            'payload': """
                IDENTIFICATION DIVISION.
                PROGRAM-ID. TEST.
                DATA DIVISION.
                WORKING-STORAGE SECTION.
                01 WS-AMOUNT PIC 9(7)V99 VALUE 50000.
                PROCEDURE DIVISION.
                    DISPLAY 'SENDING TRANSACTION'.
            """,
            'ja3': 'cd08e31494f13d058c4f4a31675465b2'
        },
        {
            'name': 'SQL Injection',
            'payload': "SELECT * FROM users WHERE username = 'admin' OR 1=1--",
            'ja3': 'b32309a26951912be7dba376398abc3b'
        },
        {
            'name': 'Normal Request',
            'payload': "GET /index.html HTTP/1.1",
            'ja3': 'cd08e31494f13d058c4f4a31675465b2'
        },
        {
            'name': 'COBOL + Suspicious JA3',
            'payload': "IDENTIFICATION DIVISION. MOVE 10000 TO WS-AMOUNT.",
            'ja3': 'b32309a26951912be7dba376398abc3b'
        }
    ]
    
    print("\n" + "="*70)
    print("🔍 JA3 PAYLOAD ANALYZER - TEST RESULTS")
    print("="*70)
    
    for test in test_cases:
        print(f"\n[>] Testing: {test['name']}")
        result = analyzer.analyze(test['payload'], test['ja3'])
        
        # Tampilan hasil
        status = "✅" if not result['anomaly'] else "⚠️" if result['risk_level'] == 'MEDIUM' else "🔥" if result['risk_level'] == 'HIGH' else "💀"
        
        print(f"    {status} Anomaly: {'YES' if result['anomaly'] else 'NO'}")
        print(f"    Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
        print(f"    Recommendation: {result['recommendation']}")
        
        if result['matched_patterns']:
            print("    Matched Patterns:")
            for match in result['matched_patterns']:
                print(f"      • {match['type']}: {match['pattern'][:30]}... ({match['severity']})")
    
    print("\n" + "="*70)
    print("📊 ANALYZER STATISTICS")
    print("="*70)
    stats = analyzer.get_stats()
    print(f"Total Patterns: {stats['total_patterns']}")
    print(f"COBOL Patterns: {stats['patterns_by_category']['cobol']}")
    print(f"SQL Patterns: {stats['patterns_by_category']['sql']}")
    print(f"Legacy Patterns: {stats['patterns_by_category']['legacy']}")
    print(f"Total Analyzed: {stats['analysis_stats']['total_analyzed']}")
    print(f"Anomalies Detected: {stats['analysis_stats']['anomalies_detected']}")
    print(f"Critical Alerts: {stats['analysis_stats']['critical_alerts']}")
    print("="*70)


if __name__ == "__main__":
    main()
