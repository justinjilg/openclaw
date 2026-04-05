#!/usr/bin/env python3
"""
BR Stress Test Suite - Phase 1: Discovery & Baseline
Jazz (OpenClaw) - BrainstormRouter M2M Testing
"""

import os
import sys
import json
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional, Any

# Configuration
BR_BASE_URL = "https://api.brainstormrouter.com"
BR_API_KEY = os.environ.get("BRAINSTORMROUTER_API_KEY", "")
TEST_RESULTS_DIR = f"./test-results/{datetime.now().strftime('%Y%m%d_%H%M%S')}"

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'

def log_info(msg: str):
    print(f"{Colors.GREEN}[INFO]{Colors.END} {msg}")

def log_warn(msg: str):
    print(f"{Colors.YELLOW}[WARN]{Colors.END} {msg}")

def log_error(msg: str):
    print(f"{Colors.RED}[ERROR]{Colors.END} {msg}")

def log_detail(msg: str):
    print(f"{Colors.BLUE}  →{Colors.END} {msg}")

class BRTestSuite:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {BR_API_KEY}",
            "Content-Type": "application/json"
        })
        self.results = {}
        os.makedirs(TEST_RESULTS_DIR, exist_ok=True)
        
    def save_result(self, name: str, data: Any):
        filepath = os.path.join(TEST_RESULTS_DIR, f"{name}.json")
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return filepath
    
    def test_1_1_self_discovery(self) -> bool:
        """Test 1.1: Basic connectivity and self-discovery"""
        log_info("=== Test 1.1: Self Discovery ===")
        
        try:
            response = self.session.get(f"{BR_BASE_URL}/v1/self")
            response.raise_for_status()
            
            data = response.json()
            self.save_result("self_discovery", data)
            
            # Extract key info
            tenant_id = data.get("identity", {}).get("tenant_id", "unknown")
            roles = data.get("identity", {}).get("roles", [])
            daily_spent = data.get("budget", {}).get("daily", {}).get("spent_usd", 0)
            models_available = data.get("models_available", 0)
            
            log_info(f"✓ Connected to tenant: {tenant_id}")
            log_detail(f"Roles: {', '.join(roles)}")
            log_detail(f"Daily spend: ${daily_spent:.6f}")
            log_detail(f"Models available: {models_available}")
            
            # Check provider health
            providers = data.get("health", {}).get("providers", {})
            log_detail(f"Providers: {len(providers)} configured")
            
            for provider, info in providers.items():
                status = info.get("status", "unknown")
                latency = info.get("latency_ms", 0)
                symbol = "✓" if status == "healthy" else "✗"
                log_detail(f"  {symbol} {provider.split('|')[0]}: {latency:.1f}ms")
            
            # Check circuit breakers
            cb = data.get("health", {}).get("circuit_breakers", {})
            log_detail(f"Circuit breakers: {cb.get('open', 0)} open, {cb.get('closed', 0)} closed")
            
            # Check suggestions
            suggestions = data.get("suggestions", [])
            if suggestions:
                log_warn(f"{len(suggestions)} configuration suggestions:")
                for s in suggestions:
                    log_detail(f"  • {s.get('action')}: {s.get('reason')}")
            
            self.results["self_discovery"] = {"status": "PASS", "data": data}
            return True
            
        except Exception as e:
            log_error(f"✗ Self discovery failed: {e}")
            self.results["self_discovery"] = {"status": "FAIL", "error": str(e)}
            return False
    
    def test_1_2_model_registry(self) -> bool:
        """Test 1.2: Model registry enumeration"""
        log_info("=== Test 1.2: Model Registry ===")
        
        try:
            # Get all models
            response = self.session.get(f"{BR_BASE_URL}/v1/models")
            response.raise_for_status()
            all_models = response.json()
            self.save_result("models_all", all_models)
            
            model_count = len(all_models.get("data", []))
            log_info(f"✓ Retrieved {model_count} total models")
            
            # Get runnable models
            response = self.session.get(f"{BR_BASE_URL}/v1/catalog/runnable")
            response.raise_for_status()
            runnable_models = response.json()
            self.save_result("models_runnable", runnable_models)
            
            runnable_count = len(runnable_models.get("data", []))
            log_info(f"✓ {runnable_count} models currently runnable")
            
            drift = model_count - runnable_count
            if drift > 0:
                log_warn(f"Model drift: {drift} models unavailable")
            
            # Get leaderboard
            response = self.session.get(f"{BR_BASE_URL}/v1/models/leaderboard")
            if response.status_code == 200:
                leaderboard = response.json()
                self.save_result("models_leaderboard", leaderboard)
                log_info(f"✓ Retrieved model leaderboard")
                
                # Show top 5
                top_models = leaderboard.get("data", [])[:5]
                log_detail("Top 5 models (Thompson sampling):")
                for i, m in enumerate(top_models, 1):
                    name = m.get("model_id", "unknown")
                    score = m.get("score", 0)
                    log_detail(f"  {i}. {name} (score: {score:.3f})")
            
            self.results["model_registry"] = {"status": "PASS"}
            return True
            
        except Exception as e:
            log_error(f"✗ Model registry failed: {e}")
            self.results["model_registry"] = {"status": "FAIL", "error": str(e)}
            return False
    
    def test_1_3_basic_completion(self) -> bool:
        """Test 1.3: Simple completion with header capture"""
        log_info("=== Test 1.3: Basic Completion ===")
        
        try:
            payload = {
                "model": "auto",
                "messages": [{"role": "user", "content": "Say hello in exactly 3 words"}],
                "max_tokens": 20
            }
            
            start_time = time.time()
            response = self.session.post(
                f"{BR_BASE_URL}/v1/chat/completions",
                json=payload
            )
            response.raise_for_status()
            elapsed = time.time() - start_time
            
            data = response.json()
            self.save_result("completion_test", data)
            
            # Save headers
            headers = dict(response.headers)
            self.save_result("completion_headers", headers)
            
            log_info(f"✓ Completion successful in {elapsed:.2f}s")
            
            # Extract key info
            model_used = data.get("model", "unknown")
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            usage = data.get("usage", {})
            
            log_detail(f"Model selected: {model_used}")
            log_detail(f"Response: '{content}'")
            log_detail(f"Tokens: {usage.get('total_tokens', 0)} total")
            
            # Check for BR-specific headers
            br_headers = {k: v for k, v in headers.items() if k.lower().startswith('x-br-')}
            if br_headers:
                log_info("BR headers detected:")
                for k, v in br_headers.items():
                    log_detail(f"  {k}: {v}")
            else:
                log_warn("No X-BR-* headers found (feature not yet implemented)")
            
            self.results["basic_completion"] = {"status": "PASS", "latency": elapsed}
            return True
            
        except Exception as e:
            log_error(f"✗ Completion failed: {e}")
            self.results["basic_completion"] = {"status": "FAIL", "error": str(e)}
            return False
    
    def test_1_4_budget_status(self) -> bool:
        """Test 1.4: Budget check"""
        log_info("=== Test 1.4: Budget Status ===")
        
        try:
            response = self.session.get(f"{BR_BASE_URL}/v1/budget/status")
            
            if response.status_code == 200:
                data = response.json()
                self.save_result("budget_status", data)
                
                daily = data.get("daily", {})
                monthly = data.get("monthly", {})
                
                log_info(f"✓ Budget endpoint accessible")
                log_detail(f"Daily: ${daily.get('spent_usd', 0):.6f} spent")
                log_detail(f"Monthly: ${monthly.get('spent_usd', 0):.6f} spent")
                
                if daily.get("limit_usd"):
                    remaining = daily.get("remaining_usd", 0)
                    log_detail(f"Daily remaining: ${remaining:.2f}")
                
                self.results["budget_status"] = {"status": "PASS"}
                return True
            else:
                log_warn(f"Budget endpoint returned HTTP {response.status_code}")
                self.results["budget_status"] = {"status": "SKIP"}
                return True
                
        except Exception as e:
            log_error(f"✗ Budget check failed: {e}")
            self.results["budget_status"] = {"status": "FAIL", "error": str(e)}
            return False
    
    def test_1_5_agent_bootstrap(self) -> bool:
        """Test 1.5: Agent bootstrap"""
        log_info("=== Test 1.5: Agent Bootstrap ===")
        
        try:
            payload = {
                "name": "jazz-test-agent",
                "description": "Test agent for stress testing",
                "budget_usd": 1.00,
                "capabilities": ["memory", "tool_use"]
            }
            
            response = self.session.post(
                f"{BR_BASE_URL}/v1/agent/bootstrap",
                json=payload
            )
            
            if response.status_code == 200:
                data = response.json()
                self.save_result("agent_bootstrap", data)
                
                agent_id = data.get("agent_id", "unknown")
                token = data.get("token", "")[:20] + "..." if data.get("token") else "none"
                
                log_info(f"✓ Agent bootstrapped: {agent_id}")
                log_detail(f"Token: {token}")
                log_detail(f"Budget: ${data.get('budget_usd', 0):.2f}")
                
                self.results["agent_bootstrap"] = {"status": "PASS", "agent_id": agent_id}
                return True
            else:
                log_warn(f"Bootstrap returned HTTP {response.status_code}")
                log_detail(f"Response: {response.text[:200]}")
                self.results["agent_bootstrap"] = {"status": "SKIP"}
                return True
                
        except Exception as e:
            log_error(f"✗ Agent bootstrap failed: {e}")
            self.results["agent_bootstrap"] = {"status": "FAIL", "error": str(e)}
            return False
    
    def generate_report(self):
        """Generate summary report"""
        log_info("=" * 60)
        log_info("Phase 1 Complete - Generating Report")
        log_info("=" * 60)
        
        report_path = os.path.join(TEST_RESULTS_DIR, "summary.json")
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Print summary
        total = len(self.results)
        passed = sum(1 for r in self.results.values() if r.get("status") == "PASS")
        failed = sum(1 for r in self.results.values() if r.get("status") == "FAIL")
        skipped = sum(1 for r in self.results.values() if r.get("status") == "SKIP")
        
        log_info(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
        log_info(f"Test data saved to: {TEST_RESULTS_DIR}")
        
        return report_path

def main():
    if not BR_API_KEY:
        log_error("BRAINSTORMROUTER_API_KEY environment variable not set")
        sys.exit(1)
    
    log_info(f"Starting BR Discovery Tests")
    log_info(f"Results directory: {TEST_RESULTS_DIR}")
    log_info("")
    
    suite = BRTestSuite()
    
    # Run all tests
    suite.test_1_1_self_discovery()
    suite.test_1_2_model_registry()
    suite.test_1_3_basic_completion()
    suite.test_1_4_budget_status()
    suite.test_1_5_agent_bootstrap()
    
    # Generate report
    report_path = suite.generate_report()
    
    log_info("")
    log_info(f"Full report: {report_path}")

if __name__ == "__main__":
    main()
