"""
NOSP vOMEGA - YAML Rules Engine
Declarative threat response system with real-time rule evaluation
"""

import yaml
import re
from typing import Dict, List, Any, Callable, Optional
from pathlib import Path
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class RuleCondition:
    """Represents a single condition in a rule"""
    field: str
    operator: str
    value: Any
    
    def evaluate(self, event: Dict[str, Any]) -> bool:
        """Evaluate this condition against an event"""
        try:
            event_value = event.get(self.field, "")
            
            if self.operator == "eq":
                return str(event_value).lower() == str(self.value).lower()
            elif self.operator == "ne":
                return str(event_value).lower() != str(self.value).lower()
            elif self.operator == "contains":
                return str(self.value).lower() in str(event_value).lower()
            elif self.operator == "regex":
                return bool(re.search(self.value, str(event_value), re.IGNORECASE))
            elif self.operator == "gt":
                try:
                    return float(event_value) > float(self.value)
                except (ValueError, TypeError):
                    return False
            elif self.operator == "lt":
                try:
                    return float(event_value) < float(self.value)
                except (ValueError, TypeError):
                    return False
            else:
                logger.warning(f"Unknown operator: {self.operator}")
                return False
        except Exception as e:
            logger.error(f"Error evaluating condition: {e}")
            return False


@dataclass
class Rule:
    """Represents a complete security rule"""
    name: str
    description: str
    enabled: bool
    severity: str
    conditions: List[RuleCondition]
    logic: str  # "and" or "or"
    actions: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def matches(self, event: Dict[str, Any]) -> bool:
        """Check if this rule matches the given event"""
        if not self.enabled:
            return False
        
        if not self.conditions:
            return False
        
        results = [cond.evaluate(event) for cond in self.conditions]
        
        if self.logic == "and":
            return all(results)
        elif self.logic == "or":
            return any(results)
        else:
            logger.warning(f"Unknown logic operator: {self.logic}")
            return False
    
    def get_priority(self) -> int:
        """Get numeric priority based on severity"""
        severity_map = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4
        }
        return severity_map.get(self.severity.lower(), 5)


class RulesEngine:
    """
    YAML-based rules engine for declarative threat response
    
    Features:
    - Hot-reload rules without restart
    - Multiple condition operators (eq, contains, regex, gt, lt)
    - AND/OR logic composition
    - Action chaining (kill, suspend, quarantine, alert, block_ip)
    - Rule priority and severity levels
    """
    
    def __init__(self, rules_file: str = "rules.yaml"):
        self.rules_file = Path(rules_file)
        self.rules: List[Rule] = []
        self.action_handlers: Dict[str, Callable] = {}
        self.stats = {
            "rules_loaded": 0,
            "rules_matched": 0,
            "actions_executed": 0
        }
        
        self.load_rules()
    
    def load_rules(self) -> bool:
        """Load rules from YAML file"""
        try:
            if not self.rules_file.exists():
                logger.warning(f"Rules file not found: {self.rules_file}")
                self._create_default_rules()
                return False
            
            with open(self.rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if not data or 'rules' not in data:
                logger.error("Invalid rules file format")
                return False
            
            self.rules.clear()
            
            for rule_data in data['rules']:
                try:
                    conditions = []
                    for cond_data in rule_data.get('conditions', []):
                        conditions.append(RuleCondition(
                            field=cond_data['field'],
                            operator=cond_data.get('operator', 'eq'),
                            value=cond_data['value']
                        ))
                    
                    rule = Rule(
                        name=rule_data['name'],
                        description=rule_data.get('description', ''),
                        enabled=rule_data.get('enabled', True),
                        severity=rule_data.get('severity', 'medium'),
                        conditions=conditions,
                        logic=rule_data.get('logic', 'and'),
                        actions=rule_data.get('actions', []),
                        metadata=rule_data.get('metadata', {})
                    )
                    
                    self.rules.append(rule)
                    
                except Exception as e:
                    logger.error(f"Error parsing rule: {e}")
                    continue
            
            self.rules.sort(key=lambda r: r.get_priority())
            
            self.stats['rules_loaded'] = len(self.rules)
            logger.info(f"Loaded {len(self.rules)} rules from {self.rules_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return False
    
    def reload_rules(self) -> bool:
        """Hot-reload rules from file"""
        logger.info("Hot-reloading rules...")
        return self.load_rules()
    
    def register_action_handler(self, action_name: str, handler: Callable):
        """Register a handler function for an action"""
        self.action_handlers[action_name] = handler
        logger.info(f"Registered action handler: {action_name}")
    
    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate an event against all rules
        
        Returns:
            List of matched rules with their actions
        """
        matches = []
        
        for rule in self.rules:
            if rule.matches(event):
                self.stats['rules_matched'] += 1
                
                match_info = {
                    'rule_name': rule.name,
                    'severity': rule.severity,
                    'description': rule.description,
                    'actions': rule.actions,
                    'metadata': rule.metadata
                }
                
                matches.append(match_info)
                logger.info(f"Rule matched: {rule.name} -> Actions: {rule.actions}")
        
        return matches
    
    def execute_actions(self, event: Dict[str, Any], matches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Execute actions for matched rules
        
        Returns:
            Dictionary of action results
        """
        results = {
            'executed': [],
            'failed': [],
            'skipped': []
        }
        
        for match in matches:
            for action in match['actions']:
                try:
                    if action not in self.action_handlers:
                        logger.warning(f"No handler registered for action: {action}")
                        results['skipped'].append({
                            'action': action,
                            'rule': match['rule_name'],
                            'reason': 'No handler registered'
                        })
                        continue
                    
                    handler = self.action_handlers[action]
                    success = handler(event, match)
                    
                    if success:
                        results['executed'].append({
                            'action': action,
                            'rule': match['rule_name'],
                            'event': event.get('process_name', 'unknown')
                        })
                        self.stats['actions_executed'] += 1
                    else:
                        results['failed'].append({
                            'action': action,
                            'rule': match['rule_name'],
                            'reason': 'Handler returned False'
                        })
                    
                except Exception as e:
                    logger.error(f"Error executing action {action}: {e}")
                    results['failed'].append({
                        'action': action,
                        'rule': match['rule_name'],
                        'error': str(e)
                    })
        
        return results
    
    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Complete pipeline: evaluate event and execute actions
        
        Returns:
            Dictionary with matches and action results
        """
        matches = self.evaluate_event(event)
        
        if not matches:
            return {'matches': [], 'actions': None}
        
        action_results = self.execute_actions(event, matches)
        
        return {
            'matches': matches,
            'actions': action_results
        }
    
    def get_stats(self) -> Dict[str, int]:
        """Get engine statistics"""
        return self.stats.copy()
    
    def get_rules_info(self) -> List[Dict[str, Any]]:
        """Get information about all loaded rules"""
        return [
            {
                'name': rule.name,
                'description': rule.description,
                'enabled': rule.enabled,
                'severity': rule.severity,
                'conditions': len(rule.conditions),
                'actions': rule.actions,
                'logic': rule.logic
            }
            for rule in self.rules
        ]
    
    def _create_default_rules(self):
        """Create a default rules.yaml file with examples"""
        default_rules = {
            'rules': [
                {
                    'name': 'Encoded PowerShell Command',
                    'description': 'Detects PowerShell with encoded commands (common obfuscation)',
                    'enabled': True,
                    'severity': 'critical',
                    'logic': 'and',
                    'conditions': [
                        {'field': 'process_name', 'operator': 'contains', 'value': 'powershell'},
                        {'field': 'cmdline', 'operator': 'contains', 'value': '-enc'}
                    ],
                    'actions': ['kill', 'alert', 'quarantine'],
                    'metadata': {'mitre': 'T1059.001', 'category': 'execution'}
                },
                {
                    'name': 'cmd.exe from Office',
                    'description': 'Office application spawning cmd.exe (macro attack)',
                    'enabled': True,
                    'severity': 'high',
                    'logic': 'and',
                    'conditions': [
                        {'field': 'parent_name', 'operator': 'regex', 'value': '(winword|excel|powerpnt)'},
                        {'field': 'process_name', 'operator': 'eq', 'value': 'cmd.exe'}
                    ],
                    'actions': ['suspend', 'alert'],
                    'metadata': {'mitre': 'T1566.001', 'category': 'initial_access'}
                },
                {
                    'name': 'High Risk Score',
                    'description': 'Any process with risk score above 80',
                    'enabled': True,
                    'severity': 'high',
                    'logic': 'and',
                    'conditions': [
                        {'field': 'risk_score', 'operator': 'gt', 'value': 80}
                    ],
                    'actions': ['alert'],
                    'metadata': {'category': 'general'}
                },
                {
                    'name': 'Suspicious Network Connection',
                    'description': 'Connection to suspicious destination countries',
                    'enabled': True,
                    'severity': 'medium',
                    'logic': 'or',
                    'conditions': [
                        {'field': 'destination_country', 'operator': 'eq', 'value': 'CN'},
                        {'field': 'destination_country', 'operator': 'eq', 'value': 'RU'}
                    ],
                    'actions': ['alert', 'block_ip'],
                    'metadata': {'category': 'network'}
                },
                {
                    'name': 'Mimikatz Detected',
                    'description': 'Known credential dumping tool',
                    'enabled': True,
                    'severity': 'critical',
                    'logic': 'or',
                    'conditions': [
                        {'field': 'process_name', 'operator': 'contains', 'value': 'mimikatz'},
                        {'field': 'cmdline', 'operator': 'contains', 'value': 'sekurlsa'}
                    ],
                    'actions': ['kill', 'quarantine', 'alert'],
                    'metadata': {'mitre': 'T1003', 'category': 'credential_access'}
                }
            ]
        }
        
        try:
            with open(self.rules_file, 'w') as f:
                yaml.dump(default_rules, f, default_flow_style=False, sort_keys=False)
            logger.info(f"Created default rules file: {self.rules_file}")
        except Exception as e:
            logger.error(f"Failed to create default rules: {e}")


def create_rules_engine(rules_file: str = "rules.yaml") -> RulesEngine:
    """Create and initialize a rules engine"""
    return RulesEngine(rules_file)
