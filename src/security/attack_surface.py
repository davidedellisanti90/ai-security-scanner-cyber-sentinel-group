class AttackSurfaceAnalyzer:
    '''Analyze and map attack surface'''
    
    def __init__(self):
        '''Initialize analyzer'''
        self.risk_matrix = {
            ('NETWORK', 'NONE'): 'CRITICAL',  # Remote + No auth
            ('NETWORK', 'LOW'): 'HIGH',
            ('ADJACENT', 'NONE'): 'HIGH',
            ('LOCAL', 'NONE'): 'MEDIUM',
            ('LOCAL', 'LOW'): 'MEDIUM',
            ('PHYSICAL', 'NONE'): 'LOW',
        }
    
    def analyze_surface(self, vulnerabilities):
        '''Analyze attack surface'''
        
        surface = {
            'entry_points': [],
            'exposed_services': set(),
            'high_risk_vectors': [],
            'summary': {}
        }
        
        # Analyze each vulnerability
        for vuln in vulnerabilities:
            av = vuln.get('attack_vector', 'LOCAL')
            pr = vuln.get('privileges_required', 'LOW')
            
            # Entry point analysis
            if av == 'NETWORK' and pr == 'NONE':
                surface['entry_points'].append({
                    'cve': vuln.get('cve_id'),
                    'type': 'Remote Unauthenticated',
                    'risk': 'CRITICAL',
                    'service': vuln.get('service', 'Unknown')
                })
            
            # Track exposed services
            if av in ['NETWORK', 'ADJACENT']:
                service = vuln.get('service', 'Unknown')
                surface['exposed_services'].add(service)
        
        # Generate summary
        surface['summary'] = {
            'total_entry_points': len(surface['entry_points']),
            'exposed_services_count': len(surface['exposed_services']),
            'network_accessible': sum(1 for v in vulnerabilities 
                                     if v.get('attack_vector') == 'NETWORK'),
            'remote_code_execution': self._count_rce(vulnerabilities)
        }
        
        return surface
    
    def _count_rce(self, vulnerabilities):
        '''Count potential RCE vulnerabilities'''
        rce_count = 0
        
        for vuln in vulnerabilities:
            # Heuristic: High CVSS + Network + Code execution indicators
            cvss = vuln.get('cvss_score', 0)
            av = vuln.get('attack_vector', '')
            
            if cvss >= 8.0 and av == 'NETWORK':
                impacts = [
                    vuln.get('confidentiality_impact', ''),
                    vuln.get('integrity_impact', ''),
                    vuln.get('availability_impact', '')
                ]
                
                if impacts.count('HIGH') >= 2:
                    rce_count += 1
        
        return rce_count
    
    def generate_report(self, surface):
        '''Generate attack surface report'''
        
        report = f'''
╔══════════════════════════════════════════════════════════╗
║           ATTACK SURFACE ANALYSIS REPORT                 ║
╚══════════════════════════════════════════════════════════╝

📊 SUMMARY:
  Total Entry Points: {surface['summary']['total_entry_points']}
  Exposed Services: {surface['summary']['exposed_services_count']}
  Network Accessible: {surface['summary']['network_accessible']}
  Potential RCE: {surface['summary']['remote_code_execution']}

🚪 HIGH-RISK ENTRY POINTS:
'''
        
        for ep in surface['entry_points'][:10]:
            report += f'''
  [{ep['risk']}] {ep['cve']}
    Type: {ep['type']}
    Service: {ep['service']}
'''
        
        report += f'''
🔍 EXPOSED SERVICES:
'''
        for service in sorted(surface['exposed_services']):
            report += f"  • {service}\n"
        
        report += '''
💡 RECOMMENDATIONS:
  1. Minimize network-exposed services
  2. Implement strong authentication
  3. Network segmentation
  4. Regular patching schedule
  5. Intrusion detection systems
'''
        
        return report


if __name__ == '__main__':
    # Test
    print("ATTACK SURFACE ANALYZER TEST")
    
    test_vulns = [
        {
            'cve_id': 'CVE-TEST-001',
            'cvss_score': 9.8,
            'attack_vector': 'NETWORK',
            'privileges_required': 'NONE',
            'confidentiality_impact': 'HIGH',
            'integrity_impact': 'HIGH',
            'availability_impact': 'HIGH',
            'service': 'HTTP'
        },
        {
            'cve_id': 'CVE-TEST-002',
            'cvss_score': 7.5,
            'attack_vector': 'NETWORK',
            'privileges_required': 'LOW',
            'service': 'SSH'
        }
    ]
    
    analyzer = AttackSurfaceAnalyzer()
    surface = analyzer.analyze_surface(test_vulns)
    report = analyzer.generate_report(surface)
    
    print(report)
