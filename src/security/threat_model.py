class ThreatModeler:
    '''Threat modeling using STRIDE'''
    
    def __init__(self):
        '''Initialize threat modeler'''
        
        # STRIDE categories
        self.stride = {
            'Spoofing': 'Authentication threat',
            'Tampering': 'Integrity threat',
            'Repudiation': 'Non-repudiation threat',
            'Information Disclosure': 'Confidentiality threat',
            'Denial of Service': 'Availability threat',
            'Elevation of Privilege': 'Authorization threat'
        }
        
        # Threat actors
        self.actors = {
            'Script Kiddie': {'skill': 'low', 'resources': 'low'},
            'Hacktivist': {'skill': 'medium', 'resources': 'medium'},
            'Cybercriminal': {'skill': 'high', 'resources': 'high'},
            'Nation State': {'skill': 'very_high', 'resources': 'unlimited'},
            'Insider': {'skill': 'varies', 'resources': 'access'}
        }
    
    def classify_threats(self, vulnerabilities):
        '''Classify vulnerabilities by STRIDE'''
        
        threats = {category: [] for category in self.stride.keys()}
        
        for vuln in vulnerabilities:
            # Spoofing
            if vuln.get('privileges_required') == 'NONE':
                threats['Spoofing'].append(vuln)
            
            # Tampering
            if vuln.get('integrity_impact') == 'HIGH':
                threats['Tampering'].append(vuln)
            
            # Repudiation
            # (Hard to detect from CVSS alone)
            
            # Information Disclosure
            if vuln.get('confidentiality_impact') == 'HIGH':
                threats['Information Disclosure'].append(vuln)
            
            # Denial of Service
            if vuln.get('availability_impact') == 'HIGH':
                threats['Denial of Service'].append(vuln)
            
            # Elevation of Privilege
            if vuln.get('privileges_required') in ['NONE', 'LOW']:
                if vuln.get('cvss_score', 0) >= 7.0:
                    threats['Elevation of Privilege'].append(vuln)
        
        return threats
    
    def assess_threat_actors(self, vulnerabilities):
        '''Assess which threat actors could exploit'''
        
        assessments = {}
        
        for actor, profile in self.actors.items():
            exploitable = []
            
            for vuln in vulnerabilities:
                cvss = vuln.get('cvss_score', 0)
                ac = vuln.get('attack_complexity', 'HIGH')
                
                # Simple heuristic
                if profile['skill'] == 'low':
                    if cvss >= 9.0 and ac == 'LOW':
                        exploitable.append(vuln)
                
                elif profile['skill'] == 'medium':
                    if cvss >= 7.0:
                        exploitable.append(vuln)
                
                else:  # high or very_high
                    exploitable.append(vuln)
            
            assessments[actor] = {
                'exploitable_count': len(exploitable),
                'threat_level': self._calculate_threat_level(len(exploitable), profile)
            }
        
        return assessments
    
    def _calculate_threat_level(self, count, profile):
        '''Calculate threat level'''
        if profile['resources'] == 'unlimited':
            return 'CRITICAL' if count > 0 else 'HIGH'
        elif count >= 10:
            return 'CRITICAL'
        elif count >= 5:
            return 'HIGH'
        elif count >= 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_threat_report(self, vulnerabilities):
        '''Generate comprehensive threat report'''
        
        # STRIDE classification
        stride_threats = self.classify_threats(vulnerabilities)
        
        # Threat actor assessment
        actor_assessment = self.assess_threat_actors(vulnerabilities)
        
        report = '''
╔══════════════════════════════════════════════════════════╗
║              THREAT MODEL ANALYSIS                       ║
╚══════════════════════════════════════════════════════════╝

🎯 STRIDE ANALYSIS:

'''
        
        for category, vulns in stride_threats.items():
            if vulns:
                report += f"  [{category}] {len(vulns)} threats\n"
                report += f"    {self.stride[category]}\n"
                for v in vulns[:3]:
                    report += f"      • {v.get('cve_id', 'Unknown')}\n"
        
        report += '''
👥 THREAT ACTOR ASSESSMENT:

'''
        
        for actor, assessment in actor_assessment.items():
            level = assessment['threat_level']
            count = assessment['exploitable_count']
            
            icon = '🔴' if level == 'CRITICAL' else '🟠' if level == 'HIGH' else '🟡'
            
            report += f"  {icon} {actor}:\n"
            report += f"     Exploitable: {count} | Threat: {level}\n"
        
        report += '''
💡 MITIGATION RECOMMENDATIONS:

  1. IMMEDIATE:
     • Patch critical vulnerabilities
     • Enable MFA everywhere
     • Review access controls

  2. SHORT TERM:
     • Implement monitoring
     • Deploy IDS/IPS
     • Security awareness training

  3. LONG TERM:
     • Security architecture review
     • Threat intelligence integration
     • Regular pentesting
'''
        
        return report


if __name__ == '__main__':
    # Test
    print("THREAT MODELING TEST")
    
    test_vulns = [
        {
            'cve_id': 'CVE-TEST-001',
            'cvss_score': 9.8,
            'attack_complexity': 'LOW',
            'privileges_required': 'NONE',
            'confidentiality_impact': 'HIGH',
            'integrity_impact': 'HIGH',
            'availability_impact': 'HIGH'
        }
    ]
    
    modeler = ThreatModeler()
    report = modeler.generate_threat_report(test_vulns)
    
    print(report)
