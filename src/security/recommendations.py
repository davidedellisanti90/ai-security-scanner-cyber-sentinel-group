class SecurityRecommendations:
    '''Generate defense recommendations'''
    
    def generate_recommendations(self, scan_results):
        '''Generate comprehensive recommendations'''
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        summary = scan_results.get('summary', {})
        
        recommendations = {
            'immediate_actions': [],
            'short_term': [],
            'long_term': [],
            'tools': [],
            'policies': []
        }
        
        # Immediate actions
        critical_count = summary.get('by_severity', {}).get('CRITICAL', 0)
        if critical_count > 0:
            recommendations['immediate_actions'].append(
                f"🔴 URGENT: Patch {critical_count} CRITICAL vulnerabilities within 24h"
            )
        
        # Network exposure
        network_vulns = [v for v in vulnerabilities 
                        if v.get('attack_vector') == 'NETWORK']
        
        if len(network_vulns) > 10:
            recommendations['immediate_actions'].append(
                "🔴 Review network exposure - too many network-accessible vulnerabilities"
            )
        
        # Short term
        recommendations['short_term'].extend([
            "📋 Implement regular patching schedule (weekly)",
            "📋 Deploy Web Application Firewall (WAF)",
            "📋 Enable centralized logging",
            "📋 Conduct security awareness training"
        ])
        
        # Long term
        recommendations['long_term'].extend([
            "📚 Develop incident response plan",
            "📚 Implement zero-trust architecture",
            "📚 Regular penetration testing (quarterly)",
            "📚 Security architecture review"
        ])
        
        # Tools
        recommendations['tools'].extend([
            "🔧 Nessus/OpenVAS - Vulnerability scanning",
            "🔧 Snort/Suricata - IDS/IPS",
            "🔧 ELK Stack - Log management",
            "🔧 Qualys/Rapid7 - Continuous monitoring"
        ])
        
        # Policies
        recommendations['policies'].extend([
            "📜 Password policy (complexity + rotation)",
            "📜 Access control policy (least privilege)",
            "📜 Data classification policy",
            "📜 Incident response policy"
        ])
        
        return recommendations
    
    def format_report(self, recommendations):
        '''Format recommendations as report'''
        
        report = '''
╔══════════════════════════════════════════════════════════╗
║         SECURITY RECOMMENDATIONS REPORT                  ║
╚══════════════════════════════════════════════════════════╝

🚨 IMMEDIATE ACTIONS (0-24 hours):
'''
        
        for action in recommendations['immediate_actions']:
            report += f"  {action}\n"
        
        report += '''
📋 SHORT TERM (1 week - 1 month):
'''
        for action in recommendations['short_term']:
            report += f"  {action}\n"
        
        report += '''
📚 LONG TERM (1-6 months):
'''
        for action in recommendations['long_term']:
            report += f"  {action}\n"
        
        report += '''
🔧 RECOMMENDED TOOLS:
'''
        for tool in recommendations['tools']:
            report += f"  {tool}\n"
        
        report += '''
📜 POLICIES TO IMPLEMENT:
'''
        for policy in recommendations['policies']:
            report += f"  {policy}\n"
        
        return report
