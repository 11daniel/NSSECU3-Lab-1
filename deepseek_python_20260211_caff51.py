import os
import yara
import magic
import argparse
from pathlib import Path
import json
from datetime import datetime

class YaraMalwareScanner:
    def __init__(self, rules_path=None):
        """
        Initialize YARA scanner with custom rules or default rules
        """
        self.rules = None
        self.mime = magic.Magic(mime=True)
        self.mime_detailed = magic.Magic()
        
        if rules_path:
            self.load_rules(rules_path)
        else:
            self.create_default_rules()
    
    def create_default_rules(self):
        """
        Create comprehensive default YARA rules for malware detection
        """
        default_rules = """
        // Default YARA Rules for Malware Detection
        
        // Rule 1: Detect common executable indicators in PE files
        rule Malware_PE_Indicators {
            meta:
                description = "Detects common malware indicators in PE files"
                author = "Security Scanner"
                date = "2024-01-01"
                severity = "high"
                file_type = "PE"
            
            strings:
                $mz = "MZ"
                $pe = "PE"
                $upx0 = "UPX0"
                $upx1 = "UPX1"
                $aspack = "ASPack"
                $crypt = ".crypt"
                $imports_suspicious = { E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E9 }
                
            condition:
                $mz at 0 and $pe and (any of ($upx*, $aspack, $crypt) or $imports_suspicious)
        }

        // Rule 2: Detect PowerShell script anomalies
        rule Malicious_PowerShell {
            meta:
                description = "Detects potentially malicious PowerShell scripts"
                author = "Security Scanner"
                date = "2024-01-01"
                severity = "medium"
                file_type = "PowerShell"
            
            strings:
                $ps1 = "PowerShell" nocase
                $ps2 = "pwsh" nocase
                $download = "DownloadString" nocase
                $execute = "Invoke-Expression" nocase
                $encoded = "-EncodedCommand" nocase
                $bypass = "Bypass" nocase
                $hidden = "-WindowStyle Hidden" nocase
                
            condition:
                any of ($ps*) and (any of ($download, $execute, $encoded) or 
                        ($bypass and $hidden))
        }

        // Rule 3: Detect JavaScript malware patterns
        rule Malicious_JavaScript {
            meta:
                description = "Detects malicious JavaScript patterns"
                author = "Security Scanner"
                date = "2024-01-01"
                severity = "medium"
                file_type = "JavaScript"
            
            strings:
                $js1 = ".js"
                $eval = "eval(" nocase
                $unescape = "unescape(" nocase
                $fromCharCode = "fromCharCode" nocase
                $document_write = "document.write(" nocase
                $activex = "ActiveXObject" nocase
                $wscript = "WScript.Shell" nocase
                
            condition:
                any of ($js*) and any of ($eval, $unescape, $fromCharCode, 
                        $document_write, $activex, $wscript)
        }

        // Rule 4: Detect suspicious macro documents
        rule Suspicious_Macros {
            meta:
                description = "Detects documents with suspicious macros"
                author = "Security Scanner"
                date = "2024-01-01"
                severity = "high"
                file_type = "Document"
            
            strings:
                $office = "Microsoft Office" nocase
                $auto_open = "Auto_Open" nocase
                $auto_close = "Auto_Close" nocase
                $auto_exec = "Auto_Exec" nocase
                $vba = "VBA" nocase
                $shell = "Shell(" nocase
                
            condition:
                any of ($office) and any of ($auto*) and any of ($vba, $shell)
        }

        // Rule 5: Detect Linux ELF malware patterns
        rule Linux_ELF_Malware {
            meta:
                description = "Detects suspicious patterns in ELF files"
                author = "Security Scanner"
                date = "2024-01-01"
                severity = "high"
                file_type = "ELF"
            
            strings:
                $elf = "ELF"
                $rootkit = "hidepid" nocase
                $backdoor = "/bin/bash -i" nocase
                $reverse_shell = "socket(AF_INET," nocase
                
            condition:
                $elf at 0 and any of ($rootkit, $backdoor, $reverse_shell)
        }

        // Rule 6: Detect common ransomware indicators
        rule Ransomware_Indicators {
            meta:
                description = "Detects common ransomware patterns"
                author = "Security Scanner"
                date = "2024-01-01"
                severity = "critical"
                file_type = "Various"
            
            strings:
                $encrypt = "encrypt" nocase
                $decrypt = "decrypt" nocase
                $bitcoin = "bitcoin" nocase
                $ransom = "ransom" nocase
                $payment = "payment" nocase
                $wallet = "wallet" nocase
                $shadow = "vssadmin" nocase
                
            condition:
                3 of them
        }

        // Rule 7: Detect suspicious network activities
        rule Suspicious_Network {
            meta:
                description = "Detects suspicious network-related patterns"
                author = "Security Scanner"
                date = "2024-01-01"
                severity = "medium"
                file_type = "Various"
            
            strings:
                $url = "http://" nocase
                $https = "https://" nocase
                $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
                $dga = /[a-z]{10,}\.(com|net|org|info)/ nocase
                $beacon = "GET /" nocase
                
            condition:
                any of ($url, $https) and $ip and any of ($dga, $beacon)
        }

        // Rule 8: Detect obfuscated/base64 encoded content
        rule Obfuscated_Content {
            meta:
                description = "Detects heavily obfuscated or base64 encoded content"
                author = "Security Scanner"
                date = "2024-01-01"
                severity = "medium"
                file_type = "Various"
            
            strings:
                $b64_chars = /[A-Za-z0-9+\/]{50,}={0,2}/
                $xor = "xor" nocase
                $rot13 = "rot13" nocase
                $char_code = "charCode" nocase
                
            condition:
                #b64_chars > 5 or (any of ($xor, $rot13) and any of ($char_code))
        }

        // Rule 9: Detect Android APK malware patterns
        rule Android_Malware {
            meta:
                description = "Detects suspicious patterns in APK files"
                author = "Security Scanner"
                date = "2024-01-01"
                severity = "high"
                file_type = "APK"
            
            strings:
                $apk = "AndroidManifest.xml"
                $sms = "SEND_SMS" nocase
                $call = "CALL_PHONE" nocase
                $contacts = "READ_CONTACTS" nocase
                
            condition:
                $apk and any of ($sms, $call, $contacts)
        }

        // Rule 10: Generic Suspicious File
        rule Generic_Suspicious {
            meta:
                description = "Generic rule for suspicious files"
                author = "Security Scanner"
                date = "2024-01-01"
                severity = "low"
                file_type = "Generic"
            
            strings:
                $susp1 = "password" nocase
                $susp2 = "backdoor" nocase
                $susp3 = "exploit" nocase
                $susp4 = "payload" nocase
                $susp5 = "malware" nocase
                $susp6 = "virus" nocase
                
            condition:
                2 of them
        }
        """
        
        try:
            self.rules = yara.compile(source=default_rules)
            print("[+] Default YARA rules compiled successfully")
        except Exception as e:
            print(f"[-] Error compiling default rules: {e}")
            self.rules = None
    
    def load_rules(self, rules_path):
        """
        Load YARA rules from file
        """
        try:
            self.rules = yara.compile(filepath=rules_path)
            print(f"[+] YARA rules loaded from {rules_path}")
        except Exception as e:
            print(f"[-] Error loading rules from {rules_path}: {e}")
            self.create_default_rules()
    
    def get_file_type(self, file_path):
        """
        Determine file type using python-magic
        """
        try:
            mime_type = self.mime.from_file(file_path)
            detailed_type = self.mime_detailed.from_file(file_path)
            return {
                'mime': mime_type,
                'detailed': detailed_type,
                'extension': Path(file_path).suffix.lower()
            }
        except Exception as e:
            return {
                'mime': 'unknown',
                'detailed': f'Error: {str(e)}',
                'extension': Path(file_path).suffix.lower()
            }
    
    def scan_file(self, file_path):
        """
        Scan a single file with YARA rules and determine file type
        """
        result = {
            'file_path': str(file_path),
            'file_name': Path(file_path).name,
            'file_size': os.path.getsize(file_path),
            'file_type': self.get_file_type(file_path),
            'scan_timestamp': datetime.now().isoformat(),
            'malware_detected': False,
            'matches': [],
            'risk_score': 0
        }
        
        # Skip if file is too large (more than 100MB)
        if result['file_size'] > 100 * 1024 * 1024:
            result['error'] = 'File too large for scanning (>100MB)'
            return result
        
        # Scan with YARA rules
        if self.rules:
            try:
                matches = self.rules.match(file_path)
                if matches:
                    result['malware_detected'] = True
                    for match in matches:
                        match_info = {
                            'rule': match.rule,
                            'meta': match.meta,
                            'tags': match.tags,
                            'strings': [str(s) for s in match.strings[:5]]  # Limit to 5 strings
                        }
                        result['matches'].append(match_info)
                        
                        # Calculate risk score
                        severity = match.meta.get('severity', 'low').lower()
                        if severity == 'critical':
                            result['risk_score'] += 10
                        elif severity == 'high':
                            result['risk_score'] += 7
                        elif severity == 'medium':
                            result['risk_score'] += 4
                        else:  # low
                            result['risk_score'] += 1
                            
            except Exception as e:
                result['error'] = f'YARA scan error: {str(e)}'
        
        return result
    
    def scan_folder(self, folder_path):
        """
        Scan all files in a folder (up to 200 files)
        """
        folder_path = Path(folder_path)
        if not folder_path.exists():
            print(f"[-] Folder not found: {folder_path}")
            return []
        
        results = []
        file_count = 0
        
        print(f"\n[*] Scanning folder: {folder_path}")
        print(f"[*] Maximum files to scan: 200\n")
        
        for file_path in folder_path.iterdir():
            if file_path.is_file():
                if file_count >= 200:
                    print(f"[!] Reached maximum file limit (200). Stopping scan.")
                    break
                
                print(f"[*] Scanning: {file_path.name}...")
                scan_result = self.scan_file(file_path)
                results.append(scan_result)
                
                if scan_result['malware_detected']:
                    print(f"  [!] MALWARE DETECTED! Risk Score: {scan_result['risk_score']}")
                else:
                    print(f"  [✓] Clean - Type: {scan_result['file_type']['mime']}")
                
                file_count += 1
        
        return results
    
    def generate_report(self, scan_results, output_file=None):
        """
        Generate detailed scan report
        """
        report = {
            'scan_summary': {
                'total_files_scanned': len(scan_results),
                'total_malware_detected': sum(1 for r in scan_results if r['malware_detected']),
                'total_errors': sum(1 for r in scan_results if 'error' in r),
                'average_risk_score': sum(r['risk_score'] for r in scan_results) / len(scan_results) if scan_results else 0,
                'scan_timestamp': datetime.now().isoformat()
            },
            'file_type_breakdown': {},
            'severity_breakdown': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'detailed_results': scan_results
        }
        
        # Generate breakdowns
        for result in scan_results:
            # File type breakdown
            file_type = result['file_type']['mime'].split('/')[0] if '/' in result['file_type']['mime'] else 'unknown'
            report['file_type_breakdown'][file_type] = report['file_type_breakdown'].get(file_type, 0) + 1
            
            # Severity breakdown from matches
            for match in result.get('matches', []):
                severity = match['meta'].get('severity', 'low').lower()
                if severity in report['severity_breakdown']:
                    report['severity_breakdown'][severity] += 1
        
        # Save or print report
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"\n[+] Report saved to: {output_file}")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='YARA Malware Scanner - Scan files for malware patterns')
    parser.add_argument('path', help='Path to file or folder to scan')
    parser.add_argument('-r', '--rules', help='Path to custom YARA rules file')
    parser.add_argument('-o', '--output', help='Output report file (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = YaraMalwareScanner(rules_path=args.rules)
    
    # Check if path exists
    path = Path(args.path)
    if not path.exists():
        print(f"[-] Path not found: {path}")
        return
    
    # Scan file or folder
    if path.is_file():
        results = [scanner.scan_file(path)]
    else:
        results = scanner.scan_folder(path)
    
    # Generate report
    report = scanner.generate_report(results, args.output)
    
    # Print summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Total Files Scanned: {report['scan_summary']['total_files_scanned']}")
    print(f"Malware Detected: {report['scan_summary']['total_malware_detected']}")
    print(f"Average Risk Score: {report['scan_summary']['average_risk_score']:.2f}")
    print(f"Errors: {report['scan_summary']['total_errors']}")
    print("\nSeverity Breakdown:")
    for severity, count in report['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity.capitalize()}: {count}")
    
    # Print infected files
    if report['scan_summary']['total_malware_detected'] > 0:
        print("\n[!] MALICIOUS FILES DETECTED:")
        for result in results:
            if result['malware_detected']:
                print(f"  - {result['file_name']} (Risk: {result['risk_score']})")
                for match in result['matches'][:3]:  # Show first 3 matches
                    print(f"    * Rule: {match['rule']} - Severity: {match['meta'].get('severity', 'unknown')}")

if __name__ == "__main__":
    main()