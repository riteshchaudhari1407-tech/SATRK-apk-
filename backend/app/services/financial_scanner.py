import re
from typing import Dict, List, Set, Any

class FinancialScanner:
    """
    FinancialScanner implements strict regex and context-aware logic to identify
    Indian financial data formats, capping risk contributions to a max of 40 points.
    Follows 'Zero Fabrication' principle.
    """
    
    def __init__(self):
        # Indian IFSC (4 chars + 0 + 6 alphanumeric)
        self.ifsc_pattern = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', re.IGNORECASE)
        # UPI IDs (strict NPCI list)
        self.upi_pattern = re.compile(r'\b[a-zA-Z0-9.\-_]{2,256}@(ybl|paytm|okicici|oksbi|okhdfcbank|okaxis|apl|ibl)\b', re.IGNORECASE)
        # Indian Mobile (10 digits starting 6-9)
        self.mobile_pattern = re.compile(r'\b(?:(?:\+?91[\-\s]?)?)(?P<mobile>[6-9]\d{9})\b')
        # PAN Card (5 letters, 4 digits, 1 letter)
        self.pan_pattern = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', re.IGNORECASE)
        # Sensitive Keywords
        self.sensitive_keywords = re.compile(r'\b(otp|cvv|pin|password|mpin)\b', re.IGNORECASE)
        # Context words for bank account disambiguation
        self.account_context = re.compile(r'\b(account|a/c|acct|transfer|bank|ac|deposit)\b', re.IGNORECASE)
        # 9-18 digit numbers (candidates for bank account)
        self.digits_pattern = re.compile(r'\b\d{9,18}\b')

    def scan_text(self, text: str) -> Dict[str, Any]:
        """
        Scans text for financial identifiers and returns risk contribution (capped at 40).
        """
        result = {
            "risk_contribution": 0,
            "identifiers": [],
            "reasons": []
        }
        
        found_identifiers: Set[str] = set()
        
        # 1. UPI IDs
        for match in self.upi_pattern.finditer(text):
            upi_id = match.group(0).lower()
            if upi_id not in found_identifiers:
                found_identifiers.add(upi_id)
                result["identifiers"].append({"type": "upi", "value": upi_id})
                result["risk_contribution"] += 15
                result["reasons"].append(f"UPI ID detected: {upi_id}")

        # 2. IFSC
        for match in self.ifsc_pattern.finditer(text):
            ifsc = match.group(0).upper()
            if ifsc not in found_identifiers:
                found_identifiers.add(ifsc)
                result["identifiers"].append({"type": "ifsc", "value": ifsc})
                result["risk_contribution"] += 10
                result["reasons"].append("IFSC code detected")

        # 3. PAN Card
        for match in self.pan_pattern.finditer(text):
            pan = match.group(0).upper()
            if pan not in found_identifiers:
                found_identifiers.add(pan)
                result["identifiers"].append({"type": "pan", "value": pan})
                result["risk_contribution"] += 15
                result["reasons"].append("PAN Card number detected")

        # 4. Sensitive Keywords
        for match in self.sensitive_keywords.finditer(text):
            kw = match.group(0).lower()
            if kw not in found_identifiers:
                found_identifiers.add(kw)
                result["identifiers"].append({"type": "keyword", "value": kw})
                result["risk_contribution"] += 10
                result["reasons"].append(f"Sensitive keyword detected: {kw}")

        # 5. Mobile Numbers & Bank Accounts Disambiguation
        # Mobile number check
        found_mobiles = set()
        for match in self.mobile_pattern.finditer(text):
            mobile = match.group("mobile")
            if mobile not in found_identifiers:
                found_identifiers.add(mobile)
                found_mobiles.add(mobile)
                result["identifiers"].append({"type": "mobile", "value": mobile})
                result["risk_contribution"] += 5
                result["reasons"].append("Indian Mobile Number detected")
        
        # Bank account check (9-18 digits) with context
        for match in self.digits_pattern.finditer(text):
            num = match.group(0)
            # If it's already flagged as a mobile, skip unless it has strong account context
            # We look for account keywords within 30 chars before or after the number
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            context_window = text[start:end]
            
            if self.account_context.search(context_window):
                if num in found_mobiles:
                    # Upgrade mobile to bank account
                    found_identifiers.add(f"acc_{num}")
                    result["identifiers"].append({"type": "account", "value": num})
                    result["risk_contribution"] += 10  # Additional 10 points
                    result["reasons"].append("Bank Account Number detected in context")
                elif num not in found_identifiers:
                    found_identifiers.add(num)
                    result["identifiers"].append({"type": "account", "value": num})
                    result["risk_contribution"] += 15
                    result["reasons"].append("Bank Account Number detected in context")

        # Cap risk contribution at 40
        if result["risk_contribution"] > 40:
            result["risk_contribution"] = 40
            
        if result["risk_contribution"] == 0:
            return {}
            
        return result
