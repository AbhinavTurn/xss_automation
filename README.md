# xss_automation
"""
Advanced XSS Vulnerability Scanner

This script first crawls an entire website to gather all URLs, then systematically tests
each URL for XSS vulnerabilities using a variety of payloads and evasion techniques.

Usage:
    python xss.py -u <target_url> -p <payloads_file> [-o <output_file>] [-d <depth>] [--cookies <cookies>]
"""
