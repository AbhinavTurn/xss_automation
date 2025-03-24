# xss_automation

**Advanced XSS Vulnerability Scanner**

This script first crawls an entire website to gather all URLs, then systematically tests
each URL for XSS vulnerabilities using a variety of payloads and evasion techniques.

**Usage:**
    python xss.py -u <target_url> -p <payloads_file> [-o <output_file>] [-d <depth>] [--cookies <cookies>]

**Phase 1: Crawling**

The scanner first thoroughly crawls the entire website to the specified depth
It collects all URLs and forms without testing them yet
All pages with URL parameters or forms are added to the testing queue

**Phase 2: Testing**

After crawling is complete, each collected URL is systematically tested
Every payload is tried on each parameter of each URL
All forms are tested with each payload
Results are carefully logged and organized
