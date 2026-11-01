# vuln-Clickjacking-Detector
Detects if a website is vulnerable to clickjacking attacks by analyzing HTTP response headers (X-Frame-Options, Content-Security-Policy) and suggesting mitigation techniques. Headers are analyzed on every response received, including error responses. Content-Security-Policy protection is judged from the frame-ancestors value: 'none', 'self', and named sources restrict framing, while * does not. If the target cannot be reached, the result is inconclusive and the run exits non-zero with no vulnerable verdict. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-clickjacking-detector`

## Usage
`./vuln-clickjacking-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided

## License
Copyright (c) ShadowStrikeHQ
