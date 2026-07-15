# CVES

Status: Erledigt
Tags 2: Misc

- Grab all the subdomains [Subdomain Methodology](https://app.notion.com/p/Subdomain-Methodology-0a0140545aaf4db997ddb4a964fb3c4e?pvs=21)
- Run `basic-detection, panel, workflow, CVE` templates and store results in a file
    - `cat alive.txt | nuclei -t nuclei-templates/workflows | tee -a workflows`
- Read each output carefully with patience
- Find interesting tech used by the target. i.e, `jira`
- Check the versions used by target
- Go on Google search `jira version exploit`
- Go to Twitter and search a CVE → get a PoC

# Automated Scanners

[https://github.com/projectdiscovery/cvemap](https://github.com/projectdiscovery/cvemap)

```python
cvemap -q "some_cve_query" -l 100 # Search for CVE's
cvemap -id <CVE-XXX-XXX> -j       # Get JSON output
```