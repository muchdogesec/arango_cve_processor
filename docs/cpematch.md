## CPE Match (`cpematch`)

CVE match strings are turned into software and grouping objects cve2stix

However, the issue is that match strings are consistently updated. See example response that shows times

```json
	"matchStrings": [
		{
			"matchString": {
				"matchCriteriaId": "36FBCF0F-8CEE-474C-8A04-5075AF53FAF4",
				"criteria": "cpe:2.3:a:nmap:nmap:3.27:*:*:*:*:*:*:*",
				"lastModified": "2019-06-17T09:16:33.960",
				"cpeLastModified": "2019-07-22T16:37:38.133",
				"created": "2019-06-17T09:16:33.960",
				"status": "Active",
```

The first place this happens is in cve2stix

You can see the modelling of STIX objects (grouping and software) in cve2stix here: https://github.com/muchdogesec/cve2stix/blob/main/docs/stix-mapping.md#grouping-and-software-objects . The logic for this is actually defined in ACVEP code (and imported to CVE2STIX)

`cpematch` mode keeps grouping objects and software objects updated to match current state of cpe match api.