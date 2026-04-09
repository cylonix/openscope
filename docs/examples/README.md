# Examples

This directory contains copy-pasteable example files for custom OpenScope apps.

Current examples:

- `jira_http_app.yaml`
  A user-defined app manifest that uses the `http` executor to expose scoped
  Jira issue reads over a broker-owned HTTP profile.

To use the Jira example:

```bash
cp docs/examples/jira_http_app.yaml ~/.openscope/apps.d/jira.yaml
openscope app enable jira
openscope app validate
```

Then follow the profile and policy steps in [`../jira_over_http.md`](../jira_over_http.md).
