# Jira Over HTTP With OpenScope

This guide shows how to broker Jira access through OpenScope's `http` executor
so the agent never receives the Jira token directly.

## Model

Split the integration into two parts:

- root-owned HTTP profile
  Holds the Jira base URL, auth header, and timeout.
- user-owned app manifest
  Defines the narrow Jira actions and which parameters participate in policy.

That keeps credentials in the broker while letting you shape Jira actions in YAML.

## 1. Add A Root-Owned Jira HTTP Profile

Create a broker-owned profile for your Jira tenant:

```bash
sudo openscope http profiles add \
  --name jira-work \
  --base-url https://your-company.atlassian.net \
  --headers "Authorization=Basic <base64-email-api-token>,Accept=application/json" \
  --timeout 30
```

You can inspect the configured profiles with:

```bash
openscope http profiles list
```

Profile data lives in:

```text
/Library/Application Support/OpenScope/http_profiles.yaml
```

## 2. Create A Jira App Manifest

You can copy the ready-made example from
[`docs/examples/jira_http_app.yaml`](docs/examples/jira_http_app.yaml), or
create a user-defined app manifest at `~/.openscope/apps.d/jira.yaml`:

```yaml
version: 1
app:
  name: jira
  display_name: Jira
  executor: http
  description: Scoped Jira access over broker-owned HTTP profiles
  security_mode: protected

actions:
  get_issue:
    description: Read a Jira issue by key
    parameters:
      - name: profile
        type: string
        required: true
        policy_key: profile
      - name: issue
        type: string
        required: true
        policy_key: issue
      - name: query.fields
        type: string
        required: false
    output:
      mode: json
      schema: jira_issue
    script: GET /rest/api/3/issue/{issue}

  search_issues:
    description: Search Jira with a constrained JQL query
    parameters:
      - name: profile
        type: string
        required: true
        policy_key: profile
      - name: query.jql
        type: string
        required: true
        policy_key: jql
      - name: query.maxResults
        type: integer
        required: false
    output:
      mode: json
      schema: jira_search
    script: GET /rest/api/3/search/jql

  list_comments:
    description: List comments for a Jira issue
    parameters:
      - name: profile
        type: string
        required: true
        policy_key: profile
      - name: issue
        type: string
        required: true
        policy_key: issue
    output:
      mode: json
      schema: jira_comments
    script: GET /rest/api/3/issue/{issue}/comment
```

Enable the app:

```bash
openscope app enable jira
openscope app validate
```

## 3. Add Policy Rules

Policy remains exact-match, so start with very specific rules:

```bash
sudo openscope policy allow \
  --agent openclaw \
  --app jira \
  --action get_issue \
  --profile jira-work \
  --issue ENG-123

sudo openscope policy allow \
  --agent openclaw \
  --app jira \
  --action search_issues \
  --profile jira-work \
  --jql "project = ENG AND assignee = currentUser() AND statusCategory != Done"
```

Because policy is exact-match in v1, a different issue key or different JQL
string needs its own rule.

## 4. Call Jira Through OpenScope

Examples:

```bash
openscope jira get_issue \
  --agent openclaw \
  --profile jira-work \
  --issue ENG-123 \
  --query.fields summary,status,assignee
```

```bash
openscope jira search_issues \
  --agent openclaw \
  --profile jira-work \
  --query.jql "project = ENG AND assignee = currentUser() AND statusCategory != Done" \
  --query.maxResults 10
```

## Notes

- `script:` for `http` actions is `METHOD /path-template`.
- Route placeholders like `{issue}` are filled from action parameters.
- Any `query.<name>` parameter becomes an HTTP query string parameter.
- Any `body.<name>` parameter becomes a JSON request body field.
- HTTP profile headers are injected by the broker, not by the agent.

## Practical Jira Guidance

Start with read-only actions first:

- `get_issue`
- `search_issues`
- `list_comments`

Jira writes often need more structured request bodies, especially rich-text
comments. For v1, it is simpler and safer to start with read-only issue access,
then extend the executor or add app-specific helpers once the exact write
workflows are clear.
