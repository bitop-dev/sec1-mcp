# The product catalog

The catalog is how the server turns a product name or a container image into
the identifiers the advisory sources need. It lives in
[`internal/catalog/catalog.yaml`](../internal/catalog/catalog.yaml) and is
compiled into the binary.

It is deliberately small, and the server never guesses beyond it. Software
that is not in the catalog can still be checked by passing identifiers
explicitly; see [agents.md](agents.md#check-software-the-catalog-does-not-know).

## An entry

```yaml
- name: LiteLLM
  aliases: [litellm, litellm-proxy]
  ecosystem: PyPI
  package: litellm
  repo: BerriAI/litellm
  cpe: litellm:litellm
  images:
    - berriai/litellm
    - litellm/litellm
```

| Field | Used for |
| --- | --- |
| `name` | The display name, and one of the names the product is found by. |
| `aliases` | Other names: what people type, and what CISA's exploited list calls the vendor or product. |
| `ecosystem`, `package` | OSV lookups, with exact version matching. Also the latest release, for PyPI and npm. |
| `repo` | The upstream GitHub repository's security advisories, and its releases. |
| `cpe` | NVD lookups, as `vendor:product`. Also what lets name-only matches from CISA's list be cleared. |
| `gitlabRepo` | A gitlab.com project, used only to find the latest release. |
| `images` | Container image repositories, without registry host or tag. |

Only `name` is required, but an entry with no `ecosystem`, `repo` or `cpe`
cannot be checked by version.

## How matching works

**Names** are compared after reducing them to lower-case letters and digits,
so `LiteLLM`, `lite-llm` and `litellm` are the same. A name matches an
entry's `name`, any of its `aliases`, or its `package`. Nothing fuzzier is
done: `litellm2` does not match.

**Images** are compared on the repository path, lower-cased, with the
registry host removed. An image matches when its path equals an entry's
image or ends with `/` followed by it, so a mirror such as
`registry.example.edu/mirror/gitlab/gitlab-ee` still resolves, and
`evil/notgitlab-ee` does not.

**Versions** are read from image tags by taking the first dotted number:
`main-v1.106.6-stable` gives `1.106.6`, and `19.6.1-ee.0` gives `19.6.1`. A
tag with none, such as `latest`, gives no version.

## Adding a product

1. Find the identifiers, and confirm each one:

   | Identifier | How to confirm it |
   | --- | --- |
   | `ecosystem`, `package` | The package's page on its registry. |
   | `repo` | The repository exists, and its Security tab lists advisories. |
   | `cpe` | Search NVD's product dictionary for the product; the name has the form `cpe:2.3:a:<vendor>:<product>`. |
   | `images` | The image names your deployments pull. |

2. Add the entry to `catalog.yaml`.
3. Add a case to `internal/catalog/catalog_test.go` if the image names are
   unusual.
4. Rebuild, and check the result with `resolve_component` and
   `check_component`.

A wrong identifier is worse than a missing one: it makes the server report
on different software. Leave a field out if you cannot confirm it.

The image names in the current entries were written from the projects'
documentation and have not all been checked against the registries.
Corrections are welcome.
