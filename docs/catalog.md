# The product catalog

The catalog is how the server turns a product name or a container image into
the identifiers the advisory sources need. It lives in
[`internal/catalog/catalog.yaml`](../internal/catalog/catalog.yaml) and is
compiled into the binary.

It covers about twenty common products, and the server never guesses beyond
it. There are three ways to check software it does not know:

- pass identifiers explicitly; see
  [agents.md](agents.md#check-software-the-catalog-does-not-know);
- add the product to [a catalog file of your own](#your-own-catalog-file),
  which needs no rebuild;
- add it to the built-in catalog, for everyone.

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
| `otherPackages` | Further package names for the same product. For Go, list the module's `/v2`, `/v3` paths here; only the one for the running version's major is asked. |
| `repo` | The upstream GitHub repository's security advisories, and its releases. |
| `cpe` | NVD lookups, as `vendor:product`. Also what lets name-only matches from CISA's list be cleared. |
| `otherCpes` | Further names NVD files the same product under. |
| `lifecycle` | The product's name in endoflife.date's data, for end-of-life status and the latest release. |
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
registry host removed.

- A catalog image with a namespace, such as `gitlab/gitlab-ee`, matches any
  path that equals it or ends with `/` followed by it. A mirror such as
  `registry.example.edu/mirror/gitlab/gitlab-ee` still resolves, and
  `evil/notgitlab-ee` does not.
- A catalog image without one, such as `postgres`, is an official image. It
  matches `postgres` and `library/postgres`, with or without a mirror's path
  in front, and nothing else: `someone/postgres` is a different image that
  merely shares the name.

**Versions** are read from image tags by taking the first dotted number:
`main-v1.106.6-stable` gives `1.106.6`, and `19.6.1-ee.0` gives `19.6.1`. A
tag with none, such as `latest`, gives no version.

## Your own catalog file

Start the server with `-catalog <path>`, or set `SEC1_CATALOG`, to load a
file in the same format as the built-in catalog:

```yaml
products:
  - name: Internal Portal
    aliases: [portal]
    repo: example-org/portal
    images:
      - example-org/portal
```

- An entry with a new name is added.
- An entry with the name of a built-in product **replaces it whole**. Copy
  the built-in entry's fields if you only mean to add an image to it.
- The file is validated when the server starts. A malformed identifier, an
  image written with a registry host or a tag, or a name or image claimed by
  two products stops the server with a message naming the entry. A mistake
  is reported then, not as a wrong answer later.

## Adding a product to the built-in catalog

1. Find the identifiers, and confirm each one:

   | Identifier | How to confirm it |
   | --- | --- |
   | `ecosystem`, `package` | The package's page on its registry. |
   | `repo` | The repository exists, and its Security tab lists advisories. |
   | `cpe` | Search NVD's product dictionary for the product; the name has the form `cpe:2.3:a:<vendor>:<product>`. |
   | `images` | The image names your deployments pull, checked against the registry. |

   `find_identifiers` gives candidates to start from.

2. Add the entry to `catalog.yaml`.
3. Add a case to `internal/catalog/catalog_test.go` if the image names are
   unusual.
4. Rebuild, and check the result with `resolve_component` and
   `check_component`.

A wrong identifier is worse than a missing one: it makes the server report
on different software. Leave a field out if you cannot confirm it.

Every identifier in the built-in catalog was checked when it was added: the
repository and its advisories on GitHub, the product name against NVD, the
package name against OSV, the lifecycle name against endoflife.date, and
each image name against its registry. Registries and vendors do rename
things, so corrections are welcome.

Known gaps:

- **ingress-nginx** has no source for the latest release or for lifecycle
  data, so `latestVersion` is empty and `support` is `unknown` for it.
- **LiteLLM, vLLM, Onyx, Ollama and Open WebUI** have no lifecycle data, so
  `support` is `unknown` for them.
- **Prometheus** is not looked up as a Go module, because its module
  versions do not match its release versions.
