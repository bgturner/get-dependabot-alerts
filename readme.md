# Get Dependabot Alerts

Queries the [Github Graphql API](https://docs.github.com/en/graphql) for [Dependabot](https://github.com/dependabot) vulnerabilites and saves them to a CSV file.

## Installation

1. Clone this repo
2. Copy `.env-sample` to `.env`
3. Create a GitHub [Personal Access Token](https://help.github.com/articles/authorizing-a-personal-access-token-for-use-with-a-saml-single-sign-on-organization/) with `repo` permission
4. Add the token to your `.env` file as `GITHUB_TOKEN='insert-token-here'`
5. Run `npm install`

## Usage

Get the vulnerabilities for any number of repos by using them in a space-separated list:

```
node index.js organization1/repo1 organization1/repo2
```

The results are written to stout, so I will often pipe the results to a file like so:

```
node index.js organization1/repo1 organization1/repo2 > dependabot-vulnerabilities.csv
```

Or maybe you have a lot of repos. You can save the following repos within a file, named something like `my-repos`.

```
org1/repo1
org1/repo2
org2/repo1
org2/repo2
org3/repo1
```

Then pull together other unix tools to get the data you need:

```
(cat my-repos | xargs node index.js ) > dependabot-alerts.csv
```

With CSV in hand, take the data wherever you need. For me, the next step was [Visidata](https://www.visidata.org/).

## Thanks

Thanks to the [get-dependabot-alerts-sample](https://github.com/tonycch/get-dependabot-alerts-sample) repo from @tonycch -- most of the bones of this project came from there. The main changes in this repo are:

- Pass multiple repos to the script
- Use `csv-writer` to handle escaping values.
