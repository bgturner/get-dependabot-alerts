#!/usr/bin/env node

import dotenv from "dotenv";
import { graphql } from "@octokit/graphql";
import { GraphQlQueryResponseData } from "@octokit/graphql/dist-types/types";
import * as csvWriter from "csv-writer";

dotenv.config();

const repos = process.argv.slice(2);

if (repos.length < 1) {
  console.error("At least one repo needs to be provided.");
  console.error(
    "    Usage: get-dependabot-alerts <@organization/repo> [...@organization/repo]"
  );
  process.exit(1);
}

if (!process.env.GITHUB_TOKEN) {
  console.error("Github auth token not set.");
  console.error(
    "Generate a token at: https://help.github.com/articles/authorizing-a-personal-access-token-for-use-with-a-saml-single-sign-on-organization/"
  );
  console.error(
    "Then update the .env file of this repo, or export within the terminal:"
  );
  console.error("    export GITHUB_TOKEN='xxxxxxxxxx'");
  process.exit(1);
}

const graphqlWithAuth = graphql.defaults({
  headers: {
    authorization: `token ${process.env.GITHUB_TOKEN}`,
  },
});

async function getDependabotAlerts(org: string, repo: string) {
  let pagination = null;
  let dependabotAlerts = [];
  const query = `query ($org: String! $repo: String! $cursor: String){
      repository(owner: $org name: $repo) {
        name
        vulnerabilityAlerts(first: 100 after: $cursor) {
          pageInfo {
            hasNextPage
            endCursor
          }
          totalCount
          nodes {
            id
            securityAdvisory {
              ...advFields
            }
            securityVulnerability {
              package {
                ...pkgFields
              }
              vulnerableVersionRange
            }
            createdAt
            state
            fixedAt
            fixReason
            dismissedAt
            dismissReason
            vulnerableManifestPath
            vulnerableRequirements
          }
        }
      }
    }

    fragment advFields on SecurityAdvisory {
      ghsaId
      permalink
      severity
      description
      summary
    }

    fragment pkgFields on SecurityAdvisoryPackage {
      name
      ecosystem
    }`;

  try {
    let hasNextPage = false;
    do {
      const getVulnResult: GraphQlQueryResponseData = await graphqlWithAuth({
        query,
        org: org,
        repo: repo,
        cursor: pagination,
      });
      hasNextPage =
        getVulnResult.repository.vulnerabilityAlerts.pageInfo.hasNextPage;
      const vulns = getVulnResult.repository.vulnerabilityAlerts.nodes;

      for (const vuln of vulns) {
        dependabotAlerts.push({
          org: org,
          repo: repo,
          package: vuln.securityVulnerability.package.name,
          ecosystem: vuln.securityVulnerability.package.ecosystem,
          summary: vuln.securityAdvisory.summary,
          severity: vuln.securityAdvisory.severity,
          advisoryPermalink: vuln.securityAdvisory.permalink,
          urlRepoAlerts: `https://github.com/${org}/${repo}/security/dependabot/?q=is:open%20package:${vuln.securityVulnerability.package.name}%20${vuln.securityAdvisory.ghsaId}`,
          vulnerableManifestPath: vuln.vulnerableManifestPath,
          vulnerableRequirements: vuln.vulnerableRequirements,
          createdAt: vuln.createdAt,
          state: vuln.state,
          fixedAt: vuln.fixedAt,
          fixReason: vuln.fixReason,
          dismissedAt: vuln.dismissedAt,
          dismissReason: vuln.dismissReason,
        });
      }

      if (hasNextPage) {
        pagination =
          getVulnResult.repository.vulnerabilityAlerts.pageInfo.endCursor;
      }
    } while (hasNextPage);
    return dependabotAlerts;
  } catch (error) {
    if (error instanceof Error) {
      console.error("Request failed:", error.message);
    }
  }
}

const header = [
  { id: "org", title: "Org" },
  { id: "repo", title: "Repo" },
  { id: "vulnerableManifestPath", title: "Vulnerable Manifest File" },
  { id: "vulnerableRequirements", title: "Minimum Fixed Version" },
  { id: "package", title: "Package" },
  { id: "ecosystem", title: "Ecosystem" },
  { id: "summary", title: "Summary" },
  { id: "severity", title: "Severity" },
  { id: "createdAt", title: "Created At" },
  { id: "state", title: "State" },
  { id: "urlRepoAlerts", title: "Url for Dependabot Alerts" },
  { id: "fixedAt", title: "Fixedat" },
  { id: "fixReason", title: "Fixreason" },
  { id: "dismissedAt", title: "Dismissed At" },
  { id: "dismissReason", title: "Dismiss Reason" },
  { id: "advisoryPermalink", title: "Advisory Permalink" },
];

const createCsvStringifier = csvWriter.createObjectCsvStringifier;
const csvStringifier = createCsvStringifier({ header });
console.log(csvStringifier.getHeaderString());

async function getVulns(repos: string[]) {
  await Promise.all(
    repos.map(async (item: string) => {
      const [org, repo] = item.split("/");
      getDependabotAlerts(org, repo).then((result) => {
        if (result) {
          console.log(csvStringifier.stringifyRecords(result));
        }
      });
    })
  );
}

getVulns(repos);
