#!/usr/bin/env node

import dotenv from "dotenv";
import { graphql } from "@octokit/graphql";
import csvWriter from "csv-writer";

dotenv.config();

const repos = process.argv.slice(2);

const graphqlWithAuth = graphql.defaults({
  headers: {
    authorization: `token ${process.env.GITHUB_TOKEN}`,
  },
});

async function getDependabotAlerts(org, repo) {
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
            vulnerableManifestFilename
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
      const getVulnResult = await graphqlWithAuth({
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
          permalink: vuln.securityAdvisory.permalink,
        });
      }

      if (hasNextPage) {
        pagination =
          getVulnResult.repository.vulnerabilityAlerts.pageInfo.endCursor;
      }
    } while (hasNextPage);
    return dependabotAlerts;
  } catch (error) {
    console.error("Request failed:", error.request);
    console.error(error.message);
  }
}

const header = [
  { id: "org", title: "Org" },
  { id: "repo", title: "Repo" },
  { id: "package", title: "Package" },
  { id: "ecosystem", title: "Ecosystem" },
  { id: "summary", title: "Summary" },
  { id: "severity", title: "Severity" },
  { id: "permalink", title: "Permalink" },
];

const createCsvStringifier = csvWriter.createObjectCsvStringifier;
const csvStringifier = createCsvStringifier({ header });
console.log(csvStringifier.getHeaderString());

async function getVulns(repos) {
  await Promise.all(
    repos.map(async (item) => {
      const [org, repo] = item.split("/");
      getDependabotAlerts(org, repo).then((result) => {
        console.log(csvStringifier.stringifyRecords(result));
      });
    })
  );
}

getVulns(repos);
