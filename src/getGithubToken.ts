const getGithubToken = () => {
  const token = process.env.GITHUB_TOKEN;
  if (undefined === token) {
    throw new Error("GITHUB_TOKEN not set");
  }
  if (!token.startsWith("ghp_")) {
    throw new Error("GITHUB_TOKEN doesn't start with ghp_");
  }
  return token;
};

export default getGithubToken;
