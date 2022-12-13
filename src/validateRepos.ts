const validateRepos = (repos: string[]) => {
  if (repos.length < 1) {
    throw new Error("At least one repo needs to be provided.");
  }
  return repos;
};

export default validateRepos;
