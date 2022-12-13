import validateRepos from "./validateRepos";

describe("Validate Repos", () => {
  it("throws an error if no repos were passed", () => {
    expect(() => {
      validateRepos([]);
    }).toThrowError();
  });
});
