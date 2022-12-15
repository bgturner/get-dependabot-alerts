import getGithubToken from "./getGithubToken";

describe("getGithubToken", () => {
  const OLD_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...OLD_ENV };
  });

  afterAll(() => {
    process.env = OLD_ENV;
  });

  it("errors when a token cant be found", () => {
    process.env.GITHUB_TOKEN = undefined;
    expect(() => {
      getGithubToken();
    }).toThrow();
  });

  it("errors when a token doesnt appear to be a Github token", () => {
    const token = "super_fake_asdf1234";
    process.env.GITHUB_TOKEN = token;
    expect(() => getGithubToken()).toThrow();
  });

  it("returns the token when the GITHUB_TOKEN env var is set", () => {
    const personalToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    process.env.GITHUB_TOKEN = personalToken;
    expect(getGithubToken()).toBe(personalToken);
  });
});
