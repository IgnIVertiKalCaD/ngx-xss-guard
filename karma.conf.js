// karma.conf.js
module.exports = function (config) {
  config.set({
    basePath: "", // Base path for resolving files
    frameworks: ["jasmine"], // Using Jasmine for tests
    files: [
      // IMPORTANT: Only include your main test entry file(s) here.
      // Webpack will handle all the imports from there.
      "spec/core/xss-defender.spec.ts",
    ],
    exclude: [],
    preprocessors: {
      // Process all .ts files with webpack before they are served to the browser
      "**/*.ts": ["webpack"],
    },
    webpack: require("./webpack.config.js"), // Link to your webpack config file
    webpackMiddleware: {
      // webpack-dev-middleware configuration
      stats: "errors-only", // Only show errors in webpack output
    },
    reporters: ["progress"], // Or 'spec', 'kjhtml' etc.
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: true,
    browsers: ["ChromeHeadless"], // Or 'Chrome' for visual debugging
    singleRun: true, // Set to true to run tests once and exit
    concurrency: Infinity,
    plugins: [
      require("karma-jasmine"),
      require("karma-chrome-launcher"),
      require("karma-webpack"),
      // Add other plugins if needed, e.g., 'karma-spec-reporter'
    ],
  });
};
