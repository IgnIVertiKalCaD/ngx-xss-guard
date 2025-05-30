// webpack.config.js
const path = require("path");

module.exports = {
  mode: "development", // Or 'production'
  // Entry point for your tests. Webpack will start here and include all imports.
  entry: "./spec/core/xss-defender.spec.ts",
  output: {
    // Output path for the bundled test file.
    path: path.resolve(__dirname, "dist"),
    filename: "test-bundle.js", // Name for the bundled test file
  },
  resolve: {
    // Automatically resolve these extensions when importing modules
    extensions: [".ts", ".js"],
    // This is important if your source files are in a different root
    // For example, if your `src` folder is outside `tests`
    alias: {
      // This alias maps '../../src/index' to the actual path.
      // Adjust if your import path is different.
      "../../src/index": path.resolve(__dirname, "src/index.ts"),
    },
  },
  module: {
    rules: [
      {
        test: /\.ts$/, // Apply this rule to .ts files
        loader: "ts-loader", // Use ts-loader to transpile TypeScript
        exclude: /node_modules/, // Don't transpile node_modules
        options: {
          // If you have a specific tsconfig for tests, you can point to it
          // configFile: 'tsconfig.test.json'
        },
      },
    ],
  },
  // Devtool for better debugging in the browser console
  devtool: "inline-source-map", // Or 'source-map'
};
