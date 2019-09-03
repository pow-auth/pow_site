module.exports = {
  content: ["./build/**/*.html"],
  css: ["./build/css/site.css"],
  defaultExtractor: content => content.match(/[A-Za-z0-9-_:/]+/g) || []
};
